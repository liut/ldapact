package ldapx

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/liut/ldapact/pkg/config"
)

func TestMinTLSVersion(t *testing.T) {
	cases := map[string]uint16{
		"":        tls.VersionTLS12,
		"TLSv1.2": tls.VersionTLS12,
		"TLSv1.3": tls.VersionTLS13,
	}
	for in, want := range cases {
		got, err := minTLSVersion(in)
		if err != nil || got != want {
			t.Errorf("minTLSVersion(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	if _, err := minTLSVersion("TLSv1.1"); err == nil {
		t.Error("TLSv1.1 should be rejected")
	}
}

func TestTLSConfig(t *testing.T) {
	cfg, err := TLSConfig(config.TLSConfig{MinVersion: "TLSv1.3"}, "ldap.example.com")
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d", cfg.MinVersion)
	}
	if cfg.ServerName != "ldap.example.com" {
		t.Errorf("ServerName = %q", cfg.ServerName)
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify must be false")
	}

	v := false
	if _, err := TLSConfig(config.TLSConfig{Verify: &v}, "x"); err == nil {
		t.Error("verify=off must be rejected")
	}
}

func TestCheckCertExpiry(t *testing.T) {
	now := time.Now()
	expired := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "expired.example.com"},
		NotBefore: now.Add(-48 * time.Hour),
		NotAfter:  now.Add(-24 * time.Hour),
	}
	valid := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "valid.example.com"},
		NotBefore: now.Add(-24 * time.Hour),
		NotAfter:  now.Add(90 * 24 * time.Hour),
	}
	soon := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "soon.example.com"},
		NotBefore: now.Add(-24 * time.Hour),
		NotAfter:  now.Add(7 * 24 * time.Hour),
	}

	closed := config.TLSConfig{}
	err := checkCertExpiry([]*x509.Certificate{expired}, closed, nil)
	if !errors.Is(err, ErrTLSCertExpired) {
		t.Fatalf("expired cert: want ErrTLSCertExpired, got %v", err)
	}
	if !strings.Contains(err.Error(), "expired.example.com") {
		t.Errorf("error should name the subject: %v", err)
	}

	open := config.TLSConfig{}
	f := false
	open.CertExpiryFailClosed = &f
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	if err := checkCertExpiry([]*x509.Certificate{expired}, open, logger); err != nil {
		t.Errorf("fail-open expired cert should not error: %v", err)
	}
	if !strings.Contains(buf.String(), "expired but fail_closed is disabled") {
		t.Error("expected warn log for fail-open expiry")
	}

	if err := checkCertExpiry([]*x509.Certificate{valid}, closed, nil); err != nil {
		t.Errorf("valid cert: %v", err)
	}
	buf.Reset()
	if err := checkCertExpiry([]*x509.Certificate{soon}, closed, logger); err != nil {
		t.Errorf("soon cert: %v", err)
	}
	if !strings.Contains(buf.String(), "expires soon") {
		t.Error("expected expiring-soon warn log")
	}
}

func TestDialInvalidURL(t *testing.T) {
	if _, err := Dial(context.Background(), DialOptions{URL: "http://localhost"}); err == nil {
		t.Fatal("want error for non-LDAP URL")
	}
	if _, err := Dial(context.Background(), DialOptions{URL: "ldap://"}); err == nil {
		t.Fatal("want error for hostless URL")
	}
}

func TestDialConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if _, err := Dial(context.Background(), DialOptions{URL: "ldap://" + addr}); err == nil {
		t.Fatal("want dial error")
	}
}

func TestDialStartTLSFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Close immediately: the client's StartTLS request will fail.
			c.Close()
		}
	}()

	opts := DialOptions{
		URL: "ldap://" + ln.Addr().String(),
		TLS: config.TLSConfig{MinVersion: "TLSv1.2"},
	}
	// StartTLS is nil => plaintext connection succeeds at dial time.
	conn, err := Dial(context.Background(), opts)
	if err != nil {
		t.Fatalf("plaintext dial: %v", err)
	}
	conn.Close()

	on := true
	opts.TLS.StartTLS = &on
	conn2, err := Dial(context.Background(), opts)
	if err == nil {
		conn2.Close()
		t.Fatal("want StartTLS failure")
	}
	if !strings.Contains(err.Error(), "StartTLS") {
		t.Errorf("error should mention StartTLS: %v", err)
	}
}

func TestDialPlaintextWithoutStartTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	off := false
	conn, err := Dial(context.Background(), DialOptions{
		URL: "ldap://" + ln.Addr().String(),
		TLS: config.TLSConfig{MinVersion: "TLSv1.2", StartTLS: &off},
	})
	if err != nil {
		t.Fatalf("plaintext dial with start_tls off: %v", err)
	}
	conn.Close()
}
