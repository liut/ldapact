package ldapx

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/config"
)

// Conn is the minimal LDAP connection surface used by this package. *ldap.Conn
// implements it; tests use fakes.
type Conn interface {
	Bind(username, password string) error
	UnauthenticatedBind(username string) error
	ExternalBind() error
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	SearchAsync(context.Context, *ldap.SearchRequest, int) ldap.Response
	Add(*ldap.AddRequest) error
	Modify(*ldap.ModifyRequest) error
	Del(*ldap.DelRequest) error
	ModifyDN(*ldap.ModifyDNRequest) error
	PasswordModify(*ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error)
	Close() error
	IsClosing() bool
}

// DialOptions configures a single LDAP connection.
type DialOptions struct {
	URL    string
	TLS    config.TLSConfig
	Logger *slog.Logger
}

// Dial establishes a connection to the LDAP server, applying KTD 5 dialer
// settings and KTD 10 TLS rules. StartTLS failures are fatal (no plaintext
// fallback). Certificate expiry is checked when the peer presents a cert.
func Dial(ctx context.Context, opts DialOptions) (Conn, error) {
	u, err := url.Parse(opts.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Host == "" {
		return nil, fmt.Errorf("ldapx: invalid LDAP URL %q", opts.URL)
	}
	tlsCfg, err := TLSConfig(opts.TLS, u.Hostname())
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{KeepAlive: 30 * time.Second, Timeout: 5 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return nil, fmt.Errorf("ldapx: dial %s: %w", u.Host, err)
	}

	switch u.Scheme {
	case "ldaps":
		tc := tls.Client(raw, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("ldapx: TLS handshake with %s: %w", u.Host, err)
		}
		if err := checkCertExpiry(tc.ConnectionState().PeerCertificates, opts.TLS, opts.Logger); err != nil {
			tc.Close()
			return nil, err
		}
		conn := ldap.NewConn(tc, true)
		conn.Start()
		return conn, nil

	default: // ldap
		conn := ldap.NewConn(raw, false)
		conn.Start()
		if opts.TLS.StartTLS != nil && *opts.TLS.StartTLS {
			if err := conn.StartTLS(tlsCfg); err != nil {
				conn.Close()
				return nil, fmt.Errorf("%w: starttls with %s: %v", ErrStartTLSFailed, u.Host, err)
			}
			if state, ok := conn.TLSConnectionState(); ok {
				if err := checkCertExpiry(state.PeerCertificates, opts.TLS, opts.Logger); err != nil {
					conn.Close()
					return nil, err
				}
			}
		}
		return conn, nil
	}
}

// TLSConfig builds the client TLS config from the server profile. verify=off
// is rejected here as a second line of defense even though config validation
// already forbids it.
func TLSConfig(cfg config.TLSConfig, serverName string) (*tls.Config, error) {
	if cfg.Verify != nil && !*cfg.Verify {
		return nil, errors.New("ldapx: tls.verify=off is not supported")
	}
	minVersion, err := minTLSVersion(cfg.MinVersion)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:         minVersion,
		ServerName:         serverName,
		InsecureSkipVerify: false,
	}, nil
}

func minTLSVersion(name string) (uint16, error) {
	switch name {
	case "", "TLSv1.2":
		return tls.VersionTLS12, nil
	case "TLSv1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("ldapx: unsupported tls.min_version %q", name)
	}
}

// checkCertExpiry fails closed when the peer certificate is expired and
// CertExpiryFailClosed is set (default). Expiry within 30 days logs a warning.
func checkCertExpiry(certs []*x509.Certificate, tlsCfg config.TLSConfig, logger *slog.Logger) error {
	if len(certs) == 0 {
		return nil
	}
	leaf := certs[0]
	now := time.Now()
	failClosed := tlsCfg.CertExpiryFailClosed == nil || *tlsCfg.CertExpiryFailClosed
	if now.After(leaf.NotAfter) {
		if failClosed {
			return fmt.Errorf("%w: certificate %q expired at %s",
				ErrTLSCertExpired, leaf.Subject.String(), leaf.NotAfter.Format(time.RFC3339))
		}
		if logger != nil {
			logger.Warn("ldap certificate expired but fail_closed is disabled",
				"event", "ldap.cert_expired",
				"subject", leaf.Subject.String())
		}
		return nil
	}
	if leaf.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
		if logger != nil {
			logger.Warn("ldap certificate expires soon",
				"event", "ldap.cert_expiring",
				"subject", leaf.Subject.String(),
				"not_after", leaf.NotAfter.Format(time.RFC3339))
		}
	}
	return nil
}
