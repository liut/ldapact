// Package testldap starts throwaway LDAP instances for integration tests.
//
// Backend selection (first match wins):
//  1. LDAPADM_TEST_LDAP_URL — connect to a caller-provisioned server (no
//     lifecycle management; must be a dedicated test instance).
//  2. Docker — an ephemeral testcontainers-go OpenLDAP container.
//  3. A local slapd binary — an ephemeral foreground instance running from a
//     generated config and temp data directory on a random loopback port
//     (MacPorts/Homebrew/system OpenLDAP).
//
// SAFETY CONTRACT: this package never touches a real LDAP service. It never
// reads or writes system configs (e.g. /opt/local/etc/openldap), system data
// directories (e.g. /var/lib/ldap, /opt/local/var/db/openldap), system
// pidfiles, or launchd/systemd services. Local instances are started as the
// current user from fully generated files under a temp dir, bound to
// 127.0.0.1 on a free port, and terminated + deleted on Stop.
package testldap

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/config"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Test fixture identity shared by all backends.
const (
	AdminDN       = "cn=admin,dc=example,dc=com"
	AdminPassword = "admin_password"
	BaseDN        = "dc=example,dc=com"
)

// ErrUnavailable is returned by Start when no backend is usable.
var ErrUnavailable = errors.New(
	"testldap: no LDAP backend available — set LDAPADM_TEST_LDAP_URL, install Docker, or install a local slapd binary")

// Instance is a running test LDAP instance.
type Instance struct {
	URL           string
	AdminDN       string
	AdminPassword string
	BaseDN        string
	// SupportsSSHA512 is true when the backend verifies {SSHA512} binds. Some
	// directory builds only support legacy schemes; Config() downgrades the
	// write scheme to {SSHA} in that case.
	SupportsSSHA512 bool
	stop            func()
}

// Stop terminates the instance and removes its temp data (no-op for the
// caller-provisioned backend).
func (i *Instance) Stop() {
	if i.stop != nil {
		i.stop()
		i.stop = nil
	}
}

// Config returns a server profile pointing at this instance.
func (i *Instance) Config() *config.Config {
	cfg := &config.Config{}
	cfg.LDAP.URL = i.URL
	cfg.LDAP.BaseDN = i.BaseDN
	cfg.LDAP.BindDN = i.AdminDN
	cfg.LDAP.PoolSize = 2
	if !i.SupportsSSHA512 {
		cfg.LDAP.PasswordScheme = "SSHA"
	}
	return cfg
}

// Start selects a backend and returns a ready instance.
func Start(ctx context.Context) (*Instance, error) {
	var inst *Instance
	var err error
	switch {
	case os.Getenv("LDAPADM_TEST_LDAP_URL") != "":
		inst = envInstance()
	case dockerAvailable():
		inst, err = dockerInstance(ctx)
	case localSlapdAvailable():
		inst, err = localInstance(ctx)
	default:
		return nil, ErrUnavailable
	}
	if err != nil {
		return nil, err
	}
	if err := waitReady(ctx, inst); err != nil {
		inst.Stop()
		return nil, err
	}
	if err := ensureBase(ctx, inst); err != nil {
		inst.Stop()
		return nil, err
	}
	inst.SupportsSSHA512 = probeSSHA512(ctx, inst)
	return inst, nil
}

// ensureBase creates the suffix entry (dc=example,dc=com) on backends that do
// not provision it automatically (local slapd). Already-present entries
// (Docker image, caller-provisioned server) are tolerated.
func ensureBase(ctx context.Context, inst *Instance) error {
	conn, err := ldap.DialURL(inst.URL, ldap.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}))
	if err != nil {
		return fmt.Errorf("testldap: ensure base dial: %w", err)
	}
	defer conn.Close()
	if err := conn.Bind(inst.AdminDN, inst.AdminPassword); err != nil {
		return fmt.Errorf("testldap: ensure base bind: %w", err)
	}
	req := ldap.NewAddRequest(inst.BaseDN, nil)
	req.Attribute("objectClass", []string{"top", "domain"})
	if v := baseRDNPair(inst.BaseDN); v != "" {
		req.Attribute(v, []string{baseRDNValue(inst.BaseDN)})
	}
	err = conn.Add(req)
	var lerr *ldap.Error
	if errors.As(err, &lerr) && lerr.ResultCode == ldap.LDAPResultEntryAlreadyExists {
		return nil
	}
	if err != nil {
		return fmt.Errorf("testldap: ensure base %s: %w", inst.BaseDN, err)
	}
	return nil
}

// baseRDNPair returns the attribute type of the base DN's first RDN
// (e.g. "dc" for dc=example,dc=com).
func baseRDNPair(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) == 0 {
		return ""
	}
	return parsed.RDNs[0].Attributes[0].Type
}

func baseRDNValue(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) == 0 {
		return ""
	}
	return parsed.RDNs[0].Attributes[0].Value
}

// probeSSHA512 determines whether the backend verifies {SSHA512} binds
// (MacPorts/Homebrew builds sometimes lack SHA-2 password support). Failure is
// best-effort: any error other than a failed bind leaves the default true.
func probeSSHA512(ctx context.Context, inst *Instance) bool {
	conn, err := ldap.DialURL(inst.URL)
	if err != nil {
		return true
	}
	defer conn.Close()
	if err := conn.Bind(inst.AdminDN, inst.AdminPassword); err != nil {
		return true
	}
	pw := "probe-password"
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return true
	}
	h := sha512.New()
	_, _ = h.Write([]byte(pw))
	_, _ = h.Write(salt)
	hashed := "{SSHA512}" + base64.StdEncoding.EncodeToString(append(h.Sum(nil), salt...))
	dn := "cn=ssha512-probe," + inst.BaseDN
	req := ldap.NewAddRequest(dn, nil)
	req.Attribute("objectClass", []string{"top", "person"})
	req.Attribute("cn", []string{"ssha512-probe"})
	req.Attribute("sn", []string{"probe"})
	req.Attribute("userPassword", []string{hashed})
	if err := conn.Add(req); err != nil {
		return true // could not probe (schema/ACL); do not change behavior
	}
	defer func() { _ = conn.Del(ldap.NewDelRequest(dn, nil)) }()
	probe, err := ldap.DialURL(inst.URL)
	if err != nil {
		return true
	}
	defer probe.Close()
	return probe.Bind(dn, pw) == nil
}

// envInstance uses a caller-provisioned server; no lifecycle management.
func envInstance() *Instance {
	return &Instance{
		URL:           strings.TrimSpace(os.Getenv("LDAPADM_TEST_LDAP_URL")),
		AdminDN:       envOr("LDAPADM_TEST_LDAP_BIND_DN", AdminDN),
		AdminPassword: envOr("LDAPADM_TEST_LDAP_BIND_PASSWORD", AdminPassword),
		BaseDN:        envOr("LDAPADM_TEST_LDAP_BASE_DN", BaseDN),
	}
}

func dockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "docker", "info").Run() == nil
}

func dockerInstance(ctx context.Context) (*Instance, error) {
	req := testcontainers.ContainerRequest{
		Image:        openldapImage(),
		ExposedPorts: []string{"389/tcp"},
		Env: map[string]string{
			"LDAP_ADMIN_NAME":     "admin",
			"LDAP_ADMIN_PASSWORD": AdminPassword,
			"LDAP_BASE_DN":        BaseDN,
		},
		WaitingFor: wait.ForListeningPort("389/tcp").WithStartupTimeout(120 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("testldap: start OpenLDAP container: %w", err)
	}
	port, err := container.MappedPort(ctx, "389/tcp")
	if err != nil {
		_ = testcontainers.TerminateContainer(container)
		return nil, fmt.Errorf("testldap: mapped port: %w", err)
	}
	return &Instance{
		URL:           fmt.Sprintf("ldap://127.0.0.1:%d", port.Num()),
		AdminDN:       AdminDN,
		AdminPassword: AdminPassword,
		BaseDN:        BaseDN,
		stop:          func() { _ = testcontainers.TerminateContainer(container) },
	}, nil
}

// openldapImage returns the Docker image for the ephemeral test container.
// LDAPADM_TEST_LDAP_IMAGE overrides the default.
func openldapImage() string {
	if img := strings.TrimSpace(os.Getenv("LDAPADM_TEST_LDAP_IMAGE")); img != "" {
		return img
	}
	return "docker.io/liut7/staffio-ldap"
}

// localInstance starts an ephemeral foreground slapd from generated files.
// It never reads the system slapd.conf and never writes outside its temp dir.
func localInstance(ctx context.Context) (*Instance, error) {
	slapd, err := findSlapd()
	if err != nil {
		return nil, ErrUnavailable
	}
	schemaDir, err := findSchemaDir()
	if err != nil {
		return nil, ErrUnavailable
	}
	tmp, err := os.MkdirTemp("", "ldapact-slapd-*")
	if err != nil {
		return nil, err
	}
	dataDir := filepath.Join(tmp, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		os.RemoveAll(tmp)
		return nil, err
	}
	port, err := freePort()
	if err != nil {
		os.RemoveAll(tmp)
		return nil, err
	}
	conf := filepath.Join(tmp, "slapd.conf")
	if err := writeConfig(conf, schemaDir, tmp, dataDir); err != nil {
		os.RemoveAll(tmp)
		return nil, err
	}

	var logBuf bytes.Buffer
	url := fmt.Sprintf("ldap://127.0.0.1:%d", port)
	cmd := exec.CommandContext(ctx, slapd, "-d", "0", "-f", conf, "-h", url)
	cmd.Stdout = &logBuf
	cmd.Stderr = &logBuf
	if err := cmd.Start(); err != nil {
		os.RemoveAll(tmp)
		return nil, fmt.Errorf("testldap: start %s: %w", slapd, err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		_ = os.RemoveAll(tmp)
	}
	// waitReady is called by Start after we return; the instance must also be
	// torn down if that wait fails, which Start handles via inst.Stop().
	return &Instance{
		URL:           url,
		AdminDN:       AdminDN,
		AdminPassword: AdminPassword,
		BaseDN:        BaseDN,
		stop:          stop,
	}, nil
}

// writeConfig generates an isolated slapd.conf in tmp (never the system one).
func writeConfig(conf, schemaDir, tmp, dataDir string) error {
	var b strings.Builder
	for _, schema := range []string{"core", "cosine", "inetorgperson", "nis"} {
		fmt.Fprintf(&b, "include %s/%s.schema\n", schemaDir, schema)
	}
	fmt.Fprintf(&b, "pidfile %s/slapd.pid\n", tmp)
	fmt.Fprintf(&b, "argsfile %s/slapd.args\n", tmp)
	fmt.Fprintf(&b, "database mdb\n")
	fmt.Fprintf(&b, "suffix %q\n", BaseDN)
	fmt.Fprintf(&b, "rootdn %q\n", AdminDN)
	fmt.Fprintf(&b, "rootpw %s\n", AdminPassword)
	fmt.Fprintf(&b, "directory %s\n", dataDir)
	fmt.Fprintf(&b, "maxsize 1073741824\n")
	fmt.Fprintf(&b, "access to attrs=userPassword by self write by * read\n")
	fmt.Fprintf(&b, "access to * by * read\n")
	return os.WriteFile(conf, []byte(b.String()), 0o600)
}

func findSlapd() (string, error) {
	if p := strings.TrimSpace(os.Getenv("LDAPADM_TEST_SLAPD")); p != "" {
		if fileExists(p) {
			return p, nil
		}
	}
	candidates := []string{
		"/opt/local/libexec/slapd",
		"/opt/local/sbin/slapd",
		"/usr/local/opt/openldap/libexec/slapd",
		"/usr/sbin/slapd",
	}
	for _, c := range candidates {
		if fileExists(c) {
			return c, nil
		}
	}
	if p, err := exec.LookPath("slapd"); err == nil {
		return p, nil
	}
	return "", ErrUnavailable
}

func findSchemaDir() (string, error) {
	if p := strings.TrimSpace(os.Getenv("LDAPADM_TEST_SLAPD_SCHEMA")); p != "" {
		if fileExists(filepath.Join(p, "core.schema")) {
			return p, nil
		}
	}
	candidates := []string{
		"/opt/local/etc/openldap/schema",
		"/usr/local/etc/openldap/schema",
		"/usr/local/opt/openldap/etc/openldap/schema",
		"/opt/homebrew/etc/openldap/schema",
		"/etc/openldap/schema",
	}
	for _, c := range candidates {
		if fileExists(filepath.Join(c, "core.schema")) {
			return c, nil
		}
	}
	return "", ErrUnavailable
}

func localSlapdAvailable() bool {
	_, err := findSlapd()
	return err == nil
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// waitReady polls an admin bind until the instance accepts connections.
func waitReady(ctx context.Context, inst *Instance) error {
	timeout := time.After(60 * time.Second)
	for {
		conn, err := ldap.DialURL(inst.URL, ldap.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}))
		if err == nil {
			bindErr := conn.Bind(inst.AdminDN, inst.AdminPassword)
			_ = conn.Close()
			if bindErr == nil {
				return nil
			}
		}
		select {
		case <-timeout:
			return fmt.Errorf("testldap: instance %s not ready: %v", inst.URL, err)
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
