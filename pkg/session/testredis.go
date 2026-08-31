package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Test Redis backend probe for integration tests, mirroring the
// internal/testldap contract (first match wins):
//  1. LDAPADM_TEST_REDIS_URL — caller-provisioned dedicated test instance.
//  2. A local redis-server binary — ephemeral foreground instance with a
//     generated temp data directory on a random 127.0.0.1 port. System
//     configs, data dirs, and services are never touched.
//  3. Docker — an ephemeral testcontainers-go Redis container.
//  4. Unavailable — skip.

var errRedisUnavailable = errors.New(
	"session: no Redis test backend available — set LDAPADM_TEST_REDIS_URL, install Docker, or install a local redis-server binary")

type testRedis struct {
	URL  string
	stop func()
}

func (r *testRedis) Stop() {
	if r.stop != nil {
		r.stop()
		r.stop = nil
	}
}

// startTestRedis selects a backend and returns a ready instance.
func startTestRedis(ctx context.Context) (*testRedis, error) {
	if u := os.Getenv("LDAPADM_TEST_REDIS_URL"); u != "" {
		return &testRedis{URL: u}, nil
	}
	if bin, err := exec.LookPath("redis-server"); err == nil {
		return startLocalRedis(ctx, bin)
	}
	if dockerAvailable() {
		return dockerRedis(ctx)
	}
	return nil, errRedisUnavailable
}

func startLocalRedis(ctx context.Context, bin string) (*testRedis, error) {
	dir, err := os.MkdirTemp("", "ldapact-redis-*")
	if err != nil {
		return nil, fmt.Errorf("session: redis test dir: %w", err)
	}
	port, err := freePort()
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	cmd := exec.Command(bin,
		"--bind", "127.0.0.1",
		"--port", strconv.Itoa(port),
		"--save", "",
		"--appendonly", "no",
		"--dir", dir,
		"--logfile", filepath.Join(dir, "redis.log"))
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("session: start redis-server: %w", err)
	}
	url := "redis://127.0.0.1:" + strconv.Itoa(port)
	if err := waitRedis(ctx, url, 10*time.Second); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return &testRedis{
		URL: url,
		stop: func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			_ = os.RemoveAll(dir)
		},
	}, nil
}

func dockerRedis(ctx context.Context) (*testRedis, error) {
	req := testcontainers.ContainerRequest{
		Image:        "docker.io/library/redis:7-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForListeningPort("6379/tcp").WithStartupTimeout(60 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("session: start redis container: %w", err)
	}
	port, err := container.MappedPort(ctx, "6379/tcp")
	if err != nil {
		_ = testcontainers.TerminateContainer(container)
		return nil, fmt.Errorf("session: redis mapped port: %w", err)
	}
	return &testRedis{
		URL:  fmt.Sprintf("redis://127.0.0.1:%d", port.Num()),
		stop: func() { _ = testcontainers.TerminateContainer(container) },
	}, nil
}

func dockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "docker", "info").Run() == nil
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("session: free port: %w", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func waitRedis(ctx context.Context, url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		rdb := redis.NewClient(&redis.Options{Addr: redisAddr(url)})
		err := rdb.Ping(ctx).Err()
		_ = rdb.Close()
		if err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("session: redis test backend not ready at %s", url)
}

func redisAddr(url string) string {
	if u, err := redis.ParseURL(url); err == nil {
		return u.Addr
	}
	return url
}
