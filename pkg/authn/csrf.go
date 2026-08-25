// Package authn provides the authentication/session-adjacent middlewares.
// CSRF defense follows KTD 9: SameSite=Strict cookies plus an Origin-header
// check on state-changing methods.
package authn

import (
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// CSRF rejects state-changing requests whose Origin header does not match the
// request Host. Requests without an Origin header (curl, same-origin legacy
// clients) pass through; SameSite=Strict cookies cover the browser cases where
// Origin is always present on cross-site state changes.
func CSRF(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isStateChanging(r.Method) {
				origin := r.Header.Get("Origin")
				if origin != "" && !sameOrigin(origin, r.Host) {
					if logger != nil {
						logger.Warn("cross-origin state change rejected",
							"event", "csrf.rejected",
							"method", r.Method,
							"path", r.URL.Path,
						)
					}
					http.Error(w, "Forbidden: cross-origin request rejected", http.StatusForbidden)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isStateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func sameOrigin(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return normalizeHost(u.Host) == normalizeHost(host)
}

// normalizeHost lowercases and strips default ports so Host and Origin compare
// consistently.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	host, port, err := net.SplitHostPort(h)
	if err == nil {
		if port == "80" || port == "443" {
			return host
		}
		return net.JoinHostPort(host, port)
	}
	return h
}
