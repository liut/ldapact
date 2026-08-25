package authn

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/liut/ldapact/pkg/config"
	"github.com/liut/ldapact/pkg/session"
)

type ctxKey int

const sessionKey ctxKey = iota + 1

// Session is the request-scoped session handle attached to the context.
type Session struct {
	ID    string
	Value *session.Value
	// Fresh is true when the session was created during this request (first
	// visit or retry_bind after expiry); fresh sessions are not rotated.
	Fresh bool
}

// SessionFrom returns the session attached by Middleware, or nil.
func SessionFrom(ctx context.Context) *Session {
	s, _ := ctx.Value(sessionKey).(*Session)
	return s
}

// MiddlewareOptions wires the session middleware.
type MiddlewareOptions struct {
	Store         *session.Store
	Logger        *slog.Logger
	ExpiredAction string // config.ExpiredActionRetryBind | config.ExpiredActionRedirectLogin
	Profile       string // bind DN used as profile_ref (R15 actor semantics)
}

// Middleware attaches (or creates, AE1) a server-side session to every
// request. State-changing methods rotate the session ID before the handler
// runs: headers must be committed before the body is written, so a
// post-handler rotation cannot reliably set the Set-Cookie header. Rotating
// on the request (rather than on success only) is the conservative direction
// for session-fixation defense; a failed mutation still leaves the user with
// a valid, freshly keyed session.
func Middleware(opts MiddlewareOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if opts.Store == nil {
				next.ServeHTTP(w, r)
				return
			}
			// Health checks and static assets must not mint sessions or set
			// cookies (monitoring probes, asset caching).
			if r.URL.Path == "/healthz" || strings.HasPrefix(r.URL.Path, "/static/") {
				next.ServeHTTP(w, r)
				return
			}
			sess := opts.ensure(w, r)
			if sess == nil {
				return // 400/503/redirect already written
			}
			if isStateChanging(r.Method) && !sess.Fresh {
				if !opts.rotate(w, r, sess) {
					return // 503 already written
				}
			}
			ctx := context.WithValue(r.Context(), sessionKey, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ensure returns the session for the request, creating one when the cookie is
// missing (AE1 auto-login), handling expiry per ExpiredAction (AE7), and
// rejecting malformed cookies. A nil return means the response is finished.
func (opts MiddlewareOptions) ensure(w http.ResponseWriter, r *http.Request) *Session {
	id, err := session.Read(r)
	switch {
	case errors.Is(err, session.ErrNoCookie):
		return opts.newSession(w)
	case errors.Is(err, session.ErrInvalidCookie):
		session.Clear(w)
		if opts.Logger != nil {
			opts.Logger.Warn("rejected malformed session cookie",
				"event", "session.invalid_cookie",
				"path", r.URL.Path)
		}
		http.Error(w, "Bad Request: invalid session cookie", http.StatusBadRequest)
		return nil
	case err != nil:
		if opts.Logger != nil {
			opts.Logger.Error("read session cookie", "event", "session.read_failed", "error", err)
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil
	}

	v, err := opts.Store.Get(id)
	if err != nil {
		switch {
		case errors.Is(err, session.ErrSessionExpired), errors.Is(err, session.ErrSessionMissing):
			session.Clear(w)
			return opts.handleExpired(w, r)
		default:
			if opts.Logger != nil {
				opts.Logger.Error("session store read failed", "event", "session.store_error", "error", err)
			}
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return nil
		}
	}
	return &Session{ID: id, Value: v}
}

func (opts MiddlewareOptions) newSession(w http.ResponseWriter) *Session {
	id, err := session.NewID()
	if err != nil {
		opts.storeError(w, err)
		return nil
	}
	v, err := opts.Store.Create(id, opts.Profile)
	if err != nil {
		opts.storeError(w, err)
		return nil
	}
	session.Write(w, id)
	if opts.Logger != nil {
		opts.Logger.Info("session created", "event", "session.created")
	}
	return &Session{ID: id, Value: v, Fresh: true}
}

// handleExpired applies the configured session_expired_action (AE7).
func (opts MiddlewareOptions) handleExpired(w http.ResponseWriter, r *http.Request) *Session {
	if opts.Logger != nil {
		opts.Logger.Info("session expired",
			"event", "session.expired",
			"action", opts.ExpiredAction)
	}
	switch opts.ExpiredAction {
	case config.ExpiredActionRedirectLogin:
		next := url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, "/login?next="+next, http.StatusFound)
		return nil
	default: // retry_bind
		return opts.newSession(w)
	}
}

// rotate mints a new session ID, migrates the value, and writes the new
// cookie. Returns false (with a 503 written) on store failure.
func (opts MiddlewareOptions) rotate(w http.ResponseWriter, r *http.Request, sess *Session) bool {
	newID, err := session.NewID()
	if err != nil {
		opts.storeError(w, err)
		return false
	}
	if _, err := opts.Store.Rotate(sess.ID, newID); err != nil {
		opts.storeError(w, err)
		return false
	}
	session.Write(w, newID)
	if opts.Logger != nil {
		opts.Logger.Info("session rotated",
			"event", "session.rotated",
			"method", r.Method,
			"path", r.URL.Path)
	}
	sess.ID = newID
	sess.Fresh = false
	return true
}

func (opts MiddlewareOptions) storeError(w http.ResponseWriter, err error) {
	if opts.Logger != nil {
		opts.Logger.Error("session store operation failed", "event", "session.store_error", "error", err)
	}
	http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
}
