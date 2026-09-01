// Package authn provides the authentication/session middlewares and the
// login gate (U6/R5-R8): every protected request needs a session whose
// encrypted bind credential was minted by /login. Public paths are
// /healthz, /static/*, and /login; everything else redirects to /login.
package authn

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/session"
	"github.com/liut/ldapact/pkg/web"
)

type ctxKey int

const (
	sessionKey ctxKey = iota + 1
	storeKey
)

// Session is the request-scoped session handle attached to the context.
type Session struct {
	ID    string
	Value *session.Value
}

// SessionFrom returns the session attached by Middleware, or nil.
func SessionFrom(ctx context.Context) *Session {
	s, _ := ctx.Value(sessionKey).(*Session)
	return s
}

// StoreFrom returns the session store attached by Middleware (needed by the
// invalidCredentials helper to invalidate the session), or nil.
func StoreFrom(ctx context.Context) session.Store {
	s, _ := ctx.Value(storeKey).(session.Store)
	return s
}

// MiddlewareOptions wires the session middleware.
type MiddlewareOptions struct {
	Store  session.Store
	Cipher *session.CredentialCipher
	Logger *slog.Logger
}

// Middleware enforces the login gate (R5/R8): requests without a valid
// session (or with an undecryptable credential) are redirected to /login;
// valid sessions have their bind credential decrypted and attached to the
// request context. State-changing methods rotate the session ID before the
// handler runs: headers must be committed before the body is written, so a
// post-handler rotation cannot reliably set the Set-Cookie header.
func Middleware(opts MiddlewareOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if opts.Store == nil {
				next.ServeHTTP(w, r)
				return
			}
			// Public paths: health probes, assets, and the login page must
			// not mint sessions or require credentials.
			if isPublic(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			sess, cred, ok := opts.ensure(w, r)
			if !ok {
				return // response already written
			}
			if isStateChanging(r.Method) {
				if !opts.rotate(w, r, sess) {
					return // 503 already written
				}
			}
			ctx := context.WithValue(r.Context(), sessionKey, sess)
			ctx = context.WithValue(ctx, storeKey, opts.Store)
			ctx = ldapx.WithCredential(ctx, cred)
			ctx = web.WithActor(ctx, sess.Value.ProfileRef)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func isPublic(path string) bool {
	return path == "/healthz" || path == "/login" || strings.HasPrefix(path, "/static/")
}

// ensure returns the session for the request, decrypting its bind credential.
// An absent/undecryptable session is invalidated and redirected to /login; a
// nil return means the response is finished.
func (opts MiddlewareOptions) ensure(w http.ResponseWriter, r *http.Request) (*Session, ldapx.BindCredential, bool) {
	id, err := session.Read(r)
	switch {
	case errors.Is(err, session.ErrNoCookie):
		redirectLogin(w, r)
		return nil, ldapx.BindCredential{}, false
	case errors.Is(err, session.ErrInvalidCookie):
		session.Clear(w)
		if opts.Logger != nil {
			opts.Logger.Warn("rejected malformed session cookie",
				"event", "session.invalid_cookie",
				"path", r.URL.Path)
		}
		http.Error(w, "Bad Request: invalid session cookie", http.StatusBadRequest)
		return nil, ldapx.BindCredential{}, false
	case err != nil:
		if opts.Logger != nil {
			opts.Logger.Error("read session cookie", "event", "session.read_failed", "error", err)
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil, ldapx.BindCredential{}, false
	}

	v, err := opts.Store.Get(id)
	if err != nil {
		switch {
		case errors.Is(err, session.ErrSessionExpired), errors.Is(err, session.ErrSessionMissing):
			session.Clear(w)
			redirectLogin(w, r)
			return nil, ldapx.BindCredential{}, false
		default:
			if opts.Logger != nil {
				opts.Logger.Error("session store read failed", "event", "session.store_error", "error", err)
			}
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return nil, ldapx.BindCredential{}, false
		}
	}

	password, err := opts.credentialFor(v)
	if err != nil {
		// Key rotation or tampering (R14): the stored credential cannot be
		// decrypted, so the session is invalid → re-login. Never 500.
		_ = opts.Store.Delete(id)
		session.Clear(w)
		if opts.Logger != nil {
			fp := ""
			if opts.Cipher != nil {
				fp = opts.Cipher.KeyFingerprint()
			}
			opts.Logger.Warn("session credential undecryptable; forcing re-login",
				"event", "session.credential_invalid",
				"key_fingerprint", fp)
		}
		redirectLogin(w, r)
		return nil, ldapx.BindCredential{}, false
	}
	return &Session{ID: id, Value: v}, ldapx.BindCredential{DN: v.ProfileRef, Password: password}, true
}

// credentialFor decrypts the session's encrypted bind password. The bind DN
// is the session's profile_ref (actor semantics, R13).
func (opts MiddlewareOptions) credentialFor(v *session.Value) (string, error) {
	if opts.Cipher == nil {
		return "", errors.New("authn: credential cipher not configured")
	}
	plain, err := opts.Cipher.Decrypt(v.Credential)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// redirectLogin sends the client to the login page, carrying the current
// request URI so the post-login redirect returns here.
func redirectLogin(w http.ResponseWriter, r *http.Request) {
	next := url.QueryEscape(r.URL.RequestURI())
	http.Redirect(w, r, "/login?next="+next, http.StatusFound)
}

// InvalidCredentialsRedirect invalidates the current session, clears the
// cookie, and redirects to /login. Handlers call it when an LDAP operation
// fails with invalidCredentials (R8/AE5): the stored bind credential no
// longer works (e.g. the directory password changed).
func InvalidCredentialsRedirect(w http.ResponseWriter, r *http.Request) {
	if s := SessionFrom(r.Context()); s != nil {
		if store := StoreFrom(r.Context()); store != nil {
			_ = store.Delete(s.ID)
		}
	}
	session.Clear(w)
	// Carry the intended destination so a directory password change drops
	// the user back where they were, matching the expiry redirect.
	next := url.QueryEscape(r.URL.RequestURI())
	http.Redirect(w, r, "/login?next="+next, http.StatusFound)
}

// rotate mints a new session ID, migrates the value (including the encrypted
// credential), and writes the new cookie. Returns false (with a 503 written)
// on store failure.
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
	return true
}

func (opts MiddlewareOptions) storeError(w http.ResponseWriter, err error) {
	if opts.Logger != nil {
		opts.Logger.Error("session store operation failed", "event", "session.store_error", "error", err)
	}
	http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
}
