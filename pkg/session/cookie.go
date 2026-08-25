package session

import (
	"encoding/base64"
	"errors"
	"net/http"
)

// CookieName follows the __Host- prefix rules (KTD 8): Secure, Path=/, and no
// Domain attribute are enforced on write.
const CookieName = "__Host-LDAPADM_SID"

// ErrNoCookie is returned by Read when the cookie is absent.
var ErrNoCookie = errors.New("session: cookie missing")

// ErrInvalidCookie is returned when a cookie with the right name carries a
// malformed session ID.
var ErrInvalidCookie = errors.New("session: cookie value invalid")

// Read extracts the session ID from the request cookie. Cookie attributes
// (Secure/Domain/Path) are not transmitted by clients, so the __Host- rules
// are enforced on the write side (see Write) plus strict value validation
// here; foreign or malformed IDs are rejected rather than trusted.
func Read(r *http.Request) (string, error) {
	c, err := r.Cookie(CookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return "", ErrNoCookie
	}
	if err != nil {
		return "", err
	}
	if !ValidID(c.Value) {
		return "", ErrInvalidCookie
	}
	return c.Value, nil
}

// ValidID reports whether v is a plausible session ID: base64url of IDBytes
// random bytes.
func ValidID(v string) bool {
	if len(v) != base64.RawURLEncoding.EncodedLen(IDBytes) {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil && len(b) == IDBytes
}

// Write sets the session cookie with the full security attribute set
// (Secure, HttpOnly, SameSite=Strict, Path=/, no Domain, session cookie).
func Write(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    id,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// Clear expires the session cookie client-side.
func Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
