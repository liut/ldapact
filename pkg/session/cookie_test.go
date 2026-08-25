package session

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteCookieSecurityAttributes(t *testing.T) {
	rr := httptest.NewRecorder()
	Write(rr, "sess-id")
	c := rr.Result().Cookies()
	if len(c) != 1 {
		t.Fatalf("cookies = %d", len(c))
	}
	cookie := c[0]
	if cookie.Name != CookieName {
		t.Errorf("name = %q", cookie.Name)
	}
	if !cookie.Secure {
		t.Error("Secure must be set")
	}
	if !cookie.HttpOnly {
		t.Error("HttpOnly must be set")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Errorf("Path = %q", cookie.Path)
	}
	if cookie.Domain != "" {
		t.Errorf("Domain must be absent (__Host- rule), got %q", cookie.Domain)
	}
	if cookie.MaxAge != 0 {
		t.Errorf("MaxAge = %d, want session cookie", cookie.MaxAge)
	}
}

func TestClearCookie(t *testing.T) {
	rr := httptest.NewRecorder()
	Clear(rr)
	c := rr.Result().Cookies()
	if len(c) != 1 || c[0].MaxAge != -1 {
		t.Fatalf("clear cookie = %+v", c)
	}
}

func TestReadCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := Read(req); !errors.Is(err, ErrNoCookie) {
		t.Fatalf("want ErrNoCookie, got %v", err)
	}

	id, _ := NewID()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(&http.Cookie{Name: CookieName, Value: id})
	got, err := Read(req2)
	if err != nil || got != id {
		t.Fatalf("Read = %q, %v", got, err)
	}

	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.AddCookie(&http.Cookie{Name: CookieName, Value: "garbage!"})
	if _, err := Read(req3); !errors.Is(err, ErrInvalidCookie) {
		t.Fatalf("want ErrInvalidCookie, got %v", err)
	}
}

func TestValidID(t *testing.T) {
	if ValidID("") {
		t.Error("empty id invalid")
	}
	if ValidID("short") {
		t.Error("short id invalid")
	}
	id, _ := NewID()
	if !ValidID(id) {
		t.Error("valid id rejected")
	}
	if ValidID(base64.StdEncoding.EncodeToString(make([]byte, 32))) {
		t.Error("standard base64 (with padding) rejected")
	}
}
