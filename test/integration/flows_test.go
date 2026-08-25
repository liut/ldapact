package integration

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func do(t *testing.T, method, path string, form url.Values) *http.Response {
	t.Helper()
	var body io.Reader
	contentType := ""
	if form != nil {
		body = strings.NewReader(form.Encode())
		contentType = "application/x-www-form-urlencoded"
	}
	req, err := http.NewRequest(method, serverURL()+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Origin", serverURL())
	resp, err := client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestFlowF1TreeBrowse: home scaffold + paged children (AE1/AE2 mechanics).
func TestFlowF1TreeBrowse(t *testing.T) {
	resp := do(t, http.MethodGet, "/", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("home = %d", resp.StatusCode)
	}
	home := body(t, resp)
	for _, want := range []string{`role="tree"`, "dc=example,dc=com", "Import LDIF", "Search"} {
		if !strings.Contains(home, want) {
			t.Errorf("home missing %q", want)
		}
	}

	resp = do(t, http.MethodGet, "/api/tree/dc=example,dc=com/children?page=1&level=2", nil)
	page1 := body(t, resp)
	if !strings.Contains(page1, ">People<") || !strings.Contains(page1, ">Groups<") {
		t.Errorf("root children: %s", page1)
	}

	resp = do(t, http.MethodGet, "/api/tree/ou=People,dc=example,dc=com/children?page=1&level=3", nil)
	users := body(t, resp)
	if !strings.Contains(users, "Load more") {
		t.Error("page 1 of 1210 users must offer Load more (paging)")
	}
	if strings.Count(users, `role="treeitem"`) < 100 {
		t.Errorf("page size < 100: %d", strings.Count(users, `role="treeitem"`))
	}
	resp = do(t, http.MethodGet, "/api/tree/ou=People,dc=example,dc=com/children?page=2&level=3", nil)
	page2 := body(t, resp)
	if strings.Contains(page2, "u0001") {
		t.Errorf("page 2 must not repeat page 1: %.200s", page2)
	}
	if strings.Count(page2, `role="treeitem"`) < 99 {
		t.Errorf("page 2 too small: %d", strings.Count(page2, `role="treeitem"`))
	}
}

// TestFlowF2CreateAE3: template form + create + bind (AE3) and audit (AE6).
func TestFlowF2CreateAE3(t *testing.T) {
	resp := do(t, http.MethodGet, "/api/template/posixAccount", nil)
	form := body(t, resp)
	for _, want := range []string{"Generic: User Account", "uidNumber", "gidNumber", "LDAPAutofill.bind"} {
		if !strings.Contains(form, want) {
			t.Errorf("create form missing %q", want)
		}
	}
	resp = do(t, http.MethodPost, "/api/template/posixAccount/create", url.Values{
		"container": {"ou=People,dc=example,dc=com"},
		"givenName": {"Smoke"}, "sn": {"One"}, "cn": {"smoke1"}, "uid": {"smoke1"},
		"userPassword": {"Smoke#2026"}, "homeDirectory": {"/home/smoke1"},
		"uidNumber": {"3001"}, "gidNumber": {"101"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create = %d: %s", resp.StatusCode, body(t, resp))
	}
	if got := resp.Header.Get("X-Mutated-Subtree"); got != "ou=People,dc=example,dc=com" {
		t.Errorf("mutated header = %q", got)
	}

	logs := envLogBuf.String()
	if !strings.Contains(logs, `"event":"ldap.create"`) || !strings.Contains(logs, `"dn":"cn=smoke1,ou=People,dc=example,dc=com"`) {
		t.Errorf("audit line missing (AE6): %.400s", logs)
	}
	if strings.Contains(logs, "Smoke#2026") {
		t.Error("log must never contain the password (AE6)")
	}
}

// TestFlowF3PasswordAE4: change password then bind with the new one.
func TestFlowF3PasswordAE4(t *testing.T) {
	resp := do(t, http.MethodPost, "/api/entry/uid=u0001,ou=People,dc=example,dc=com/password", url.Values{
		"new_password": {"Changed#2026"}, "confirm_password": {"Changed#2026"},
	})
	if !strings.Contains(body(t, resp), "Password changed") {
		t.Fatalf("password change failed: %d %s", resp.StatusCode, body(t, resp))
	}
	conn, err := dialEnv()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Bind("uid=u0001,ou=People,dc=example,dc=com", "Changed#2026"); err != nil {
		t.Fatalf("bind with new password: %v", err)
	}
}

// TestFlowF4ImportAE5: partial-success import.
func TestFlowF4ImportAE5(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("ldif", "in.ldif")
	_, _ = fw.Write([]byte(`version: 1
dn: cn=import1,ou=Services,dc=example,dc=com
objectClass: inetOrgPerson
cn: import1
sn: Imported

dn: cn=badimport,ou=Services,dc=example,dc=com
objectClass: inetOrgPerson
cn: badimport
`))
	_ = mw.Close()
	req, _ := http.NewRequest(http.MethodPost, serverURL()+"/api/import", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Origin", serverURL())
	resp, err := client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := body(t, resp)
	if !strings.Contains(out, "Success: <strong>1</strong>") || !strings.Contains(out, "Failed: <strong>1</strong>") {
		t.Errorf("import summary (AE5): %s", out)
	}
}

// TestFlowF5F6: rename then delete the renamed entry.
func TestFlowF5F6(t *testing.T) {
	resp := do(t, http.MethodPost, "/api/entry/uid=u0002,ou=People,dc=example,dc=com/rename", url.Values{
		"new_rdn": {"uid=u0002r"}, "delete_old_rdn": {"1"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rename = %d: %s", resp.StatusCode, body(t, resp))
	}
	resp = do(t, http.MethodPost, "/api/entry/uid=u0002r,ou=People,dc=example,dc=com/delete", url.Values{
		"confirm_dn": {"uid=u0002r,ou=People,dc=example,dc=com"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete = %d: %s", resp.StatusCode, body(t, resp))
	}
}

// TestFlowF7F8: export subtree + search.
func TestFlowF7F8(t *testing.T) {
	resp := do(t, http.MethodGet, "/api/export?dn=ou=Services,dc=example,dc=com&scope=subtree", nil)
	export := body(t, resp)
	if !strings.Contains(export, "dn: cn=import1,ou=Services,dc=example,dc=com") {
		t.Errorf("export missing imported entry: %.300s", export)
	}

	resp = do(t, http.MethodGet, "/api/search?q=(uid=u0001)&scope=subtree", nil)
	search := body(t, resp)
	if !strings.Contains(search, "uid=u0001,ou=People,dc=example,dc=com") {
		t.Errorf("search missing result: %.300s", search)
	}
	resp = do(t, http.MethodGet, "/api/search?q=(uid=u0001", nil)
	if !strings.Contains(body(t, resp), "filter syntax error at position") {
		t.Error("invalid filter feedback missing")
	}
}
