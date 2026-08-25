package entry

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/tplengine"
	"github.com/liut/ldapact/pkg/web"
)

type fakeClient struct {
	searchFn   func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error)
	addFn      func(ctx context.Context, dn string, attrs map[string][]string) error
	modifyFn   func(ctx context.Context, dn string, changes []ldap.Change) error
	deleteFn   func(ctx context.Context, dn string) error
	modifyDNFn func(ctx context.Context, dn, newRDN string, deleteOldRDN bool, newSuperior string) error
	schema     *ldapx.Schema
	baseDN     string
}

func (f *fakeClient) Search(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if f.searchFn != nil {
		return f.searchFn(ctx, req)
	}
	return &ldap.SearchResult{}, nil
}
func (f *fakeClient) Add(ctx context.Context, dn string, attrs map[string][]string) error {
	if f.addFn != nil {
		return f.addFn(ctx, dn, attrs)
	}
	return nil
}
func (f *fakeClient) Modify(ctx context.Context, dn string, changes []ldap.Change) error {
	if f.modifyFn != nil {
		return f.modifyFn(ctx, dn, changes)
	}
	return nil
}
func (f *fakeClient) Delete(ctx context.Context, dn string) error {
	if f.deleteFn != nil {
		return f.deleteFn(ctx, dn)
	}
	return nil
}
func (f *fakeClient) ModifyDN(ctx context.Context, dn, newRDN string, deleteOldRDN bool, newSuperior string) error {
	if f.modifyDNFn != nil {
		return f.modifyDNFn(ctx, dn, newRDN, deleteOldRDN, newSuperior)
	}
	return nil
}
func (f *fakeClient) Schema() *ldapx.Schema { return f.schema }
func (f *fakeClient) BaseDN() string        { return f.baseDN }

func testHandler(t *testing.T, client EntryClient) *Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	renderer := web.New(web.MustParse(nil))
	loader := fixtureLoader(t)
	return New(client, renderer, logger, loader, nil, nil)
}

func fixtureLoader(t *testing.T) *TemplateLoader {
	t.Helper()
	dir := filepath.Join("..", "tplengine", "fixtures")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		fsys["creation/"+e.Name()] = &fstest.MapFile{Data: b}
	}
	return NewTemplateLoader(fsys, "")
}

func posixEntry() *ldap.Entry {
	return &ldap.Entry{
		DN: "cn=alice,ou=People,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"top", "person", "inetOrgPerson"}},
			{Name: "cn", Values: []string{"alice"}},
			{Name: "sn", Values: []string{"Smith"}},
			{Name: "uid", Values: []string{"alice"}},
			{Name: "userPassword", Values: []string{"{SSHA512}hash"}},
		},
	}
}

func TestCreateFormRenders(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			// uidNumber GetNextNumber + gidNumber PickList.
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				{DN: "cn=staff,ou=Groups,dc=example,dc=com", Attributes: []*ldap.EntryAttribute{{Name: "gidNumber", Values: []string{"100"}}, {Name: "cn", Values: []string{"staff"}}}},
			}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/template/posixAccount", nil)
	req.SetPathValue("name", "posixAccount")
	h.CreateForm(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		"Generic: User Account",
		`name="givenName"`,
		`name="userPassword"`,
		`name="gidNumber"`,
		`>staff<`,
		`name="uidNumber"`,
		"LDAPAutofill.bind",
		`aria-current="step"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("form missing %q", want)
		}
	}
}

func TestCreateSubmitSuccess(t *testing.T) {
	var addedDN string
	var addedAttrs map[string][]string
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		addFn: func(ctx context.Context, dn string, attrs map[string][]string) error {
			addedDN = dn
			addedAttrs = attrs
			return nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{
		"container":     {"ou=People,dc=example,dc=com"},
		"givenName":     {"Alice"},
		"sn":            {"Smith"},
		"cn":            {"alice"},
		"uid":           {"alice"},
		"userPassword":  {"NewPass#2026"},
		"homeDirectory": {"/home/alice"},
		"uidNumber":     {"1001"},
		"gidNumber":     {"100"},
		"loginShell":    {"/bin/bash"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/template/posixAccount/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("name", "posixAccount")
	h.CreateSubmit(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
	if addedDN != "cn=alice,ou=People,dc=example,dc=com" {
		t.Errorf("dn = %q", addedDN)
	}
	if !containsAll(addedAttrs["objectClass"], "inetOrgPerson", "posixAccount") {
		t.Errorf("objectClasses = %v", addedAttrs["objectClass"])
	}
	pw := addedAttrs["userPassword"][0]
	if !strings.HasPrefix(pw, "{SSHA512}") {
		t.Errorf("password not SSHA512-hashed: %.20s", pw)
	}
	if !tplengine.VerifyPassword(pw, "NewPass#2026") {
		t.Error("stored hash does not verify")
	}
	if got := rr.Header().Get("X-Mutated-Subtree"); got != "ou=People,dc=example,dc=com" {
		t.Errorf("X-Mutated-Subtree = %q", got)
	}
}

func TestCreateSubmitMissingRequired(t *testing.T) {
	fake := &fakeClient{baseDN: "dc=example,dc=com"}
	h := testHandler(t, fake)
	form := url.Values{"container": {"dc=example,dc=com"}, "givenName": {"Alice"}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/template/posixAccount/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("name", "posixAccount")
	h.CreateSubmit(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, "This field is required") || !strings.Contains(body, `aria-invalid="true"`) {
		t.Errorf("missing-required feedback: %s", body)
	}
}

func TestCreateSubmitAddFailure(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		addFn: func(ctx context.Context, dn string, attrs map[string][]string) error {
			return &ldapx.LDAPError{Op: "add", Code: 65, DN: dn, Err: errors.New("object class violation")}
		},
	}
	h := testHandler(t, fake)
	form := url.Values{
		"container": {"dc=example,dc=com"}, "givenName": {"A"}, "sn": {"B"},
		"cn": {"ab"}, "uid": {"ab"}, "userPassword": {"x"}, "uidNumber": {"1"}, "gidNumber": {"1"},
		"homeDirectory": {"/home/ab"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/template/posixAccount/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("name", "posixAccount")
	h.CreateSubmit(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, "schema violation") || !strings.Contains(body, "rollback") {
		t.Errorf("add-failure feedback: %s", body)
	}
}

func TestDetail(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{posixEntry()}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/cn=alice,ou=People,dc=example,dc=com", nil)
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.Detail(rr, req)
	body := rr.Body.String()
	for _, want := range []string{"alice", "Smith", "Change password", "SSHA512", "Rename / move", "Delete", "Export LDIF", `role="main"`} {
		if !strings.Contains(body, want) {
			t.Errorf("detail missing %q", want)
		}
	}
	if strings.Contains(body, "hash") {
		t.Error("detail must not echo the userPassword value")
	}
	if !strings.Contains(body, "[redacted]") {
		t.Error("detail should show [redacted] for userPassword")
	}
}

func TestDetailNotFound(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, &ldapx.LDAPError{Op: "search", Code: 32, DN: "x", Err: errors.New("no such object")}
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/x", nil)
	req.SetPathValue("dn", "x")
	h.Detail(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("code = %d", rr.Code)
	}
}

func TestPasswordChangeSuccess(t *testing.T) {
	var modifiedDN string
	var changes []ldap.Change
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{posixEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, ch []ldap.Change) error {
			modifiedDN = dn
			changes = ch
			return nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{"new_password": {"NewPass#2026"}, "confirm_password": {"NewPass#2026"}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=alice,ou=People,dc=example,dc=com/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.PasswordChange(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
	if modifiedDN == "" || len(changes) != 1 || changes[0].Modification.Type != "userPassword" {
		t.Fatalf("modify = %q %+v", modifiedDN, changes)
	}
	hashed := changes[0].Modification.Vals[0]
	if !strings.HasPrefix(hashed, "{SSHA512}") || !tplengine.VerifyPassword(hashed, "NewPass#2026") {
		t.Errorf("password hash: %.30s", hashed)
	}
	if !strings.Contains(rr.Body.String(), "Password changed") {
		t.Errorf("success banner missing: %s", rr.Body.String())
	}
}

func TestPasswordChangeMismatch(t *testing.T) {
	fake := &fakeClient{baseDN: "dc=example,dc=com"}
	h := testHandler(t, fake)
	form := url.Values{"new_password": {"a"}, "confirm_password": {"b"}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/x/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "x")
	h.PasswordChange(rr, req)
	if !strings.Contains(rr.Body.String(), "do not match") {
		t.Errorf("mismatch feedback: %s", rr.Body.String())
	}
}

func TestDeleteLeaf(t *testing.T) {
	var deleted string
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{}, nil // no children
		},
		deleteFn: func(ctx context.Context, dn string) error {
			deleted = dn
			return nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{"confirm_dn": {"cn=alice,ou=People,dc=example,dc=com"}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=alice,ou=People,dc=example,dc=com/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.DeleteSubmit(rr, req)
	if deleted != "cn=alice,ou=People,dc=example,dc=com" {
		t.Errorf("deleted = %q", deleted)
	}
	if got := rr.Header().Get("X-Mutated-Subtree"); got != "ou=People,dc=example,dc=com" {
		t.Errorf("mutated header = %q", got)
	}
}

func TestDeleteNonLeafRequiresTypedDN(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{{DN: "cn=child,ou=People,dc=example,dc=com"}}}, nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{"confirm_dn": {"wrong-dn"}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/ou=People,dc=example,dc=com/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "ou=People,dc=example,dc=com")
	h.DeleteSubmit(rr, req)
	if !strings.Contains(rr.Body.String(), "typing the full DN") {
		t.Errorf("confirmation feedback: %s", rr.Body.String())
	}
}

func TestDeleteRecursive(t *testing.T) {
	var deleted []string
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if req.Scope == ldap.ScopeSingleLevel {
				return &ldap.SearchResult{Entries: []*ldap.Entry{{DN: "ou=Child,ou=People,dc=example,dc=com"}}}, nil
			}
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				{DN: "ou=People,dc=example,dc=com"},
				{DN: "ou=Child,ou=People,dc=example,dc=com"},
				{DN: "cn=grand,ou=Child,ou=People,dc=example,dc=com"},
			}}, nil
		},
		deleteFn: func(ctx context.Context, dn string) error {
			deleted = append(deleted, dn)
			return nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{"confirm_dn": {"ou=People,dc=example,dc=com"}, "recursive": {"1"}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/ou=People,dc=example,dc=com/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "ou=People,dc=example,dc=com")
	h.DeleteSubmit(rr, req)
	// Deepest first: grand, child, root.
	if len(deleted) != 3 || deleted[0] != "cn=grand,ou=Child,ou=People,dc=example,dc=com" || deleted[2] != "ou=People,dc=example,dc=com" {
		t.Errorf("delete order = %v", deleted)
	}
}

func TestRenameSuccess(t *testing.T) {
	var gotDN, gotRDN, gotSuperior string
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{}, nil // target parent exists
		},
		modifyDNFn: func(ctx context.Context, dn, newRDN string, deleteOldRDN bool, newSuperior string) error {
			gotDN, gotRDN, gotSuperior = dn, newRDN, newSuperior
			return nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{"new_rdn": {"cn=robert"}, "delete_old_rdn": {"1"}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=bob,ou=People,dc=example,dc=com/rename", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=bob,ou=People,dc=example,dc=com")
	h.RenameSubmit(rr, req)
	if gotDN != "cn=bob,ou=People,dc=example,dc=com" || gotRDN != "cn=robert" || gotSuperior != "" {
		t.Errorf("modrdn = %q %q %q", gotDN, gotRDN, gotSuperior)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "cn=robert,ou=People,dc=example,dc=com") {
		t.Errorf("result must reference the new DN: %s", rr.Body.String())
	}
}

func TestRenameTargetParentMissing(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, &ldapx.LDAPError{Op: "search", Code: 32, DN: "ou=Archive,dc=example,dc=com", Err: errors.New("no such object")}
		},
	}
	h := testHandler(t, fake)
	form := url.Values{"new_rdn": {"cn=robert"}, "new_superior": {"ou=Archive,dc=example,dc=com"}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=bob,dc=example,dc=com/rename", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=bob,dc=example,dc=com")
	h.RenameSubmit(rr, req)
	if !strings.Contains(rr.Body.String(), "Target parent does not exist") {
		t.Errorf("parent-missing feedback: %s", rr.Body.String())
	}
}

func TestTemplateLoader(t *testing.T) {
	loader := fixtureLoader(t)
	if _, err := loader.Load("posixAccount"); err != nil {
		t.Fatalf("load posixAccount: %v", err)
	}
	if _, err := loader.Load("missing"); err == nil {
		t.Error("missing template should error")
	}
	if _, err := loader.Load("../../etc/passwd"); err == nil {
		t.Error("path traversal must be rejected")
	}
}

func TestEscapeRDNValue(t *testing.T) {
	cases := map[string]string{
		"alice":  "alice",
		"a,b":    `a\,b`,
		" lead":  `\ lead`,
		"trail ": "trail\\ ",
		"a+b":    `a\+b`,
		"#hash":  `\#hash`,
	}
	for in, want := range cases {
		if got := escapeRDNValue(in); got != want {
			t.Errorf("escape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildDN(t *testing.T) {
	if got := buildDN("ou=People,dc=example,dc=com", "cn", "alice"); got != "cn=alice,ou=People,dc=example,dc=com" {
		t.Errorf("got %q", got)
	}
	if got := buildDN("", "uid", "jdoe"); got != "uid=jdoe" {
		t.Errorf("got %q", got)
	}
	if got := parentDN("cn=a,ou=b,dc=c"); got != "ou=b,dc=c" {
		t.Errorf("parent = %q", got)
	}
}

func containsAll(vals []string, wants ...string) bool {
	set := map[string]bool{}
	for _, v := range vals {
		set[v] = true
	}
	for _, w := range wants {
		if !set[w] {
			return false
		}
	}
	return true
}
