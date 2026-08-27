package entry

import (
	"bytes"
	"context"
	"encoding/base64"
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
	fsys := fstest.MapFS{}
	loadDir := func(dir, prefix string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			fsys[prefix+e.Name()] = &fstest.MapFile{Data: b}
		}
	}
	loadDir(filepath.Join("..", "tplengine", "fixtures"), "creation/")
	loadDir(filepath.Join("..", "..", "templates", "modification"), "modification/")
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

func inetOrgPersonEntry() *ldap.Entry {
	return &ldap.Entry{
		DN: "cn=alice,ou=People,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"top", "person", "inetOrgPerson"}},
			{Name: "cn", Values: []string{"alice"}},
			{Name: "sn", Values: []string{"Smith"}},
			{Name: "givenName", Values: []string{"Alice"}},
			{Name: "uid", Values: []string{"alice"}},
			{Name: "mail", Values: []string{"alice@example.com"}},
			{Name: "userPassword", Values: []string{"{SSHA512}hash"}},
		},
	}
}

func posixGroupEntry() *ldap.Entry {
	return &ldap.Entry{
		DN: "cn=staff,ou=Groups,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"top", "posixGroup"}},
			{Name: "cn", Values: []string{"staff"}},
			{Name: "gidNumber", Values: []string{"100"}},
			{Name: "memberUid", Values: []string{"alice", "bob"}},
		},
	}
}

func genericOUEntry() *ldap.Entry {
	return &ldap.Entry{
		DN: "ou=People,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"top", "organizationalUnit"}},
			{Name: "ou", Values: []string{"People"}},
			{Name: "description", Values: []string{"People here"}},
		},
	}
}

func testHandlerWithLogger(t *testing.T, client EntryClient, buf *bytes.Buffer) *Handler {
	t.Helper()
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	renderer := web.New(web.MustParse(nil))
	loader := fixtureLoader(t)
	return New(client, renderer, logger, loader, nil, nil)
}

func testHandlerWithLoader(t *testing.T, client EntryClient, loader *TemplateLoader) *Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	renderer := web.New(web.MustParse(nil))
	return New(client, renderer, logger, loader, nil, nil)
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

func TestEditFormInetOrgPerson(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{inetOrgPersonEntry()}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/cn=alice,ou=People,dc=example,dc=com/edit", nil)
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.EditForm(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		"Edit entry",
		"Generic: Address Book Entry",
		`name="givenName"`,
		`value="Alice"`,
		`name="sn"`,
		`value="Smith"`,
		`name="mail"`,
		`value="alice@example.com"`,
		"Review changes",
		`name="stage" value="review"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("edit form missing %q", want)
		}
	}
	if !strings.Contains(body, `name="cn"`) || !strings.Contains(body, "readonly") {
		t.Error("RDN attribute cn must render read-only")
	}
	if !strings.Contains(body, "[redacted]") || !strings.Contains(body, "/password") {
		t.Error("userPassword must render [redacted] with an F3 link")
	}
	if strings.Contains(body, "{SSHA512}hash") {
		t.Error("edit form must not echo the userPassword value")
	}
}

func TestEditFormPosixGroupMultiValue(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{posixGroupEntry()}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/cn=staff,ou=Groups,dc=example,dc=com/edit", nil)
	req.SetPathValue("dn", "cn=staff,ou=Groups,dc=example,dc=com")
	h.EditForm(rr, req)
	body := rr.Body.String()
	for _, want := range []string{"Generic: Posix Group", `value="alice"`, `value="bob"`, `name="memberUid"`, "add-row"} {
		if !strings.Contains(body, want) {
			t.Errorf("posixGroup edit form missing %q", want)
		}
	}
	if !strings.Contains(body, `name="gidNumber"`) || !strings.Contains(body, "readonly") {
		t.Error("gidNumber must render read-only per the template")
	}
	if strings.Count(body, `name="memberUid"`) < 2 {
		t.Error("memberUid must render one input per existing member")
	}
}

func TestEditFormGenericFallback(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{genericOUEntry()}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/ou=People,dc=example,dc=com/edit", nil)
	req.SetPathValue("dn", "ou=People,dc=example,dc=com")
	h.EditForm(rr, req)
	body := rr.Body.String()
	for _, want := range []string{"the generic editor", `name="description"`, `value="People here"`} {
		if !strings.Contains(body, want) {
			t.Errorf("generic edit form missing %q", want)
		}
	}
	if strings.Contains(body, `name="ou"`) {
		t.Error("RDN attribute must not be editable in the generic editor")
	}
}

func TestEditFormForcedTemplate(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{inetOrgPersonEntry()}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/cn=alice,ou=People,dc=example,dc=com/edit?template=posixGroup", nil)
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.EditForm(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, "Generic: Posix Group") || !strings.Contains(body, `name="memberUid"`) {
		t.Errorf("forced template not honored: %.300s", body)
	}
}

func TestEditFormNotFound(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, &ldapx.LDAPError{Op: "search", Code: 32, DN: "cn=missing,dc=example,dc=com", Err: errors.New("no such object")}
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/cn=missing,dc=example,dc=com/edit", nil)
	req.SetPathValue("dn", "cn=missing,dc=example,dc=com")
	h.EditForm(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", rr.Code)
	}
}

func TestEditFormTemplateParseFailure(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{inetOrgPersonEntry()}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/cn=alice,ou=People,dc=example,dc=com/edit?template=missing", nil)
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.EditForm(rr, req)
	if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "missing") {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
}

func editFormValues() url.Values {
	return url.Values{
		"givenName":                {"Alice"},
		"sn":                       {"Smith"},
		"cn":                       {"alice"},
		"jpegPhoto":                {""},
		"o":                        {""},
		"street":                   {""},
		"l":                        {""},
		"st":                       {""},
		"postalCode":               {""},
		"telephoneNumber":          {""},
		"facsimileTelephoneNumber": {""},
		"mobile":                   {""},
		"mail":                     {"alice@example.com"},
	}
}

func TestEditReviewAndApply(t *testing.T) {
	var modifiedDN string
	var changes []ldap.Change
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{inetOrgPersonEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, ch []ldap.Change) error {
			modifiedDN = dn
			changes = ch
			return nil
		},
	}
	h := testHandler(t, fake)

	form := editFormValues()
	form.Set("telephoneNumber", "+1 555 0100")
	form.Set("mail", "alice@new.example.com")
	form.Set("stage", "review")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=alice,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("review code = %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{"Review changes", "alice@example.com", "alice@new.example.com", "1 555 0100"} {
		if !strings.Contains(body, want) {
			t.Errorf("review page missing %q", want)
		}
	}
	if modifiedDN != "" {
		t.Error("review must not call Modify")
	}

	form.Set("stage", "apply")
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/entry/cn=alice,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("apply code = %d: %s", rr.Code, rr.Body.String())
	}
	if modifiedDN != "cn=alice,ou=People,dc=example,dc=com" {
		t.Errorf("modified DN = %q", modifiedDN)
	}
	if len(changes) != 2 {
		t.Fatalf("changes = %+v", changes)
	}
	byType := map[string]ldap.Change{}
	for _, c := range changes {
		byType[c.Modification.Type] = c
	}
	if c := byType["mail"]; c.Operation != uint(ldap.ReplaceAttribute) || len(c.Modification.Vals) != 1 || c.Modification.Vals[0] != "alice@new.example.com" {
		t.Errorf("mail change = %+v", c)
	}
	if c := byType["telephoneNumber"]; c.Operation != uint(ldap.ReplaceAttribute) || len(c.Modification.Vals) != 1 || c.Modification.Vals[0] != "+1 555 0100" {
		t.Errorf("telephoneNumber change = %+v", c)
	}
	if got := rr.Header().Get("X-Mutated-Subtree"); got != "ou=People,dc=example,dc=com" {
		t.Errorf("X-Mutated-Subtree = %q", got)
	}
	if !strings.Contains(rr.Body.String(), "Entry updated") {
		t.Errorf("result page: %s", rr.Body.String())
	}
}

func TestEditClearAttribute(t *testing.T) {
	var changes []ldap.Change
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{inetOrgPersonEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, ch []ldap.Change) error {
			changes = ch
			return nil
		},
	}
	h := testHandler(t, fake)
	form := editFormValues()
	form.Set("mail", "")
	form.Set("stage", "apply")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=alice,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if len(changes) != 1 || changes[0].Operation != uint(ldap.DeleteAttribute) || changes[0].Modification.Type != "mail" {
		t.Fatalf("cleared attribute change = %+v", changes)
	}
}

func TestEditNoChangesShortCircuit(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{inetOrgPersonEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, ch []ldap.Change) error {
			t.Error("Modify must not be called on an unchanged submit")
			return nil
		},
	}
	h := testHandler(t, fake)
	form := editFormValues()
	form.Set("stage", "apply")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=alice,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if !strings.Contains(rr.Body.String(), "No changes") {
		t.Errorf("no-changes result: %s", rr.Body.String())
	}
}

func TestEditMultiValueReplace(t *testing.T) {
	var changes []ldap.Change
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{posixGroupEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, ch []ldap.Change) error {
			changes = ch
			return nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{
		"cn":        {"staff"},
		"gidNumber": {"100"},
		"memberUid": {"alice", "bob", "carol"},
		"stage":     {"apply"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=staff,ou=Groups,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=staff,ou=Groups,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if len(changes) != 1 || changes[0].Modification.Type != "memberUid" {
		t.Fatalf("changes = %+v", changes)
	}
	if !containsAll(changes[0].Modification.Vals, "alice", "bob", "carol") || len(changes[0].Modification.Vals) != 3 {
		t.Errorf("memberUid vals = %v", changes[0].Modification.Vals)
	}
}

func TestEditMultiValueDedupesSubmitted(t *testing.T) {
	var changes []ldap.Change
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{posixGroupEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, ch []ldap.Change) error {
			changes = ch
			return nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{
		"cn":        {"staff"},
		"gidNumber": {"100"},
		"memberUid": {"alice", "alice", "bob"},
		"stage":     {"apply"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=staff,ou=Groups,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=staff,ou=Groups,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if len(changes) != 0 {
		t.Fatalf("duplicate submitted values must dedupe to the current set and short-circuit: %+v", changes)
	}
	if !strings.Contains(rr.Body.String(), "No changes") {
		t.Errorf("deduped no-op must render the no-changes result: %s", rr.Body.String())
	}
}

func TestPhotoBytes(t *testing.T) {
	jpeg := []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46}
	if raw, mime, ok := photoBytes(string(jpeg)); !ok || mime != "image/jpeg" || !bytes.Equal(raw, jpeg) {
		t.Errorf("raw jpeg photoBytes = %q %q %v", raw, mime, ok)
	}
	if raw, mime, ok := photoBytes(base64.StdEncoding.EncodeToString(jpeg)); !ok || mime != "image/jpeg" || !bytes.Equal(raw, jpeg) {
		t.Errorf("base64 jpeg photoBytes = %q %q %v", raw, mime, ok)
	}
	png := append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, 0x00)
	if _, mime, ok := photoBytes(string(png)); !ok || mime != "image/png" {
		t.Errorf("png photoBytes mime = %q %v", mime, ok)
	}
	if _, _, ok := photoBytes("not-an-image"); ok {
		t.Error("non-image must not resolve")
	}
}

func TestImageURL(t *testing.T) {
	for _, ok := range []string{
		"https://example.com/a.png", "http://x/a.png",
		"/avatars/a.jpg", "./a.png", "data:image/png;base64,AAA",
	} {
		if !imageURL(ok) {
			t.Errorf("imageURL(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "avatars/a.jpg", "https://a b.com/x", "not a url", "ftp://x/y"} {
		if imageURL(bad) {
			t.Errorf("imageURL(%q) = true, want false", bad)
		}
	}
}

func TestDetailRendersPhotos(t *testing.T) {
	jpeg := []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10}
	entry := inetOrgPersonEntry()
	entry.Attributes = append(entry.Attributes,
		&ldap.EntryAttribute{Name: "jpegPhoto", Values: []string{string(jpeg)}},
		&ldap.EntryAttribute{Name: "avatarPath", Values: []string{"https://example.com/alice.png"}},
	)
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/cn=alice,ou=People,dc=example,dc=com", nil)
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.Detail(rr, req)
	body := rr.Body.String()
	for _, want := range []string{
		`src="/api/entry/`,
		`/photo?idx=0"`,
		`<img class="media-preview" src="https://example.com/alice.png"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("detail photo rendering missing %q", want)
		}
	}
}

func TestEditFormPhotoPreviews(t *testing.T) {
	jpeg := []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10}
	entry := genericOUEntry()
	entry.Attributes = append(entry.Attributes,
		&ldap.EntryAttribute{Name: "jpegPhoto", Values: []string{string(jpeg)}},
		&ldap.EntryAttribute{Name: "avatarPath", Values: []string{"https://example.com/alice.png"}},
	)
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/ou=People,dc=example,dc=com/edit", nil)
	req.SetPathValue("dn", "ou=People,dc=example,dc=com")
	h.EditForm(rr, req)
	body := rr.Body.String()
	for _, want := range []string{
		`src="/api/entry/`,
		`/photo?idx=0"`,
		"[photo]",
		`src="https://example.com/alice.png"`,
		`name="avatarPath"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("edit photo previews missing %q", want)
		}
	}
}

func TestPhotoEndpoint(t *testing.T) {
	jpeg := []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x01, 0x02, 0x03}
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{{
				DN: "cn=alice,ou=People,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{{
					Name: "jpegPhoto", Values: []string{base64.StdEncoding.EncodeToString(jpeg)},
				}},
			}}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/cn=alice,ou=People,dc=example,dc=com/photo?idx=0", nil)
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.Photo(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("photo code = %d: %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "image/jpeg" {
		t.Errorf("content-type = %q", ct)
	}
	if !bytes.Equal(rr.Body.Bytes(), jpeg) {
		t.Errorf("photo body = %x", rr.Body.Bytes())
	}
}

func TestPhotoEndpointNotFound(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{{
				DN: "cn=alice,ou=People,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{{
					Name: "jpegPhoto", Values: []string{"not-an-image"},
				}},
			}}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/cn=alice,ou=People,dc=example,dc=com/photo", nil)
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.Photo(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("photo code = %d, want 404", rr.Code)
	}
}

func TestEditLDAPFailureRerenders(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{inetOrgPersonEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, ch []ldap.Change) error {
			return &ldapx.LDAPError{Op: "modify", Code: 19, DN: dn, Err: errors.New("constraint violation")}
		},
	}
	h := testHandler(t, fake)
	form := editFormValues()
	form.Set("mail", "alice@new.example.com")
	form.Set("stage", "apply")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=alice,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	body := rr.Body.String()
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rr.Code, body)
	}
	if !strings.Contains(body, "constraint violation") || !strings.Contains(body, `role="alert"`) {
		t.Errorf("inline error missing: %.300s", body)
	}
	if !strings.Contains(body, `value="alice@new.example.com"`) {
		t.Error("submitted values must be preserved on failure")
	}
}

func TestEditAuditShape(t *testing.T) {
	var buf bytes.Buffer
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{inetOrgPersonEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, ch []ldap.Change) error {
			return nil
		},
	}
	h := testHandlerWithLogger(t, fake, &buf)
	form := editFormValues()
	form.Set("mail", "alice@new.example.com")
	form.Set("stage", "apply")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=alice,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	logs := buf.String()
	for _, want := range []string{`"event":"ldap.modify"`, `"dn":"cn=alice,ou=People,dc=example,dc=com"`, `"op_type":"modify"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("audit line missing %q: %s", want, logs)
		}
	}
	if strings.Contains(logs, "NewPass") || strings.Contains(logs, "{SSHA512}") {
		t.Error("audit must never contain password material")
	}
}

func TestDetailShowsEditLink(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{inetOrgPersonEntry()}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/cn=alice,ou=People,dc=example,dc=com", nil)
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.Detail(rr, req)
	body := rr.Body.String()
	for _, want := range []string{"Edit attributes", "Generic: Address Book Entry", "/edit", "[redacted]", "/password"} {
		if !strings.Contains(body, want) {
			t.Errorf("detail missing %q", want)
		}
	}
}

func TestDetailGenericEditorLabel(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{genericOUEntry()}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/ou=People,dc=example,dc=com", nil)
	req.SetPathValue("dn", "ou=People,dc=example,dc=com")
	h.Detail(rr, req)
	if !strings.Contains(rr.Body.String(), "Edit attributes — generic editor") {
		t.Errorf("generic editor label missing: %.300s", rr.Body.String())
	}
}

func TestEditTemplateExcludesPasswordAndBinary(t *testing.T) {
	customXML := `<?xml version="1.0" encoding="UTF-8"?>
<template><title>Custom</title><rdn>cn</rdn>
<objectClasses><objectClass id="inetOrgPerson"></objectClass></objectClasses>
<attributes>
<attribute id="userPassword"><display>Password</display></attribute>
<attribute id="jpegPhoto"><display>Photo</display></attribute>
<attribute id="mail"><display>Email</display></attribute>
</attributes></template>`
	loader := NewTemplateLoader(fstest.MapFS{
		"modification/custom.xml": &fstest.MapFile{Data: []byte(customXML)},
	}, "")
	entry := inetOrgPersonEntry()
	entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{
		Name: "jpegPhoto", Values: []string{string([]byte{0xff, 0xfe, 0x01})},
	})
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
		},
	}
	h := testHandlerWithLoader(t, fake, loader)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/cn=alice,ou=People,dc=example,dc=com/edit?template=custom", nil)
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.EditForm(rr, req)
	body := rr.Body.String()
	if strings.Contains(body, `name="userPassword"`) {
		t.Error("template-declared userPassword must not render as an editable field")
	}
	if !strings.Contains(body, "[redacted]") {
		t.Error("userPassword row must render [redacted]")
	}
	if !strings.Contains(body, `name="jpegPhoto"`) || !strings.Contains(body, "[binary]") || !strings.Contains(body, "readonly") {
		t.Errorf("binary template value must render read-only [binary]: %.400s", body)
	}
}

func TestEditForcedTemplateRoundTrip(t *testing.T) {
	var changes []ldap.Change
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{inetOrgPersonEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, ch []ldap.Change) error {
			changes = ch
			return nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{
		"template":  {"posixGroup"},
		"cn":        {"staff"},
		"gidNumber": {"100"},
		"memberUid": {"alice", "bob", "carol"},
		"stage":     {"review"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=alice,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if !strings.Contains(rr.Body.String(), "memberUid") {
		t.Fatalf("review must use the forced template fields: %.300s", rr.Body.String())
	}
	form.Set("stage", "apply")
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/entry/cn=alice,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if len(changes) != 1 || changes[0].Modification.Type != "memberUid" || !containsAll(changes[0].Modification.Vals, "alice", "bob", "carol") {
		t.Fatalf("apply must keep the forced template and its changes: %+v", changes)
	}
}
