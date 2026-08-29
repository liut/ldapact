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

// controlSchema builds a subschema covering every control classification,
// usage variant, and a person → organizationalPerson → inetOrgPerson SUP
// chain.
func controlSchema() *ldapx.Schema {
	entry := &ldap.Entry{
		DN: "cn=Subschema",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClasses", Values: []string{
				"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )",
				"( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL MAY ( postalAddress $ l $ st ) )",
				"( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL MAY ( mail $ uid $ userCertificate ) )",
				"( 2.5.6.9 NAME 'groupOfNames' SUP top STRUCTURAL MUST ( cn $ member ) MAY ( owner $ seeAlso $ businessCategory $ o $ ou $ description ) )",
				"( 1.3.6.1.1.1.2.0 NAME 'posixAccount' SUP top AUXILIARY MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory ) MAY ( userPassword $ loginShell $ gecos $ description ) )",
			}},
			{Name: "attributeTypes", Values: []string{
				"( 2.5.4.3 NAME ( 'cn' 'commonName' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
				"( 2.5.4.4 NAME ( 'sn' 'surname' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
				"( 0.9.2342.19200300.100.1.3 NAME ( 'mail' 'rfc822Mailbox' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
				"( 2.5.4.16 NAME 'postalAddress' SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )",
				"( 2.5.4.20 NAME 'telephoneNumber' EQUALITY telephoneNumberMatch SUBSTR telephoneNumberSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )",
				"( 2.5.4.13 NAME 'description' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
				"( 2.5.4.34 NAME 'seeAlso' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
				"( 2.5.4.5 NAME 'booleanAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )",
				"( 2.5.4.49 NAME 'dnAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
				"( 2.5.4.36 NAME 'certificateAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.8 )",
				"( 1.3.6.1.4.1.9999.1.1 NAME 'operationalAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE directoryOperation )",
			}},
		},
	}
	s, err := ldapx.ParseSchema(entry)
	if err != nil {
		panic(err)
	}
	return s
}

// schemaControlsEntry is a plain person (no modification template matches,
// so the generic editor renders) exercising every schema-driven control.
func schemaControlsEntry() *ldap.Entry {
	return &ldap.Entry{
		DN: "cn=carol,ou=People,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"top", "person"}},
			{Name: "cn", Values: []string{"carol"}},
			{Name: "sn", Values: []string{"Davis"}},
			{Name: "booleanAttr", Values: []string{"TRUE"}},
			{Name: "dnAttr", Values: []string{"cn=manager,ou=People,dc=example,dc=com"}},
			{Name: "certificateAttr", Values: []string{"\x00\x01"}},
			{Name: "postalAddress", Values: []string{"123 Main St\nSpringfield"}},
			{Name: "operationalAttr", Values: []string{"hidden"}},
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

func TestDeleteNonLeafBlocked(t *testing.T) {
	var deleted bool
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{{DN: "cn=child,ou=People,dc=example,dc=com"}}}, nil
		},
		deleteFn: func(ctx context.Context, dn string) error {
			deleted = true
			return nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{"confirm_dn": {"ou=People,dc=example,dc=com"}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/ou=People,dc=example,dc=com/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "ou=People,dc=example,dc=com")
	h.DeleteSubmit(rr, req)
	if !strings.Contains(rr.Body.String(), "delete them first") {
		t.Errorf("blocked feedback: %s", rr.Body.String())
	}
	if deleted {
		t.Error("non-leaf entry must not be deleted")
	}
}

func TestDeleteNonLeafRecursiveStillBlocked(t *testing.T) {
	var deleted bool
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{{DN: "ou=Child,ou=People,dc=example,dc=com"}}}, nil
		},
		deleteFn: func(ctx context.Context, dn string) error {
			deleted = true
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
	if !strings.Contains(rr.Body.String(), "delete them first") {
		t.Errorf("blocked feedback: %s", rr.Body.String())
	}
	if deleted {
		t.Error("recursive delete must not bypass the leaf-only rule")
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

func TestDetailPasswordActionGated(t *testing.T) {
	cases := []struct {
		name    string
		entry   *ldap.Entry
		visible bool
	}{
		{"with password", inetOrgPersonEntry(), true},
		{"without password", genericOUEntry(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeClient{
				baseDN: "dc=example,dc=com",
				searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
					return &ldap.SearchResult{Entries: []*ldap.Entry{tc.entry}}, nil
				},
			}
			h := testHandler(t, fake)
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/entry/"+tc.entry.DN, nil)
			req.SetPathValue("dn", tc.entry.DN)
			h.Detail(rr, req)
			body := rr.Body.String()
			if tc.visible && !strings.Contains(body, "Change password") {
				t.Error("detail page with userPassword must show Change password")
			}
			if !tc.visible && strings.Contains(body, "Change password") {
				t.Error("detail page without userPassword must hide Change password")
			}
		})
	}
}

func TestPasswordRouteGated(t *testing.T) {
	var modified bool
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{genericOUEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, changes []ldap.Change) error {
			modified = true
			return nil
		},
	}
	h := testHandler(t, fake)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/ou=People,dc=example,dc=com/password", nil)
	req.SetPathValue("dn", "ou=People,dc=example,dc=com")
	h.PasswordForm(rr, req)
	if !strings.Contains(rr.Body.String(), "no userPassword") {
		t.Errorf("password form must gate: %s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/entry/ou=People,dc=example,dc=com/password",
		strings.NewReader(url.Values{"new_password": {"x"}, "confirm_password": {"x"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "ou=People,dc=example,dc=com")
	h.PasswordChange(rr, req)
	if !strings.Contains(rr.Body.String(), "no userPassword") {
		t.Errorf("password change must gate: %s", rr.Body.String())
	}
	if modified {
		t.Error("password modify must not run for an entry without userPassword")
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

func TestEditFormSchemaControls(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{schemaControlsEntry()}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/cn=carol,ou=People,dc=example,dc=com/edit", nil)
	req.SetPathValue("dn", "cn=carol,ou=People,dc=example,dc=com")
	h.EditForm(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()

	// Boolean syntax → TRUE/FALSE select with the current value selected.
	for _, want := range []string{`name="booleanAttr"`, `value="TRUE" selected`, `value="FALSE"`} {
		if !strings.Contains(body, want) {
			t.Errorf("boolean control missing %q", want)
		}
	}
	// DN syntax → text input with a DN hint wired via aria-describedby.
	for _, want := range []string{`name="dnAttr"`, `aria-describedby="hint-dnAttr"`, "Distinguished Name"} {
		if !strings.Contains(body, want) {
			t.Errorf("DN control missing %q", want)
		}
	}
	// Binary syntax → read-only placeholder.
	for _, want := range []string{`name="certificateAttr"`, `value="[binary]"`, "readonly"} {
		if !strings.Contains(body, want) {
			t.Errorf("binary control missing %q", want)
		}
	}
	// Postal Address → textarea with the current value.
	for _, want := range []string{`name="postalAddress"`, "<textarea", "123 Main St"} {
		if !strings.Contains(body, want) {
			t.Errorf("textarea control missing %q", want)
		}
	}
	// Schema USAGE excludes operational attributes.
	if strings.Contains(body, "operationalAttr") {
		t.Error("operational attribute must not render in the generic editor")
	}
	// MUST (sn via person) renders the informational required marker.
	if !strings.Contains(body, `for="f-sn">sn <span class="schema-required">Required (schema)</span>`) {
		t.Error("sn must carry the schema-required marker")
	}
}

func TestEditFormTemplateRequiredMarkers(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{inetOrgPersonEntry()}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/cn=alice,ou=People,dc=example,dc=com/edit", nil)
	req.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.EditForm(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, `for="f-sn">Last name <span class="schema-required">Required (schema)</span>`) {
		t.Error("template form must mark sn required by schema (person MUST via SUP)")
	}
	if !strings.Contains(body, `for="f-mail">Email</label>`) {
		t.Error("mail (MAY) must not carry the schema-required marker")
	}
	// Template-declared textarea on a string attribute is preserved.
	if !strings.Contains(body, `name="street"`) || !strings.Contains(body, "<textarea") {
		t.Error("template type=textarea must survive schema classification")
	}
}

func TestEditFormBooleanLowercase(t *testing.T) {
	entry := schemaControlsEntry()
	for _, a := range entry.Attributes {
		if a.Name == "booleanAttr" {
			a.Values = []string{"true"}
		}
	}
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/cn=carol,ou=People,dc=example,dc=com/edit", nil)
	req.SetPathValue("dn", "cn=carol,ou=People,dc=example,dc=com")
	h.EditForm(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `value="TRUE" selected`) {
		t.Error("lowercase boolean value must select the TRUE option")
	}
}

func TestEditFormBooleanUnchangedSubmit(t *testing.T) {
	modified := false
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{schemaControlsEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, changes []ldap.Change) error {
			modified = true
			return nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{
		"booleanAttr":   {"TRUE"},
		"dnAttr":        {"cn=manager,ou=People,dc=example,dc=com"},
		"postalAddress": {"123 Main St\nSpringfield"},
		"sn":            {"Davis"},
		"stage":         {"apply"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=carol,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=carol,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "No changes") {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
	if modified {
		t.Error("unchanged boolean submit must not call Modify")
	}
}

func TestBooleanOptions(t *testing.T) {
	opts := booleanOptions(false, nil)
	if len(opts) != 3 || opts[0].ID != "" || opts[0].Display != "(not set)" ||
		opts[1].ID != "TRUE" || opts[2].ID != "FALSE" {
		t.Errorf("booleanOptions(MAY, empty) = %+v", opts)
	}
	requiredSet := booleanOptions(true, []string{"TRUE"})
	if len(requiredSet) != 2 || requiredSet[0].ID != "TRUE" {
		t.Errorf("booleanOptions(MUST, set) must have no (not set): %+v", requiredSet)
	}
	requiredEmpty := booleanOptions(true, nil)
	if len(requiredEmpty) != 3 || requiredEmpty[0].ID != "" {
		t.Errorf("booleanOptions(MUST, empty) must include (not set): %+v", requiredEmpty)
	}
}

func TestEditMultiValueRemoveAllDeletes(t *testing.T) {
	var got []ldap.Change
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{posixGroupEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, changes []ldap.Change) error {
			got = changes
			return nil
		},
	}
	h := testHandler(t, fake)
	// The user removed every memberUid row: the field is absent from POST.
	form := url.Values{
		"gidNumber": {"100"},
		"cn":        {"staff"},
		"stage":     {"apply"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=staff,ou=Groups,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=staff,ou=Groups,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
	if len(got) != 1 || got[0].Operation != uint(ldap.DeleteAttribute) ||
		got[0].Modification.Type != "memberUid" {
		t.Fatalf("remove-all must delete memberUid, got %+v", got)
	}
}

func TestEditBooleanClear(t *testing.T) {
	var got []ldap.Change
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{schemaControlsEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, changes []ldap.Change) error {
			got = changes
			return nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{
		"booleanAttr":   {""}, // "(not set)" selected
		"dnAttr":        {"cn=manager,ou=People,dc=example,dc=com"},
		"postalAddress": {"123 Main St\nSpringfield"},
		"sn":            {"Davis"},
		"stage":         {"apply"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=carol,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=carol,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
	if len(got) != 1 || got[0].Operation != uint(ldap.DeleteAttribute) ||
		got[0].Modification.Type != "booleanAttr" {
		t.Fatalf("clearing boolean must delete it, got %+v", got)
	}
}

func TestEditSingleValueClear(t *testing.T) {
	var got []ldap.Change
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{inetOrgPersonEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, changes []ldap.Change) error {
			got = changes
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
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
	found := false
	for _, c := range got {
		if c.Modification.Type == "mail" && c.Operation == uint(ldap.DeleteAttribute) {
			found = true
		}
	}
	if !found {
		t.Fatalf("clearing mail must delete it, got %+v", got)
	}
}

func TestEditMultiValueEmptyRowNoFabrication(t *testing.T) {
	entry := posixGroupEntry()
	entry.Attributes = []*ldap.EntryAttribute{
		{Name: "objectClass", Values: []string{"top", "posixGroup"}},
		{Name: "cn", Values: []string{"staff"}},
		{Name: "gidNumber", Values: []string{"100"}},
	}
	var modified bool
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, changes []ldap.Change) error {
			modified = true
			return nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{
		"memberUid": {""}, // empty row's "(not set)" default
		"gidNumber": {"100"},
		"cn":        {"staff"},
		"stage":     {"apply"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=staff,ou=Groups,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=staff,ou=Groups,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "No changes") {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
	if modified {
		t.Error("untouched empty select row must not fabricate a value")
	}
}

func TestMergeOptionsNotSet(t *testing.T) {
	opts := mergeOptions(nil, []tplengine.Value{{ID: "a", Display: "A"}, {ID: "b", Display: "B"}}, false)
	if len(opts) != 3 || opts[0].ID != "" || opts[0].Display != "(not set)" {
		t.Errorf("mergeOptions(nil, ...) = %+v", opts)
	}
	withValue := mergeOptions([]string{"b"}, []tplengine.Value{{ID: "a", Display: "A"}, {ID: "b", Display: "B"}}, false)
	if len(withValue) != 3 || withValue[0].ID != "" || withValue[1].ID != "b" {
		t.Errorf("mergeOptions([b], ...) = %+v", withValue)
	}
	requiredSet := mergeOptions([]string{"b"}, []tplengine.Value{{ID: "a", Display: "A"}, {ID: "b", Display: "B"}}, true)
	if len(requiredSet) != 2 || requiredSet[0].ID != "b" {
		t.Errorf("mergeOptions(MUST, set) must have no (not set): %+v", requiredSet)
	}
}

func TestEditFormAddCandidates(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{schemaControlsEntry()}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/cn=carol,ou=People,dc=example,dc=com/edit", nil)
	req.SetPathValue("dn", "cn=carol,ou=People,dc=example,dc=com")
	h.EditForm(rr, req)
	body := rr.Body.String()
	for _, want := range []string{`name="add_attr"`, `value="telephoneNumber"`, `value="description"`, `value="seeAlso"`} {
		if !strings.Contains(body, want) {
			t.Errorf("add-attribute candidates missing %q", want)
		}
	}
	for _, not := range []string{`value="sn"`, `value="userPassword"`, `value="operationalAttr"`} {
		if strings.Contains(body, not) {
			t.Errorf("add-attribute candidates must not contain %q", not)
		}
	}
}

func TestEditAddAttribute(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{schemaControlsEntry()}}, nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{
		"booleanAttr":   {"TRUE"},
		"dnAttr":        {"cn=manager,ou=People,dc=example,dc=com"},
		"postalAddress": {"123 Main St\nSpringfield"},
		"sn":            {"Davis"},
		"add_attr":      {"telephoneNumber"},
		"stage":         {"review"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=carol,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=carol,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `name="telephoneNumber"`) {
		t.Fatalf("add_attr must re-render with the new field: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "Apply changes") {
		t.Error("adding an attribute must not proceed to review")
	}
}

func TestEditAddAttributeApply(t *testing.T) {
	var got []ldap.Change
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{schemaControlsEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, changes []ldap.Change) error {
			got = changes
			return nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{
		"booleanAttr":     {"TRUE"},
		"dnAttr":          {"cn=manager,ou=People,dc=example,dc=com"},
		"postalAddress":   {"123 Main St\nSpringfield"},
		"sn":              {"Davis"},
		"telephoneNumber": {"+1 555 0100"},
		"stage":           {"apply"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=carol,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=carol,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
	found := false
	for _, c := range got {
		if c.Modification.Type == "telephoneNumber" && c.Operation == uint(ldap.ReplaceAttribute) &&
			len(c.Modification.Vals) == 1 && c.Modification.Vals[0] == "+1 555 0100" {
			found = true
		}
	}
	if !found {
		t.Fatalf("added attribute must be created via Replace, got %+v", got)
	}
}

func TestEditAddAttributeInvalid(t *testing.T) {
	var modified bool
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{schemaControlsEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, changes []ldap.Change) error {
			modified = true
			return nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{
		"booleanAttr":   {"TRUE"},
		"dnAttr":        {"cn=manager,ou=People,dc=example,dc=com"},
		"postalAddress": {"123 Main St\nSpringfield"},
		"sn":            {"Davis"},
		"add_attr":      {"operationalAttr"},
		"stage":         {"review"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=carol,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=carol,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if !strings.Contains(rr.Body.String(), "Cannot add attribute") || strings.Contains(rr.Body.String(), `name="operationalAttr"`) {
		t.Errorf("invalid add_attr must be rejected: %s", rr.Body.String())
	}
	if modified {
		t.Error("invalid add must not call Modify")
	}
}

func TestEditDeleteAttributeButton(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{schemaControlsEntry()}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/cn=carol,ou=People,dc=example,dc=com/edit", nil)
	req.SetPathValue("dn", "cn=carol,ou=People,dc=example,dc=com")
	h.EditForm(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, `class="delete-attr" data-name="postalAddress"`) {
		t.Error("MAY attribute must render a Delete attribute button")
	}
	if strings.Contains(body, `class="delete-attr" data-name="sn"`) {
		t.Error("MUST attribute must not render a Delete attribute button")
	}
}

func posixAccountEntry() *ldap.Entry {
	return &ldap.Entry{
		DN: "uid=carol,ou=People,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"top", "person", "posixAccount"}},
			{Name: "cn", Values: []string{"carol"}},
			{Name: "sn", Values: []string{"Davis"}},
			{Name: "uidNumber", Values: []string{"2001"}},
			{Name: "uid", Values: []string{"carol"}},
			{Name: "gidNumber", Values: []string{"100"}},
			{Name: "homeDirectory", Values: []string{"/home/carol"}},
		},
	}
}

func TestEditFormObjectClassSection(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{schemaControlsEntry()}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/cn=carol,ou=People,dc=example,dc=com/edit", nil)
	req.SetPathValue("dn", "cn=carol,ou=People,dc=example,dc=com")
	h.EditForm(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, `name="add_oc"`) || !strings.Contains(body, `value="posixAccount"`) {
		t.Error("auxiliary add picker must list posixAccount")
	}
	if strings.Contains(body, `name="remove_oc"`) {
		t.Error("no auxiliary class should be removable on a plain person entry")
	}
}

func TestEditObjectClassRemoveBlockedByValues(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{posixAccountEntry()}}, nil
		},
	}
	h := testHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/entry/uid=carol,ou=People,dc=example,dc=com/edit", nil)
	req.SetPathValue("dn", "uid=carol,ou=People,dc=example,dc=com")
	h.EditForm(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, `oc-name">posixAccount`) {
		t.Error("posixAccount must appear in the object class list")
	}
	if strings.Contains(body, `name="remove_oc" value="posixAccount"`) {
		t.Error("posixAccount with own values must not be removable")
	}
}

func TestEditObjectClassAdd(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{schemaControlsEntry()}}, nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{
		"booleanAttr":   {"TRUE"},
		"dnAttr":        {"cn=manager,ou=People,dc=example,dc=com"},
		"postalAddress": {"123 Main St\nSpringfield"},
		"sn":            {"Davis"},
		"objectClass":   {"top", "person"},
		"add_oc":        {"posixAccount"},
		"stage":         {"review"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=carol,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=carol,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `oc-name">posixAccount`) {
		t.Fatalf("add_oc must re-render with posixAccount listed: %d %s", rr.Code, rr.Body.String())
	}
}

func TestEditObjectClassAddStructuralRejected(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{schemaControlsEntry()}}, nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{
		"booleanAttr":   {"TRUE"},
		"dnAttr":        {"cn=manager,ou=People,dc=example,dc=com"},
		"postalAddress": {"123 Main St\nSpringfield"},
		"sn":            {"Davis"},
		"objectClass":   {"top", "person"},
		"add_oc":        {"inetOrgPerson"},
		"stage":         {"review"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=carol,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=carol,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if !strings.Contains(rr.Body.String(), "AUXILIARY classes can be added") {
		t.Errorf("structural add must be rejected: %s", rr.Body.String())
	}
}

func TestEditObjectClassRemove(t *testing.T) {
	entry := posixAccountEntry()
	// Strip the own-only values so posixAccount becomes removable.
	entry.Attributes = []*ldap.EntryAttribute{
		{Name: "objectClass", Values: []string{"top", "person", "posixAccount"}},
		{Name: "cn", Values: []string{"carol"}},
		{Name: "sn", Values: []string{"Davis"}},
	}
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{
		"cn":          {"carol"},
		"sn":          {"Davis"},
		"objectClass": {"top", "person", "posixAccount"},
		"remove_oc":   {"posixAccount"},
		"stage":       {"review"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/uid=carol,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "uid=carol,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	body := rr.Body.String()
	if strings.Contains(body, `oc-name">posixAccount`) ||
		strings.Contains(body, "cannot be removed — its attributes") {
		t.Errorf("value-less posixAccount must be removable: %s", body)
	}
}

func TestEditObjectClassRemoveWithValuesRejected(t *testing.T) {
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{posixAccountEntry()}}, nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{
		"cn":            {"carol"},
		"sn":            {"Davis"},
		"uid":           {"carol"},
		"uidNumber":     {"2001"},
		"gidNumber":     {"100"},
		"homeDirectory": {"/home/carol"},
		"objectClass":   {"top", "person", "posixAccount"},
		"remove_oc":     {"posixAccount"},
		"stage":         {"review"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/uid=carol,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "uid=carol,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if !strings.Contains(rr.Body.String(), "cannot be removed — its attributes") {
		t.Errorf("posixAccount with own values must be blocked: %s", rr.Body.String())
	}
}

func TestEditObjectClassApply(t *testing.T) {
	var got []ldap.Change
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{schemaControlsEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, changes []ldap.Change) error {
			got = changes
			return nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{
		"booleanAttr":   {"TRUE"},
		"dnAttr":        {"cn=manager,ou=People,dc=example,dc=com"},
		"postalAddress": {"123 Main St\nSpringfield"},
		"sn":            {"Davis"},
		"objectClass":   {"top", "person", "posixAccount"},
		"stage":         {"apply"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=carol,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=carol,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
	gotSet := map[string]bool{}
	for _, c := range got {
		if c.Modification.Type == "objectClass" && c.Operation == uint(ldap.ReplaceAttribute) {
			for _, v := range cleanValues(c.Modification.Vals) {
				gotSet[v] = true
			}
		}
	}
	if !gotSet["top"] || !gotSet["person"] || !gotSet["posixAccount"] || len(gotSet) != 3 {
		t.Fatalf("objectClass change must apply via Replace, got %+v", got)
	}
}

func TestEditObjectClassApplyStructuralRemovalRejected(t *testing.T) {
	var modified bool
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{schemaControlsEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, changes []ldap.Change) error {
			modified = true
			return nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{
		"booleanAttr":   {"TRUE"},
		"dnAttr":        {"cn=manager,ou=People,dc=example,dc=com"},
		"postalAddress": {"123 Main St\nSpringfield"},
		"sn":            {"Davis"},
		"objectClass":   {"top"}, // person (STRUCTURAL) removed
		"stage":         {"apply"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=carol,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=carol,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if !strings.Contains(rr.Body.String(), "cannot be removed") {
		t.Errorf("structural removal must be rejected: %s", rr.Body.String())
	}
	if modified {
		t.Error("structural removal must not call Modify")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestEditRequiredClearRejected(t *testing.T) {
	var modified bool
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{schemaControlsEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, changes []ldap.Change) error {
			modified = true
			return nil
		},
	}
	h := testHandler(t, fake)
	form := url.Values{
		"sn":    {""}, // sn is person MUST
		"stage": {"apply"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=carol,ou=People,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=carol,ou=People,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "required by schema and cannot be cleared") {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
	if modified {
		t.Error("clearing a MUST attribute must not call Modify")
	}
}

func groupOfNamesEntry() *ldap.Entry {
	return &ldap.Entry{
		DN: "cn=team,ou=Groups,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"top", "groupOfNames"}},
			{Name: "cn", Values: []string{"team"}},
			{Name: "member", Values: []string{"cn=alice,ou=People,dc=example,dc=com", "cn=bob,ou=People,dc=example,dc=com"}},
		},
	}
}

func TestEditRequiredMultiRemoveAllRejected(t *testing.T) {
	var modified bool
	fake := &fakeClient{
		baseDN: "dc=example,dc=com",
		schema: controlSchema(),
		searchFn: func(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{groupOfNamesEntry()}}, nil
		},
		modifyFn: func(ctx context.Context, dn string, changes []ldap.Change) error {
			modified = true
			return nil
		},
	}
	h := testHandler(t, fake)
	// Remove every member row: the field is absent from the POST.
	form := url.Values{
		"cn":    {"team"},
		"stage": {"apply"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/entry/cn=team,ou=Groups,dc=example,dc=com/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("dn", "cn=team,ou=Groups,dc=example,dc=com")
	h.EditSubmit(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "required by schema and cannot be cleared") {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
	if modified {
		t.Error("removing all members of a MUST multi-value attribute must not call Modify")
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
