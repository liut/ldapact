package ldapx

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// pagingFake serves three pages of two entries each, keyed by cookie.
type pagingFake struct {
	fakeConn
	pageSize uint32
}

func (f *pagingFake) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.fakeConn.searchCalls.Add(1)
	ctrlAny := ldap.FindControl(req.Controls, ldap.ControlTypePaging)
	if ctrlAny == nil {
		// Validation search from Pool.Put: just answer successfully.
		return &ldap.SearchResult{}, nil
	}
	ctrl := ctrlAny.(*ldap.ControlPaging)
	page := 1
	switch string(ctrl.Cookie) {
	case "":
		page = 1
	case "1":
		page = 2
	case "2":
		page = 3
	default:
		return nil, errors.New("unexpected cookie")
	}
	var next []byte
	if page < 3 {
		next = []byte{byte('0' + page)}
	}
	res := &ldap.SearchResult{
		Entries: []*ldap.Entry{
			testEntry("cn=p" + string(rune('0'+page)) + "a,dc=example,dc=com"),
			testEntry("cn=p" + string(rune('0'+page)) + "b,dc=example,dc=com"),
		},
		Controls: []ldap.Control{&ldap.ControlPaging{PagingSize: f.pageSize, Cookie: next}},
	}
	return res, nil
}

func pagingClient(t *testing.T) *Client {
	t.Helper()
	f := &pagingFake{pageSize: 2}
	p := newTestPool(f)
	return &Client{pool: p, baseDN: "dc=example,dc=com"}
}

func TestPageFirstPage(t *testing.T) {
	c := pagingClient(t)
	res, err := c.Page(context.Background(), SearchOptions{Scope: ldap.ScopeSingleLevel, PageSize: 2}, 1)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if len(res.Entries) != 2 || res.Entries[0].DN != "cn=p1a,dc=example,dc=com" {
		t.Errorf("entries: %+v", res.Entries)
	}
	if !res.HasMore {
		t.Error("HasMore should be true on page 1")
	}
	if res.Page != 1 {
		t.Errorf("Page = %d", res.Page)
	}
}

func TestPageSecondPage(t *testing.T) {
	c := pagingClient(t)
	res, err := c.Page(context.Background(), SearchOptions{Scope: ldap.ScopeSingleLevel, PageSize: 2}, 2)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if len(res.Entries) != 2 || res.Entries[0].DN != "cn=p2a,dc=example,dc=com" {
		t.Errorf("entries: %+v", res.Entries)
	}
	if !res.HasMore {
		t.Error("HasMore should be true on page 2")
	}
}

func TestPageLastPage(t *testing.T) {
	c := pagingClient(t)
	res, err := c.Page(context.Background(), SearchOptions{Scope: ldap.ScopeSingleLevel, PageSize: 2}, 3)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if len(res.Entries) != 2 || res.Entries[0].DN != "cn=p3a,dc=example,dc=com" {
		t.Errorf("entries: %+v", res.Entries)
	}
	if res.HasMore {
		t.Error("HasMore should be false on final page")
	}
	if res.Page != 3 {
		t.Errorf("Page = %d", res.Page)
	}
}

func TestPageBeyondLastReturnsLastPage(t *testing.T) {
	c := pagingClient(t)
	res, err := c.Page(context.Background(), SearchOptions{Scope: ldap.ScopeSingleLevel, PageSize: 2}, 9)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if res.Page != 3 || res.HasMore {
		t.Errorf("want last page (3, no more), got page %d hasMore=%v", res.Page, res.HasMore)
	}
}

func TestPageDefaults(t *testing.T) {
	c := pagingClient(t)
	res, err := c.Page(context.Background(), SearchOptions{Scope: ldap.ScopeSingleLevel}, 1)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if len(res.Entries) != 2 {
		t.Errorf("page size should default; got %d entries", len(res.Entries))
	}
}

func TestPageCanceled(t *testing.T) {
	c := pagingClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Page(ctx, SearchOptions{Scope: ldap.ScopeSingleLevel}, 1); err == nil {
		t.Fatal("want context cancellation error")
	}
}

func TestSearchWrapsLDAPError(t *testing.T) {
	f := &fakeConn{searchFn: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return nil, ldap.NewError(32, errors.New("no such object"))
	}}
	c := &Client{pool: newTestPool(f), baseDN: "dc=example,dc=com"}
	req := ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil)
	_, err := c.Search(context.Background(), req)
	var lerr *LDAPError
	if !errors.As(err, &lerr) {
		t.Fatalf("want *LDAPError, got %T: %v", err, err)
	}
	if lerr.Code != 32 || lerr.Op != "search" || lerr.DN != "dc=example,dc=com" {
		t.Errorf("LDAPError = %+v", lerr)
	}
}

func TestSearchAutoWithoutPool(t *testing.T) {
	c := &Client{pool: newTestPool()}
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil)
	if _, err := c.SearchAuto(context.Background(), req); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("want ErrPoolClosed, got %v", err)
	}
}
