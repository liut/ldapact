package ldapx

import (
	"context"
	"sync/atomic"

	"github.com/go-ldap/ldap/v3"
)

// fakeConn implements Conn for unit tests without a real LDAP server.
type fakeConn struct {
	bindFn     func(user, pass string) error
	unbindFn   func(user string) error
	externalFn func() error
	searchFn   func(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	addFn      func(req *ldap.AddRequest) error
	modifyFn   func(req *ldap.ModifyRequest) error
	delFn      func(req *ldap.DelRequest) error
	modifyDNFn func(req *ldap.ModifyDNRequest) error
	passwdFn   func(req *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error)

	closed       atomic.Bool
	lastBindUser string
	lastBindPass string
	searchCalls  atomic.Int64
}

func (f *fakeConn) Bind(user, pass string) error {
	f.lastBindUser = user
	f.lastBindPass = pass
	if f.bindFn != nil {
		return f.bindFn(user, pass)
	}
	return nil
}

func (f *fakeConn) UnauthenticatedBind(user string) error {
	f.lastBindUser = user
	if f.unbindFn != nil {
		return f.unbindFn(user)
	}
	return nil
}

func (f *fakeConn) ExternalBind() error {
	if f.externalFn != nil {
		return f.externalFn()
	}
	return nil
}

func (f *fakeConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.searchCalls.Add(1)
	if f.searchFn != nil {
		return f.searchFn(req)
	}
	return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
}

func (f *fakeConn) SearchAsync(_ context.Context, req *ldap.SearchRequest, _ int) ldap.Response {
	res, err := f.Search(req)
	if err != nil {
		return &fakeResponse{err: err}
	}
	return &fakeResponse{entries: res.Entries}
}

func (f *fakeConn) Add(req *ldap.AddRequest) error {
	if f.addFn != nil {
		return f.addFn(req)
	}
	return nil
}

func (f *fakeConn) Modify(req *ldap.ModifyRequest) error {
	if f.modifyFn != nil {
		return f.modifyFn(req)
	}
	return nil
}

func (f *fakeConn) Del(req *ldap.DelRequest) error {
	if f.delFn != nil {
		return f.delFn(req)
	}
	return nil
}

func (f *fakeConn) ModifyDN(req *ldap.ModifyDNRequest) error {
	if f.modifyDNFn != nil {
		return f.modifyDNFn(req)
	}
	return nil
}

func (f *fakeConn) PasswordModify(req *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
	if f.passwdFn != nil {
		return f.passwdFn(req)
	}
	return &ldap.PasswordModifyResult{}, nil
}

func (f *fakeConn) Close() error {
	f.closed.Store(true)
	return nil
}

func (f *fakeConn) IsClosing() bool { return f.closed.Load() }

// fakeResponse is a minimal ldap.Response for SearchAsync tests.
type fakeResponse struct {
	entries []*ldap.Entry
	err     error
	pos     int
}

func (r *fakeResponse) Next() bool {
	if r.err != nil || r.pos >= len(r.entries) {
		return false
	}
	r.pos++
	return true
}

func (r *fakeResponse) Entry() *ldap.Entry {
	if r.pos == 0 {
		return nil
	}
	return r.entries[r.pos-1]
}

func (r *fakeResponse) Err() error               { return r.err }
func (r *fakeResponse) Referral() string         { return "" }
func (r *fakeResponse) Controls() []ldap.Control { return nil }

func testEntry(dn string) *ldap.Entry {
	return &ldap.Entry{DN: dn, Attributes: []*ldap.EntryAttribute{{Name: "objectClass", Values: []string{"top"}}}}
}
