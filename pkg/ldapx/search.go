package ldapx

import (
	"context"

	"github.com/go-ldap/ldap/v3"
)

// DefaultPageSize is the tree/search pagination default (plan: 100).
const DefaultPageSize = 100

// SearchOptions describes a (paged) search.
type SearchOptions struct {
	BaseDN    string
	Scope     int
	Filter    string
	Attrs     []string
	PageSize  int
	SizeLimit int
	TimeLimit int
}

// PageResult is one page of a paged search.
type PageResult struct {
	Entries []*ldap.Entry
	HasMore bool
	Page    int
}

// Search runs a single LDAP search through the pool with one retry on
// network-level failures.
func (c *Client) Search(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	var res *ldap.SearchResult
	err := c.pool.Do(ctx, func(conn Conn) error {
		var err error
		res, err = conn.Search(req)
		if err != nil {
			return wrapError("search", req.BaseDN, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// Page returns the Nth page (1-based) of a paged search (R2). The handler
// stays stateless: each page request re-runs the search from the start with
// the paging cookie carried forward, discarding earlier pages. Cancellation is
// honored between pages and per request (the conn is dropped if the request
// is still in flight when ctx is canceled).
func (c *Client) Page(ctx context.Context, opts SearchOptions, page int) (*PageResult, error) {
	if page < 1 {
		page = 1
	}
	if opts.PageSize <= 0 {
		opts.PageSize = DefaultPageSize
	}
	if opts.Filter == "" {
		opts.Filter = "(objectClass=*)"
	}
	if opts.BaseDN == "" {
		opts.BaseDN = c.baseDN
	}

	var cookie []byte
	var entries []*ldap.Entry
	for p := 1; p <= page; p++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := ldap.NewSearchRequest(opts.BaseDN, opts.Scope, ldap.NeverDerefAliases,
			opts.SizeLimit, opts.TimeLimit, false, opts.Filter, opts.Attrs,
			[]ldap.Control{&ldap.ControlPaging{PagingSize: uint32(opts.PageSize), Cookie: cookie}})
		res, err := c.Search(ctx, req)
		if err != nil {
			return nil, err
		}
		entries = res.Entries
		cookie = pagingCookie(res.Controls)
		if len(cookie) == 0 {
			return &PageResult{Entries: entries, HasMore: false, Page: p}, nil
		}
	}
	return &PageResult{Entries: entries, HasMore: true, Page: page}, nil
}

// SearchAuto runs a search through the independent auto-number pool (R8
// GetNextNumber). Returns ErrPoolClosed if no auto-number pool is configured.
func (c *Client) SearchAuto(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if c.autoPool == nil {
		return nil, ErrPoolClosed
	}
	var res *ldap.SearchResult
	err := c.autoPool.Do(ctx, func(conn Conn) error {
		var err error
		res, err = conn.Search(req)
		if err != nil {
			return wrapError("search", req.BaseDN, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func pagingCookie(controls []ldap.Control) []byte {
	ctrl := ldap.FindControl(controls, ldap.ControlTypePaging)
	if ctrl == nil {
		return nil
	}
	if pc, ok := ctrl.(*ldap.ControlPaging); ok {
		return pc.Cookie
	}
	return nil
}
