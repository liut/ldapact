package ldapx

import (
	"context"
	"errors"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// DefaultPageSize is the tree/search pagination default (plan: 100).
const DefaultPageSize = 100

// SortSpec requests a server-side sort control (RFC 2891) on a paged search.
// The directory may ignore or reject the control; callers keep a per-page
// client sort as fallback (see PageResult.SortFallback).
type SortSpec struct {
	Attribute string
	Reverse   bool
}

// SearchOptions describes a (paged) search.
type SearchOptions struct {
	BaseDN    string
	Scope     int
	Filter    string
	Attrs     []string
	PageSize  int
	SizeLimit int
	TimeLimit int
	// Sort optionally attaches a server-side sort control (RFC 2891).
	Sort *SortSpec
	// AllowEmptyBase permits an explicit empty BaseDN (root DSE, F8 "global"
	// scope) instead of defaulting to the configured base DN.
	AllowEmptyBase bool
}

// PageResult is one page of a paged search.
type PageResult struct {
	Entries []*ldap.Entry
	HasMore bool
	Page    int
	// SortFallback is true when the directory rejected or reported failure
	// for the server-side sort control; the returned page was not
	// server-ordered, so callers should apply their own client sort.
	SortFallback bool
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
// the paging cookie carried forward, discarding earlier pages. The whole
// multi-page loop runs on ONE pooled connection because LDAP paged-result
// sessions are connection-scoped (sending a cookie on another connection
// yields "paged results cookie is invalid").
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
	if opts.BaseDN == "" && !opts.AllowEmptyBase {
		opts.BaseDN = c.baseDN
	}

	conn, err := c.pool.Get(ctx)
	if err != nil {
		return nil, err
	}
	for attempt := 1; ; attempt++ {
		res, perr := pageLoop(ctx, conn, opts, page)
		if perr == nil {
			c.pool.Put(conn)
			return res, nil
		}
		if attempt == 1 && isRetryable(perr) {
			_ = c.pool.Put(conn) // validates and drops the sick conn
			select {
			case <-time.After(backoffFor(attempt)):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			conn, err = c.pool.Get(ctx)
			if err != nil {
				return nil, err
			}
			continue
		}
		c.pool.Put(conn)
		return nil, perr
	}
}

// pageLoop walks pages 1..page on a single connection, carrying the paging
// cookie forward.
func pageLoop(ctx context.Context, conn Conn, opts SearchOptions, page int) (*PageResult, error) {
	var cookie []byte
	var entries []*ldap.Entry
	sortFallback := false
	for p := 1; p <= page; p++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		controls := []ldap.Control{&ldap.ControlPaging{PagingSize: uint32(opts.PageSize), Cookie: cookie}}
		if opts.Sort != nil && !sortFallback {
			controls = append(controls, ldap.NewControlServerSideSortingWithSortKeys([]*ldap.SortKey{{
				AttributeType: opts.Sort.Attribute,
				Reverse:       opts.Sort.Reverse,
			}}))
		}
		req := ldap.NewSearchRequest(opts.BaseDN, opts.Scope, ldap.NeverDerefAliases,
			opts.SizeLimit, opts.TimeLimit, false, opts.Filter, opts.Attrs, controls)
		res, err := conn.Search(req)
		if err != nil && opts.Sort != nil && !sortFallback && sortRejected(err) {
			// The directory refused the RFC 2891 control; restart the paging
			// session without it (a mid-session cookie would be invalid).
			sortFallback = true
			cookie = nil
			p = 0
			continue
		}
		if err != nil {
			return nil, wrapError("search", opts.BaseDN, err)
		}
		if opts.Sort != nil && !sortFallback && sortResultFailed(res.Controls) {
			sortFallback = true
		}
		entries = res.Entries
		cookie = pagingCookie(res.Controls)
		if len(cookie) == 0 {
			return &PageResult{Entries: entries, HasMore: false, Page: p, SortFallback: sortFallback}, nil
		}
	}
	return &PageResult{Entries: entries, HasMore: true, Page: page, SortFallback: sortFallback}, nil
}

// sortRejected reports whether an LDAP error means the directory refused the
// server-side sort control outright.
func sortRejected(err error) bool {
	var le *ldap.Error
	if errors.As(err, &le) {
		switch le.ResultCode {
		case ldap.LDAPResultUnwillingToPerform,
			ldap.LDAPResultUnavailableCriticalExtension,
			ldap.LDAPResultInsufficientAccessRights,
			ldap.LDAPResultNoSuchAttribute:
			return true
		}
	}
	return false
}

// sortResultFailed reports whether the response's RFC 2891 sortResult
// control carried a non-success code (server returned unsorted results).
func sortResultFailed(controls []ldap.Control) bool {
	ctrl := ldap.FindControl(controls, ldap.ControlTypeServerSideSortingResult)
	if ctrl == nil {
		return false
	}
	if sc, ok := ctrl.(*ldap.ControlServerSideSortingResult); ok {
		return sc.Result != ldap.ControlServerSideSortingCodeSuccess
	}
	return false
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
