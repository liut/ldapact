package ldif

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/authn"
	"github.com/liut/ldapact/pkg/ldapx"
)

// Exporter is the read surface for F7; *ldapx.Client implements it.
type Exporter interface {
	Search(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error)
	Page(ctx context.Context, opts ldapx.SearchOptions, page int) (*ldapx.PageResult, error)
}

// ExportHandler serves F7 (LDIF export with default userPassword redaction).
type ExportHandler struct {
	client   Exporter
	logger   *slog.Logger
	pageSize int
}

// NewExportHandler builds the F7 handler.
func NewExportHandler(client Exporter, logger *slog.Logger) *ExportHandler {
	return &ExportHandler{client: client, logger: logger, pageSize: 500}
}

// Export handles GET /api/export?dn=...&scope=entry|subtree&include_secrets=1.
func (h *ExportHandler) Export(w http.ResponseWriter, r *http.Request) {
	dn := r.URL.Query().Get("dn")
	scope := strings.ToLower(r.URL.Query().Get("scope"))
	if scope == "" {
		scope = "entry"
	}
	if scope != "entry" && scope != "subtree" {
		http.Error(w, "Bad Request: scope must be entry or subtree", http.StatusBadRequest)
		return
	}
	if dn == "" {
		http.Error(w, "Bad Request: missing dn", http.StatusBadRequest)
		return
	}
	includeSecrets := r.URL.Query().Get("include_secrets") == "1"
	if includeSecrets && h.logger != nil {
		h.logger.Warn("LDIF export includes secrets", "event", "ldif.export_secrets", "dn", dn)
	}

	// Entry scope: resolve the entry before committing response headers so a
	// failed lookup returns a clean error status instead of a mangled LDIF.
	var single *ldap.Entry
	if scope == "entry" {
		req := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			0, 0, false, "(objectClass=*)", []string{"*"}, nil)
		res, err := h.client.Search(r.Context(), req)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		if len(res.Entries) == 0 {
			http.Error(w, "Entry not found", http.StatusNotFound)
			return
		}
		single = res.Entries[0]
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="ldapact-export-%s.ldif"`, time.Now().Format("20060102-150405")))
	wr := NewWriter(w)
	if _, err := wr.w.WriteString("version: 1\n"); err != nil {
		return
	}
	if scope == "entry" {
		if err := wr.WriteEntry(entryToLDIF(single, includeSecrets)); err != nil {
			return
		}
		return
	}

	// Subtree: stream page by page via the paging cookie (plan: streaming for
	// huge subtrees, no full-materialization).
	flusher, _ := w.(http.Flusher)
	page := 1
	for {
		res, err := h.client.Page(r.Context(), ldapx.SearchOptions{
			BaseDN:   dn,
			Scope:    ldap.ScopeWholeSubtree,
			Filter:   "(objectClass=*)",
			Attrs:    []string{"*"},
			PageSize: h.pageSize,
		}, page)
		if err != nil {
			h.logger.Error("export page failed", "event", "ldif.export_error", "dn", dn, "error", err)
			return
		}
		for _, e := range res.Entries {
			if err := wr.WriteEntry(entryToLDIF(e, includeSecrets)); err != nil {
				return
			}
		}
		if flusher != nil {
			flusher.Flush()
		}
		if !res.HasMore {
			break
		}
		page++
	}
}

func (h *ExportHandler) writeError(w http.ResponseWriter, r *http.Request, err error) {
	if authn.IsInvalidCredentials(err) {
		authn.InvalidCredentialsRedirect(w, r)
		return
	}
	h.logger.Error("export failed", "event", "ldif.export_error", "error", err)
	http.Error(w, "Directory error", http.StatusBadGateway)
}

// entryToLDIF converts a search entry, dropping userPassword unless secrets
// are explicitly requested (R10/F7 default redaction).
func entryToLDIF(e *ldap.Entry, includeSecrets bool) *Entry {
	out := &Entry{DN: e.DN}
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, "userPassword") && !includeSecrets {
			continue
		}
		vals := a.Values
		if len(vals) == 0 {
			continue
		}
		attr := Attribute{Name: a.Name}
		// Binary values may not survive UTF-8 conversion in Values; prefer
		// ByteValues when they differ (R10 base64 for binary attrs).
		if len(a.ByteValues) == len(a.Values) {
			for i := range a.Values {
				attr.Values = append(attr.Values, string(a.ByteValues[i]))
			}
		} else {
			attr.Values = vals
		}
		out.Attrs = append(out.Attrs, attr)
	}
	return out
}
