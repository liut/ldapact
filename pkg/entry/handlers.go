// Package entry implements the template-driven flows F2 (create), F3
// (password change), F5 (delete), F6 (rename), entry edit (R1), and the
// F-Detail entry view.
package entry

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/authn"
	"github.com/liut/ldapact/pkg/config"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/session"
	"github.com/liut/ldapact/pkg/tplengine"
	"github.com/liut/ldapact/pkg/web"
)

// EntryClient is the LDAP surface the flows need. *ldapx.Client implements it.
type EntryClient interface {
	Search(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error)
	Add(ctx context.Context, dn string, attrs map[string][]string) error
	Modify(ctx context.Context, dn string, changes []ldap.Change) error
	Delete(ctx context.Context, dn string) error
	ModifyDN(ctx context.Context, dn, newRDN string, deleteOldRDN bool, newSuperior string) error
	Schema() *ldapx.Schema
	BaseDN() string
}

// Handler serves the entry and template routes.
type Handler struct {
	client   EntryClient
	render   *web.Renderer
	logger   *slog.Logger
	loader   *TemplateLoader
	sessions *session.Store
	cfg      *config.Config
}

// autoSearcher adapts an LDAP client's independent auto-number pool
// (ldapx.Client.SearchAuto) to the macro Searcher interface (R8 rebind).
type autoSearcher struct {
	client interface {
		SearchAuto(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error)
	}
}

func (a autoSearcher) Search(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return a.client.SearchAuto(ctx, req)
}

// macroContext builds a render-time macro context; GetNextNumber uses the
// independent auto-number pool when one is configured (R8).
func (h *Handler) macroContext(r *http.Request, values map[string]string) *tplengine.MacroContext {
	mc := &tplengine.MacroContext{
		Ctx:           r.Context(),
		Client:        h.client,
		Logger:        h.logger,
		BaseDN:        h.client.BaseDN(),
		ParentDN:      h.client.BaseDN(),
		Values:        values,
		PlainAllowed:  h.cfg != nil && h.cfg.LDAP.PasswordPlainOverride,
		DefaultScheme: h.passwordScheme(),
	}
	if h.cfg != nil && h.cfg.LDAP.AutoNumberDN != "" {
		if as, ok := h.client.(interface {
			SearchAuto(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error)
		}); ok {
			mc.AutoSearcher = autoSearcher{client: as}
		}
	}
	return mc
}

// passwordScheme returns the configured write scheme (KTD 6 default).
func (h *Handler) passwordScheme() string {
	if h.cfg != nil && h.cfg.LDAP.PasswordScheme != "" {
		return h.cfg.LDAP.PasswordScheme
	}
	return tplengine.DefaultHashScheme
}

// ResultData drives the generic result page (success/error).
type ResultData struct {
	Title    string
	Message  string
	Link     string
	LinkText string
	Error    bool
}

// New builds the flow handler.
func New(client EntryClient, renderer *web.Renderer, logger *slog.Logger, loader *TemplateLoader, sessions *session.Store, cfg *config.Config) *Handler {
	return &Handler{client: client, render: renderer, logger: logger, loader: loader, sessions: sessions, cfg: cfg}
}

// TemplateLoader resolves template names from the embedded corpus and an
// optional server-profile custom directory (R7 custom loads).
type TemplateLoader struct {
	corpus    fs.FS
	customDir string
}

// NewTemplateLoader builds a loader. corpus is the embedded templates FS;
// customDir may be empty.
func NewTemplateLoader(corpus fs.FS, customDir string) *TemplateLoader {
	return &TemplateLoader{corpus: corpus, customDir: customDir}
}

// Load opens {name}.xml: custom directory first, then the embedded
// creation corpus. Template names must be simple (no path separators).
func (l *TemplateLoader) Load(name string) (*tplengine.Template, error) {
	return l.load("creation", name)
}

// LoadModification opens modification/{name}.xml with the same custom-dir-
// first resolution as Load. Modification templates parse with the shared
// tplengine parser (R5).
func (l *TemplateLoader) LoadModification(name string) (*tplengine.Template, error) {
	return l.load("modification", name)
}

func (l *TemplateLoader) load(kind, name string) (*tplengine.Template, error) {
	if name == "" || strings.ContainsAny(name, "/\\.") {
		return nil, errors.New("entry: invalid template name")
	}
	rel := kind + "/" + name + ".xml"
	if l.customDir != "" {
		p := l.customDir + "/" + rel
		if f, err := os.Open(p); err == nil {
			defer f.Close()
			return tplengine.Parse(f, p)
		}
	}
	f, err := l.corpus.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return tplengine.Parse(f, rel)
}

// ModificationNames returns the sorted modification-template base names from
// the custom directory (first) and the embedded corpus, deduplicated.
func (l *TemplateLoader) ModificationNames() []string {
	seen := map[string]bool{}
	if entries, err := fs.Glob(l.corpus, "modification/*.xml"); err == nil {
		for _, e := range entries {
			seen[strings.TrimSuffix(path.Base(e), path.Ext(e))] = true
		}
	}
	if l.customDir != "" {
		if entries, err := os.ReadDir(l.customDir + "/modification"); err == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".xml") {
					seen[strings.TrimSuffix(e.Name(), ".xml")] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// renderPage renders a full page via the shared layout.
func (h *Handler) renderPage(w http.ResponseWriter, title, content string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.render.Page(w, title, content, data); err != nil {
		h.logger.Error("render page", "event", "web.render_failed", "template", content, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// actor extracts the bind DN (R15 actor semantics) from the request session.
func actor(r *http.Request) string {
	if s := authn.SessionFrom(r.Context()); s != nil && s.Value != nil {
		return s.Value.ProfileRef
	}
	return ""
}

// audit logs a mutation event with the R15 shape and never any password
// values (redaction happens at the logger boundary; SafeAttr for call sites).
func (h *Handler) audit(r *http.Request, event, dn, opType string) {
	h.logger.Info("ldap mutation",
		"event", event,
		"actor", actor(r),
		"dn", dn,
		"op_type", opType)
}

// isNotFound reports whether an LDAP error means the entry is missing.
func isNotFound(err error) bool {
	var lerr *ldapx.LDAPError
	if errors.As(err, &lerr) {
		return lerr.Code == ldap.LDAPResultNoSuchObject
	}
	return false
}

// escapeRDNValue escapes an RDN value for use in a DN (RFC 4514 subset).
func escapeRDNValue(v string) string {
	var sb strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == ',' || c == '+' || c == '"' || c == '\\' || c == '<' || c == '>' || c == ';' || c == '=':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c == ' ' && (i == 0 || i == len(v)-1):
			sb.WriteString(`\ `)
		case c == '#' && i == 0:
			sb.WriteString(`\#`)
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}
