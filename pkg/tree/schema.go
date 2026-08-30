package tree

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/web"
)

// SchemaListData drives the schema list pages (R5).
type SchemaListData struct {
	Title string
	Rows  []SchemaRow
}

// SchemaRow is one row of a schema list.
type SchemaRow struct {
	Name string
	Kind string
	Desc string
	URL  string
}

// SchemaDetailData drives schema detail pages (R5.x cross-navigation).
type SchemaDetailData struct {
	Name               string
	OID                string
	Desc               string
	Kind               string
	Sup                []SchemaLink
	Children           []SchemaLink
	Must               []SchemaAttrLink
	May                []SchemaAttrLink
	Syntax             string // syntax OID without any {length} suffix
	SyntaxDesc         string // syntax OID's description from ldapSyntaxes
	Equality           string
	Ordering           string
	Substr             string
	SingleValue        bool
	Collective         bool
	Obsolete           bool
	NoUserModification bool
	MaxLength          string // formatted "N characters"; empty when absent
	Usage              string
	Aliases            []SchemaLink
	UsedBy             []SchemaLink
	BackList           string // "objectclass" or "attribute"
	IsObjectClass      bool
}

// SchemaLink is a cross-navigation link (R5.x: clickable attribute/class names).
type SchemaLink struct {
	Name string
	URL  string
}

// SchemaAttrLink is a MUST/MAY attribute link plus the objectClass that
// declared it, so inherited attributes can be annotated (phpLDAPadmin
// "Inherited from" parity).
type SchemaAttrLink struct {
	Name      string
	URL       string
	Source    string
	SourceURL string
	Inherited bool
}

// SchemaBrowser renders the read-only schema pages (R5, R5.x).
type SchemaBrowser struct {
	client Lister
	render *web.Renderer
}

// NewSchemaBrowser builds the R5 handler set.
func NewSchemaBrowser(client Lister, renderer *web.Renderer) *SchemaBrowser {
	return &SchemaBrowser{client: client, render: renderer}
}

// ObjectClasses handles GET /schema/objectclass.
func (s *SchemaBrowser) ObjectClasses(w http.ResponseWriter, r *http.Request) {
	schema := s.client.Schema()
	if schema == nil {
		http.Error(w, "Service Unavailable: schema not loaded", http.StatusServiceUnavailable)
		return
	}
	names := make([]string, 0, len(schema.ObjectClasses))
	for name := range schema.ObjectClasses {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([]SchemaRow, 0, len(names))
	for _, name := range names {
		oc := schema.ObjectClasses[name]
		rows = append(rows, SchemaRow{
			Name: name,
			Kind: oc.Kind,
			Desc: oc.Desc,
			URL:  "/schema/objectclass/" + url.PathEscape(name),
		})
	}
	s.renderPage(w, "Object Classes — ldapact", "schema-list-content", SchemaListData{Title: "Object Classes", Rows: rows})
}

// ObjectClassDetail handles GET /schema/objectclass/{name}.
func (s *SchemaBrowser) ObjectClassDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	schema := s.client.Schema()
	if schema == nil {
		http.Error(w, "Service Unavailable: schema not loaded", http.StatusServiceUnavailable)
		return
	}
	oc, ok := schema.ObjectClass(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	data := SchemaDetailData{
		Name:          oc.Name,
		OID:           oc.OID,
		Desc:          oc.Desc,
		Kind:          oc.Kind,
		BackList:      "objectclass",
		IsObjectClass: true,
	}
	for _, sup := range oc.Sup {
		data.Sup = append(data.Sup, SchemaLink{
			Name: sup,
			URL:  "/schema/objectclass/" + url.PathEscape(sup),
		})
	}
	if strings.EqualFold(oc.Name, "top") {
		// phpLDAPadmin renders every class as a child of top.
		data.Children = []SchemaLink{{Name: "all", URL: "/schema/objectclass"}}
	} else {
		for _, child := range schema.ChildObjectClasses(oc.Name) {
			data.Children = append(data.Children, SchemaLink{
				Name: child,
				URL:  "/schema/objectclass/" + url.PathEscape(child),
			})
		}
	}
	data.Must = schemaAttrLinks(schema.EffectiveMustAttrs(oc.Name), oc.Name)
	data.May = schemaAttrLinks(schema.EffectiveMayAttrs(oc.Name), oc.Name)
	s.renderPage(w, name+" — ldapact", "schema-detail-content", data)
}

// schemaAttrLinks converts source-tagged objectClass attributes into view
// links, marking those inherited from a SUP ancestor.
func schemaAttrLinks(attrs []ldapx.ObjectClassAttr, current string) []SchemaAttrLink {
	links := make([]SchemaAttrLink, 0, len(attrs))
	for _, a := range attrs {
		links = append(links, SchemaAttrLink{
			Name:      a.Name,
			URL:       "/schema/attribute/" + url.PathEscape(a.Name),
			Source:    a.Source,
			SourceURL: "/schema/objectclass/" + url.PathEscape(a.Source),
			Inherited: !strings.EqualFold(a.Source, current),
		})
	}
	return links
}

// Attributes handles GET /schema/attribute.
func (s *SchemaBrowser) Attributes(w http.ResponseWriter, r *http.Request) {
	schema := s.client.Schema()
	if schema == nil {
		http.Error(w, "Service Unavailable: schema not loaded", http.StatusServiceUnavailable)
		return
	}
	names := make([]string, 0, len(schema.AttributeTypes))
	for name := range schema.AttributeTypes {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([]SchemaRow, 0, len(names))
	for _, name := range names {
		at := schema.AttributeTypes[name]
		kind := "multi-value"
		if at.SingleValue {
			kind = "single-value"
		}
		rows = append(rows, SchemaRow{
			Name: name,
			Kind: kind,
			Desc: at.Desc,
			URL:  "/schema/attribute/" + url.PathEscape(name),
		})
	}
	s.renderPage(w, "Attribute Types — ldapact", "schema-list-content", SchemaListData{Title: "Attribute Types", Rows: rows})
}

// AttributeDetail handles GET /schema/attribute/{name}.
func (s *SchemaBrowser) AttributeDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	schema := s.client.Schema()
	if schema == nil {
		http.Error(w, "Service Unavailable: schema not loaded", http.StatusServiceUnavailable)
		return
	}
	at, ok := schema.Attribute(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	data := SchemaDetailData{
		Name:               at.Name,
		OID:                at.OID,
		Desc:               at.Desc,
		Syntax:             at.SyntaxOID,
		SyntaxDesc:         schema.LDAPSyntaxes[at.SyntaxOID],
		Equality:           at.Equality,
		Ordering:           at.Ordering,
		Substr:             at.Substr,
		SingleValue:        at.SingleValue,
		Collective:         at.Collective,
		Obsolete:           at.Obsolete,
		NoUserModification: at.NoUserModification,
		MaxLength:          formatMaxLength(at.MaxLength),
		Usage:              at.Usage,
		BackList:           "attribute",
	}
	for _, sup := range at.Sup {
		supName := sup
		if sa, ok := schema.Attribute(sup); ok {
			supName = sa.Name
		}
		data.Sup = append(data.Sup, SchemaLink{
			Name: supName,
			URL:  "/schema/attribute/" + url.PathEscape(supName),
		})
	}
	for _, alias := range at.Names[1:] {
		data.Aliases = append(data.Aliases, SchemaLink{
			Name: alias,
			URL:  "/schema/attribute/" + url.PathEscape(alias),
		})
	}
	for _, oc := range schema.ObjectClassesUsing(at.Name) {
		data.UsedBy = append(data.UsedBy, SchemaLink{
			Name: oc,
			URL:  "/schema/objectclass/" + url.PathEscape(oc),
		})
	}
	s.renderPage(w, name+" — ldapact", "schema-detail-content", data)
}

// formatMaxLength renders a syntax {length} as a human-readable string with
// thousands separators, e.g. 32768 → "32,768 characters". Empty means the
// attributeType declares no maximum length.
func formatMaxLength(n int) string {
	if n <= 0 {
		return ""
	}
	s := strconv.Itoa(n)
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteByte(s[i])
	}
	unit := "characters"
	if n == 1 {
		unit = "character"
	}
	return b.String() + " " + unit
}

func (s *SchemaBrowser) renderPage(w http.ResponseWriter, title, content string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.render.Page(w, title, content, data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
