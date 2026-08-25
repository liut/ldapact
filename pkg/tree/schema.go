package tree

import (
	"net/http"
	"net/url"
	"sort"

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
	Name        string
	OID         string
	Desc        string
	Kind        string
	Sup         []SchemaLink
	Must        []SchemaLink
	May         []SchemaLink
	Syntax      string
	Equality    string
	Ordering    string
	Substr      string
	SingleValue bool
	Usage       string
	BackList    string // "objectclass" or "attribute"
}

// SchemaLink is a cross-navigation link (R5.x: clickable attribute/class names).
type SchemaLink struct {
	Name string
	URL  string
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

// ObjectClasses handles GET /api/schema/objectclass.
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
			URL:  "/api/schema/objectclass/" + url.PathEscape(name),
		})
	}
	s.renderPage(w, "Object Classes — ldapact", "schema-list-content", SchemaListData{Title: "Object Classes", Rows: rows})
}

// ObjectClassDetail handles GET /api/schema/objectclass/{name}.
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
		Name:     name,
		OID:      oc.OID,
		Desc:     oc.Desc,
		Kind:     oc.Kind,
		BackList: "objectclass",
	}
	for _, sup := range oc.Sup {
		data.Sup = append(data.Sup, SchemaLink{
			Name: sup,
			URL:  "/api/schema/objectclass/" + url.PathEscape(sup),
		})
	}
	for _, m := range oc.Must {
		data.Must = append(data.Must, SchemaLink{
			Name: m,
			URL:  "/api/schema/attribute/" + url.PathEscape(m),
		})
	}
	for _, m := range oc.May {
		data.May = append(data.May, SchemaLink{
			Name: m,
			URL:  "/api/schema/attribute/" + url.PathEscape(m),
		})
	}
	s.renderPage(w, name+" — ldapact", "schema-detail-content", data)
}

// Attributes handles GET /api/schema/attribute.
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
			URL:  "/api/schema/attribute/" + url.PathEscape(name),
		})
	}
	s.renderPage(w, "Attribute Types — ldapact", "schema-list-content", SchemaListData{Title: "Attribute Types", Rows: rows})
}

// AttributeDetail handles GET /api/schema/attribute/{name}.
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
		Name:        at.Name,
		OID:         at.OID,
		Desc:        at.Desc,
		Syntax:      at.Syntax,
		Equality:    at.Equality,
		Ordering:    at.Ordering,
		Substr:      at.Substr,
		SingleValue: at.SingleValue,
		Usage:       at.Usage,
		BackList:    "attribute",
	}
	for _, sup := range at.Sup {
		data.Sup = append(data.Sup, SchemaLink{
			Name: sup,
			URL:  "/api/schema/attribute/" + url.PathEscape(sup),
		})
	}
	s.renderPage(w, name+" — ldapact", "schema-detail-content", data)
}

func (s *SchemaBrowser) renderPage(w http.ResponseWriter, title, content string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.render.Page(w, title, content, data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
