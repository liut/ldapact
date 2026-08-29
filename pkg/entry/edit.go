package entry

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/tplengine"
	"github.com/liut/ldapact/pkg/tree"
)

// operationalAttributes are never editable in the generic editor: RFC 4512
// operational attributes plus common server-maintained values.
var operationalAttributes = map[string]bool{
	"creatorsname":          true,
	"createtimestamp":       true,
	"entrydn":               true,
	"entryuuid":             true,
	"hassubordinates":       true,
	"modifiersname":         true,
	"modifytimestamp":       true,
	"pwdaccountlockedtime":  true,
	"pwdchangedtime":        true,
	"pwdfailuretime":        true,
	"pwdhistory":            true,
	"pwdpolicysubentry":     true,
	"pwdreset":              true,
	"structuralobjectclass": true,
	"subschemasubentry":     true,
}

// EditFormData drives the entry edit form (R1, R6).
type EditFormData struct {
	DN            string
	TemplateName  string
	TemplateTitle string
	Attributes    []FormField
	AddCandidates []tplengine.Value
	Errors        map[string]string
	Crumbs        []tree.Crumb
}

// EditConfirmData drives the old→new review page (phpLDAPadmin
// update_confirm.php parity).
type EditConfirmData struct {
	DN           string
	TemplateName string
	Rows         []EditDiffRow
	Hidden       []EditHiddenField
	Crumbs       []tree.Crumb
}

// EditDiffRow is one attribute row of the review table.
type EditDiffRow struct {
	Name    string
	Old     []string
	New     []string
	Changed bool
}

// EditHiddenField round-trips one editable attribute's new values through
// the stateless review page.
type EditHiddenField struct {
	Name   string
	Values []string
}

// editFieldModel is the internal representation of one editable attribute.
type editFieldModel struct {
	id       string
	display  string
	kind     string // text | textarea | select
	multi    bool
	readonly bool
	redacted bool
	required bool
	options  []tplengine.Value
	values   []string
	helpText string
	hint     string
	preview  string
}

// EditForm handles GET /api/entry/{dn...}/edit (R1).
func (h *Handler) EditForm(w http.ResponseWriter, r *http.Request) {
	dn := r.PathValue("dn")
	e, err := h.fetchEntry(r, dn)
	if err != nil {
		h.dnError(w, r, err)
		return
	}
	if e == nil {
		http.NotFound(w, r)
		return
	}
	fields, tmpl, err := h.buildEditModel(r, e, nil)
	if err != nil {
		h.editTemplateError(w, r, err)
		return
	}
	h.renderEditForm(w, r, e, fields, tmpl, nil)
}

// EditSubmit handles POST /api/entry/{dn...}/edit (R1/R3/R4):
// stage=review renders the old→new page; stage=apply executes the modify.
func (h *Handler) EditSubmit(w http.ResponseWriter, r *http.Request) {
	dn := r.PathValue("dn")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request: invalid form", http.StatusBadRequest)
		return
	}
	e, err := h.fetchEntry(r, dn)
	if err != nil {
		h.dnError(w, r, err)
		return
	}
	if e == nil {
		http.NotFound(w, r)
		return
	}
	fields, tmpl, err := h.buildEditModel(r, e, submittedValues(r))
	if err != nil {
		h.editTemplateError(w, r, err)
		return
	}
	// Stateless round trip: attributes added via add_attr travel through the
	// review/apply hidden inputs; re-derive them from the submitted form.
	fields = h.mergeSubmittedFields(e, fields, submittedValues(r))
	changes := buildChanges(e, fields)
	if errMsg := h.validateChanges(e, fields, changes); errMsg != "" {
		h.renderEditForm(w, r, e, fields, tmpl, map[string]string{"_form": errMsg})
		return
	}
	if add := strings.TrimSpace(r.FormValue("add_attr")); add != "" {
		if h.validAddCandidate(e, fields, add) {
			fields = append(fields, h.addedEditField(e, add, submittedValues(r)))
			h.renderEditForm(w, r, e, fields, tmpl, nil)
		} else {
			h.renderEditForm(w, r, e, fields, tmpl, map[string]string{
				"_form": fmt.Sprintf("Cannot add attribute %q — not in this entry's objectClass schema.", add),
			})
		}
		return
	}
	switch r.FormValue("stage") {
	case "review":
		h.renderEditConfirm(w, r, e, tmpl, fields, changes)
	case "apply":
		if len(changes) == 0 {
			h.renderPage(w, "No changes — ldapact", "result-page", ResultData{
				Title:    "No changes",
				Message:  "No attributes were changed.",
				Link:     "/api/entry/" + url.PathEscape(dn),
				LinkText: "Back to entry",
			})
			return
		}
		if h.client.Schema() != nil {
			for i := range changes {
				if canon, ok := h.client.Schema().CanonicalAttribute(changes[i].Modification.Type); ok && canon != changes[i].Modification.Type {
					changes[i].Modification.Type = canon
				}
			}
		}
		if err := h.client.Modify(r.Context(), dn, changes); err != nil {
			h.logger.Warn("entry edit rejected", "event", "ldap.error", "dn", dn, "error", err)
			h.renderEditForm(w, r, e, fields, tmpl, map[string]string{"_form": editError(err)})
			return
		}
		h.audit(r, "ldap.modify", dn, "modify")
		w.Header().Set("X-Mutated-Subtree", parentDN(dn))
		h.renderPage(w, "Entry updated — ldapact", "result-page", ResultData{
			Title:    "Entry updated",
			Message:  fmt.Sprintf("Updated %s", dn),
			Link:     "/api/entry/" + url.PathEscape(dn),
			LinkText: "View entry",
		})
	default:
		http.Error(w, "Bad Request: unknown stage", http.StatusBadRequest)
	}
}

// fetchEntry returns the entry with all attributes, or nil when the base
// search finds nothing.
func (h *Handler) fetchEntry(r *http.Request, dn string) (*ldap.Entry, error) {
	req := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"*"}, nil)
	res, err := h.client.Search(r.Context(), req)
	if err != nil {
		return nil, err
	}
	if len(res.Entries) == 0 {
		return nil, nil
	}
	return res.Entries[0], nil
}

// selectModificationTemplate picks the modification template whose
// objectClass set is a subset of the entry's, most specific first. A
// ?template= override forces a named template. Returns nil when no template
// matches (generic editor).
func (h *Handler) selectModificationTemplate(r *http.Request, e *ldap.Entry) (*tplengine.Template, error) {
	// A hidden form input carries the template across the stateless
	// review/apply round trip; the URL override remains for direct links.
	if forced := strings.TrimSpace(r.FormValue("template")); forced != "" {
		tmpl, err := h.loader.LoadModification(forced)
		if err != nil {
			return nil, fmt.Errorf("template %q: %w", forced, err)
		}
		return tmpl, nil
	}
	entryOCs := map[string]bool{}
	for _, oc := range e.GetAttributeValues("objectClass") {
		entryOCs[strings.ToLower(oc)] = true
	}
	var best *tplengine.Template
	bestScore := -1
	for _, name := range h.loader.ModificationNames() {
		tmpl, err := h.loader.LoadModification(name)
		if err != nil {
			// A broken custom template must not take down the generic
			// editor; the parser contract error surfaces only when that
			// template is forced or explicitly selected.
			h.logger.Warn("modification template load failed", "event", "tpl.load_failed", "template", name, "error", err)
			continue
		}
		matched := true
		for _, oc := range tmpl.ObjectClasses {
			if !entryOCs[strings.ToLower(oc)] {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		if len(tmpl.ObjectClasses) > bestScore {
			best = tmpl
			bestScore = len(tmpl.ObjectClasses)
		}
	}
	return best, nil
}

// buildEditModel builds the editable-field model for an entry, honoring the
// R9/R15 exclusions and the RDN read-only contract. submitted carries the
// form values on POST (nil on GET).
func (h *Handler) buildEditModel(r *http.Request, e *ldap.Entry, submitted map[string][]string) ([]editFieldModel, *tplengine.Template, error) {
	tmpl, err := h.selectModificationTemplate(r, e)
	if err != nil {
		return nil, nil, err
	}
	required := h.requiredAttrs(e)
	var fields []editFieldModel
	if tmpl != nil {
		fields = h.templateEditFields(r, e, tmpl, submitted, required)
	} else {
		fields = h.genericEditFields(e, submitted, required)
	}
	fields = append([]editFieldModel{objectClassField(e)}, fields...)
	if len(e.GetAttributeValues("userPassword")) > 0 {
		fields = append(fields, passwordField())
	}
	return fields, tmpl, nil
}

func (h *Handler) templateEditFields(r *http.Request, e *ldap.Entry, tmpl *tplengine.Template, submitted map[string][]string, required map[string]bool) []editFieldModel {
	tmpl.SortFormFields()
	rdnAttrs := rdnAttributes(e.DN)
	fields := make([]editFieldModel, 0, len(tmpl.Attributes))
	for _, a := range tmpl.Attributes {
		if a.Hidden {
			continue
		}
		lower := strings.ToLower(a.ID)
		if lower == "userpassword" || h.isOperational(a.ID) {
			continue
		}
		f := editFieldModel{
			id:       a.ID,
			display:  displayName(a),
			kind:     fieldKind(a),
			multi:    h.attrMultiValue(a.ID, a),
			required: required[lower],
			helpText: a.HelpText,
		}
		switch lower {
		case "jpegphoto":
			if _, _, ok := photoBytes(firstValue(e.GetAttributeValues(a.ID))); ok {
				f.preview = photoURL(e.DN, 0)
				f.readonly = true
				f.hint = "Photo preview — binary photo values are not editable in this flow."
				f.values = []string{"[photo]"}
			}
		case "avatarpath":
			if v := firstValue(e.GetAttributeValues(a.ID)); imageURL(v) {
				f.preview = v
			}
		}
		if options := h.editOptions(r, a); len(options) > 0 {
			f.kind = "select"
			f.options = mergeOptions(e.GetAttributeValues(a.ID), options, f.required)
		}
		sk, hasSchemaKind := h.schemaControlKind(a.ID)
		if hasSchemaKind {
			applySchemaControl(&f, sk, e.GetAttributeValues(a.ID))
		}
		if f.readonly {
			fields = append(fields, f)
			continue
		}
		switch {
		case a.Readonly:
			f.readonly = true
			f.hint = "Read-only attribute"
		case rdnAttrs[strings.ToLower(a.ID)]:
			f.readonly = true
			f.hint = "RDN attribute — use Rename / move to change it"
		}
		for _, v := range e.GetAttributeValues(a.ID) {
			if !utf8.ValidString(v) {
				f.readonly = true
				f.hint = "Binary value — not editable in this flow"
				f.values = []string{"[binary]"}
				break
			}
		}
		if !f.readonly {
			f.values = fieldValues(e, a.ID, submitted)
		}
		// LDAP boolean values are case-insensitive; normalize to the select
		// option spelling so the rendered control matches its value.
		if hasSchemaKind && sk == ldapx.ControlKindSelect && len(f.values) > 0 && f.values[0] != "" {
			f.values[0] = strings.ToUpper(f.values[0])
		}
		if len(f.values) == 0 {
			f.values = []string{""}
		}
		fields = append(fields, f)
	}
	return fields
}

func (h *Handler) genericEditFields(e *ldap.Entry, submitted map[string][]string, required map[string]bool) []editFieldModel {
	rdnAttrs := rdnAttributes(e.DN)
	var fields []editFieldModel
	for _, a := range e.Attributes {
		name := a.Name
		lower := strings.ToLower(name)
		if lower == "objectclass" || lower == "userpassword" || h.isOperational(name) || rdnAttrs[lower] {
			continue
		}
		f := editFieldModel{
			id:       name,
			display:  schemaDisplayName(h.client.Schema(), name),
			kind:     "text",
			multi:    h.attrMultiValue(name, nil),
			required: required[lower],
		}
		switch lower {
		case "jpegphoto":
			if _, _, ok := photoBytes(firstValue(a.Values)); ok {
				f.preview = photoURL(e.DN, 0)
				f.readonly = true
				f.hint = "Photo preview — binary photo values are not editable in this flow."
				f.values = []string{"[photo]"}
			}
		case "avatarpath":
			if v := firstValue(a.Values); imageURL(v) {
				f.preview = v
			}
		}
		sk, hasSchemaKind := h.schemaControlKind(name)
		if hasSchemaKind {
			applySchemaControl(&f, sk, a.Values)
		}
		if f.readonly {
			fields = append(fields, f)
			continue
		}
		for _, v := range a.Values {
			if !utf8.ValidString(v) {
				f.readonly = true
				f.hint = "Binary value — not editable in this flow"
				f.values = []string{"[binary]"}
				break
			}
		}
		if !f.readonly {
			f.values = fieldValues(e, name, submitted)
		}
		// LDAP boolean values are case-insensitive; normalize to the select
		// option spelling so the rendered control matches its value.
		if hasSchemaKind && sk == ldapx.ControlKindSelect && len(f.values) > 0 && f.values[0] != "" {
			f.values[0] = strings.ToUpper(f.values[0])
		}
		fields = append(fields, f)
	}
	sort.SliceStable(fields, func(i, j int) bool { return fields[i].display < fields[j].display })
	return fields
}

// buildChanges computes the RFC 4511 Modify change set: Replace for changed
// attributes (full value set), Delete for cleared attributes, unchanged
// attributes skipped.
func buildChanges(e *ldap.Entry, fields []editFieldModel) []ldap.Change {
	var changes []ldap.Change
	for _, f := range fields {
		if f.readonly || f.redacted || f.id == "objectClass" || f.id == "userPassword" {
			continue
		}
		oldVals := cleanValues(e.GetAttributeValues(f.id))
		newVals := cleanValues(f.values)
		if equalValueSets(oldVals, newVals) {
			continue
		}
		op := ldap.ReplaceAttribute
		if len(newVals) == 0 {
			op = ldap.DeleteAttribute
		}
		changes = append(changes, ldap.Change{
			Operation:    uint(op),
			Modification: ldap.PartialAttribute{Type: f.id, Vals: newVals},
		})
	}
	return changes
}

// validateChanges rejects Delete changes on schema-required attributes that
// currently hold values: MUST attributes cannot be cleared or removed.
// Returns a user-facing error message, or "" when the change set is valid.
func (h *Handler) validateChanges(e *ldap.Entry, fields []editFieldModel, changes []ldap.Change) string {
	for _, c := range changes {
		if c.Operation != uint(ldap.DeleteAttribute) {
			continue
		}
		for _, f := range fields {
			if !f.required || !strings.EqualFold(f.id, c.Modification.Type) {
				continue
			}
			if len(cleanValues(e.GetAttributeValues(f.id))) > 0 {
				return f.display + " is required by schema and cannot be cleared."
			}
		}
	}
	return ""
}

func (h *Handler) renderEditForm(w http.ResponseWriter, r *http.Request, e *ldap.Entry, fields []editFieldModel, tmpl *tplengine.Template, errs map[string]string) {
	title := "the generic editor"
	name := ""
	if tmpl != nil && tmpl.Title != "" {
		title = tmpl.Title
		name = tmpl.Name
	}
	if errs == nil {
		errs = map[string]string{}
	}
	attrs := make([]FormField, 0, len(fields))
	for _, f := range fields {
		ff := toFormField(f, e.DN)
		ff.Error = errs[strings.ToLower(f.id)]
		attrs = append(attrs, ff)
	}
	h.renderPage(w, "Edit entry — ldapact", "edit-form-content", EditFormData{
		DN:            e.DN,
		TemplateName:  name,
		TemplateTitle: title,
		Attributes:    attrs,
		AddCandidates: h.attributeCandidates(e, fields),
		Errors:        errs,
		Crumbs:        tree.Breadcrumbs(e.DN, h.client.BaseDN(), 5),
	})
}

func (h *Handler) renderEditConfirm(w http.ResponseWriter, r *http.Request, e *ldap.Entry, tmpl *tplengine.Template, fields []editFieldModel, changes []ldap.Change) {
	name := ""
	if tmpl != nil {
		name = tmpl.Name
	}
	var rows []EditDiffRow
	var hidden []EditHiddenField
	for _, f := range fields {
		if f.readonly || f.redacted || f.id == "objectClass" || f.id == "userPassword" {
			continue
		}
		oldVals := cleanValues(e.GetAttributeValues(f.id))
		newVals := cleanValues(f.values)
		rows = append(rows, EditDiffRow{
			Name:    f.id,
			Old:     oldVals,
			New:     newVals,
			Changed: !equalValueSets(oldVals, newVals),
		})
		hidden = append(hidden, EditHiddenField{Name: f.id, Values: f.values})
	}
	h.renderPage(w, "Review changes — ldapact", "edit-confirm-content", EditConfirmData{
		DN:           e.DN,
		TemplateName: name,
		Rows:         rows,
		Hidden:       hidden,
		Crumbs:       tree.Breadcrumbs(e.DN, h.client.BaseDN(), 5),
	})
}

func (h *Handler) editTemplateError(w http.ResponseWriter, r *http.Request, err error) {
	h.logger.Error("edit template failed", "event", "tpl.load_failed", "error", err)
	http.Error(w, "Internal Server Error: "+err.Error(), http.StatusInternalServerError)
}

// editOptions evaluates a PickList/MultiList value macro for a single-value
// select field; multi-value fields render as text inputs instead.
func (h *Handler) editOptions(r *http.Request, a *tplengine.Attribute) []tplengine.Value {
	if len(a.Values) != 1 {
		return nil
	}
	raw := strings.TrimSpace(a.Values[0].ID)
	if !strings.HasPrefix(raw, "=php.PickList") && !strings.HasPrefix(raw, "=php.MultiList") {
		return nil
	}
	res, err := tplengine.Evaluate(h.macroContext(r, map[string]string{}), raw)
	if err != nil {
		h.logger.Warn("edit picklist evaluation failed", "event", "tpl.macro_failed", "attribute", a.ID, "error", err)
		return nil
	}
	if ev, ok := res.(*tplengine.Evaluated); ok {
		return ev.Values
	}
	return nil
}

// requiredAttrs returns the entry's effective schema-MUST attribute set
// (resolved through SUP inheritance), keyed by lowercase name. Returns an
// empty set when no schema is available.
func (h *Handler) requiredAttrs(e *ldap.Entry) map[string]bool {
	out := map[string]bool{}
	if h.client.Schema() == nil {
		return out
	}
	for _, name := range h.client.Schema().EffectiveMust(e.GetAttributeValues("objectClass")) {
		out[strings.ToLower(name)] = true
	}
	return out
}

// isOperational reports whether an attribute must be excluded from editing:
// the schema USAGE declaration is the primary signal, with the hardcoded
// list retained as fallback for schema-unknown names.
func (h *Handler) isOperational(name string) bool {
	if h.client.Schema() != nil && h.client.Schema().IsOperational(name) {
		return true
	}
	return operationalAttributes[strings.ToLower(name)]
}

// schemaControlKind classifies an attribute's edit control from its schema
// syntax. ok is false when the schema is unavailable or the attribute is
// unknown — callers fall back to their current rendering.
func (h *Handler) schemaControlKind(name string) (ldapx.ControlKind, bool) {
	if h.client.Schema() == nil {
		return ldapx.ControlKindText, false
	}
	return h.client.Schema().ControlKind(name)
}

// attributeCandidates returns the "Add attribute" picker options: the
// entry's effective objectClass MUST ∪ MAY (SUP-resolved) minus attributes
// already active on the form, minus exclusions (userPassword, objectClass,
// operational, schema-unknown). MUST attributes missing from a broken entry
// appear here so they can be repaired.
func (h *Handler) attributeCandidates(e *ldap.Entry, fields []editFieldModel) []tplengine.Value {
	schema := h.client.Schema()
	if schema == nil {
		return nil
	}
	active := map[string]bool{}
	for _, f := range fields {
		active[strings.ToLower(f.id)] = true
	}
	seen := map[string]bool{}
	var out []tplengine.Value
	rdn := rdnAttributes(e.DN)
	add := func(name string) {
		lower := strings.ToLower(name)
		if lower == "userpassword" || lower == "objectclass" || rdn[lower] || active[lower] || seen[lower] {
			return
		}
		if h.isOperational(name) {
			return
		}
		at, ok := schema.Attribute(name)
		if !ok {
			return
		}
		seen[lower] = true
		out = append(out, tplengine.Value{ID: at.Name, Display: at.Name})
	}
	for _, n := range schema.EffectiveMust(e.GetAttributeValues("objectClass")) {
		add(n)
	}
	for _, n := range schema.EffectiveMay(e.GetAttributeValues("objectClass")) {
		add(n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// mergeSubmittedFields re-derives fields for attribute names present in the
// submitted form but absent from the base model (entry/template attributes) —
// the stateless carry-over of add_attr through review → apply. Control fields
// (stage, template, add_attr, …) fail the candidate check and are ignored.
func (h *Handler) mergeSubmittedFields(e *ldap.Entry, fields []editFieldModel, submitted map[string][]string) []editFieldModel {
	if submitted == nil {
		return fields
	}
	for name := range submitted {
		if !h.validAddCandidate(e, fields, name) {
			continue
		}
		fields = append(fields, h.addedEditField(e, name, submitted))
	}
	return fields
}

// validAddCandidate reports whether add_attr names a genuine candidate for
// this entry, so a crafted POST cannot inject arbitrary attributes.
func (h *Handler) validAddCandidate(e *ldap.Entry, fields []editFieldModel, name string) bool {
	for _, c := range h.attributeCandidates(e, fields) {
		if strings.EqualFold(c.ID, name) {
			return true
		}
	}
	return false
}

// addedEditField builds the editable field for a just-added attribute (R8):
// schema-driven control kind, single/multi shape, and empty values so an
// untouched add stays a no-op.
func (h *Handler) addedEditField(e *ldap.Entry, name string, submitted map[string][]string) editFieldModel {
	lower := strings.ToLower(name)
	f := editFieldModel{
		id:       name,
		display:  schemaDisplayName(h.client.Schema(), name),
		kind:     "text",
		multi:    h.attrMultiValue(name, nil),
		required: h.requiredAttrs(e)[lower],
	}
	if sk, ok := h.schemaControlKind(name); ok {
		applySchemaControl(&f, sk, nil)
	}
	if !f.readonly {
		f.values = fieldValues(e, name, submitted)
	}
	if len(f.values) == 0 {
		f.values = []string{""}
	}
	return f
}

// booleanOptions returns the TRUE/FALSE options for a Boolean-syntax field.
// The empty "(not set)" option is included for MAY/schema-unknown fields
// (browser default against fabrication + clear affordance) and for required
// fields only when the entry has no current value (fabrication protection
// without a clear affordance — MUST attributes cannot be cleared).
func booleanOptions(required bool, current []string) []tplengine.Value {
	opts := []tplengine.Value{
		{ID: "TRUE", Display: "TRUE"},
		{ID: "FALSE", Display: "FALSE"},
	}
	if !required || len(current) == 0 {
		opts = append([]tplengine.Value{{ID: "", Display: "(not set)"}}, opts...)
	}
	return opts
}

// applySchemaControl refines a field model with the schema-derived control
// kind. Binary read-only and boolean select always win over template
// presentation; DN fields get a hint; textarea matches template textareas.
func applySchemaControl(f *editFieldModel, sk ldapx.ControlKind, current []string) {
	switch sk {
	case ldapx.ControlKindSelect:
		f.kind = "select"
		f.options = booleanOptions(f.required, current)
	case ldapx.ControlKindReadonly:
		if !f.readonly {
			f.readonly = true
			f.hint = "Binary value — not editable in this flow"
			f.values = []string{"[binary]"}
		}
	case ldapx.ControlKindDN:
		f.hint = "Distinguished Name"
	case ldapx.ControlKindTextarea:
		f.kind = "textarea"
	}
}

func (h *Handler) attrMultiValue(name string, tmplAttr *tplengine.Attribute) bool {
	if tmplAttr != nil {
		for _, v := range tmplAttr.Values {
			if strings.Contains(strings.ToLower(strings.TrimSpace(v.ID)), "multilist") {
				return true
			}
		}
	}
	if h.client.Schema() != nil {
		if at, ok := h.client.Schema().Attribute(name); ok {
			return !at.SingleValue
		}
	}
	return false
}

func schemaDisplayName(schema *ldapx.Schema, name string) string {
	if schema != nil {
		if at, ok := schema.Attribute(name); ok {
			return at.Name
		}
	}
	return name
}

func objectClassField(e *ldap.Entry) editFieldModel {
	return editFieldModel{
		id:       "objectClass",
		display:  "Object classes",
		kind:     "text",
		multi:    true,
		readonly: true,
		values:   e.GetAttributeValues("objectClass"),
		hint:     "Object classes cannot be changed in this flow.",
	}
}

func passwordField() editFieldModel {
	return editFieldModel{
		id:       "userPassword",
		display:  "Password",
		kind:     "password",
		redacted: true,
		values:   []string{"[redacted]"},
		hint:     "Passwords are changed in the password flow (F3).",
	}
}

func toFormField(f editFieldModel, dn string) FormField {
	ff := FormField{
		ID:             f.id,
		Display:        f.display,
		Kind:           f.kind,
		Readonly:       f.readonly,
		Multi:          f.multi,
		MultiValues:    f.values,
		Values:         f.options,
		Redacted:       f.redacted,
		SchemaRequired: f.required,
		HelpText:       f.helpText,
		Hint:           f.hint,
		Preview:        f.preview,
	}
	if f.redacted {
		ff.PasswordLink = "/api/entry/" + url.PathEscape(dn) + "/password"
	}
	if !f.multi && !f.redacted && len(f.values) > 0 {
		ff.Value = f.values[0]
	}
	return ff
}

// fieldValues returns the current entry values, or the submitted values when
// a POST round-trip is in flight. On POST, a field absent from the form means
// the user removed every value (e.g. all multi-value rows): it must NOT fall
// back to the entry's values, or removal would silently no-op.
func fieldValues(e *ldap.Entry, id string, submitted map[string][]string) []string {
	if submitted != nil {
		if vs, ok := submitted[strings.ToLower(id)]; ok {
			return cleanValues(vs)
		}
		return nil
	}
	return cleanValues(e.GetAttributeValues(id))
}

func submittedValues(r *http.Request) map[string][]string {
	out := make(map[string][]string, len(r.Form))
	for k, vs := range r.Form {
		out[strings.ToLower(k)] = vs
	}
	return out
}

func cleanValues(vs []string) []string {
	out := make([]string, 0, len(vs))
	seen := make(map[string]bool, len(vs))
	for _, v := range vs {
		if v = strings.TrimSpace(v); v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func firstValue(vs []string) string {
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}

func equalValueSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ca := append([]string(nil), a...)
	cb := append([]string(nil), b...)
	sort.Strings(ca)
	sort.Strings(cb)
	for i := range ca {
		if ca[i] != cb[i] {
			return false
		}
	}
	return true
}

func rdnAttributes(dn string) map[string]bool {
	out := map[string]bool{}
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return out
	}
	for _, rdn := range parsed.RDNs {
		for _, a := range rdn.Attributes {
			out[strings.ToLower(a.Type)] = true
		}
	}
	return out
}

func displayName(a *tplengine.Attribute) string {
	if strings.TrimSpace(a.Display) != "" {
		return a.Display
	}
	return a.ID
}

func fieldKind(a *tplengine.Attribute) string {
	switch a.Kind.String() {
	case "textarea":
		return "textarea"
	default:
		return "text"
	}
}

// mergeOptions keeps current entry values first so a picklist-backed edit
// field always has the current value selectable. For MAY/schema-unknown
// fields it prepends an empty "(not set)" option (no-fabrication default +
// clear affordance); for required fields the empty option appears only when
// the entry has no current value.
func mergeOptions(current []string, opts []tplengine.Value, required bool) []tplengine.Value {
	seen := map[string]bool{}
	out := make([]tplengine.Value, 0, len(opts)+len(current)+1)
	if !required || len(current) == 0 {
		out = append(out, tplengine.Value{ID: "", Display: "(not set)"})
	}
	for _, v := range current {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, tplengine.Value{ID: v, Display: v})
	}
	for _, o := range opts {
		if o.ID == "" || seen[o.ID] {
			continue
		}
		seen[o.ID] = true
		out = append(out, o)
	}
	return out
}

func editError(err error) string {
	var lerr *ldapx.LDAPError
	if errors.As(err, &lerr) {
		switch lerr.Code {
		case ldap.LDAPResultConstraintViolation:
			return "The directory rejected the change (constraint violation)."
		case ldap.LDAPResultObjectClassViolation:
			return "The directory rejected the change (object class violation)."
		case ldap.LDAPResultNoSuchAttribute:
			return "The directory rejected the change (attribute does not exist)."
		case ldap.LDAPResultAttributeOrValueExists:
			return "The directory rejected the change (value already exists)."
		}
	}
	return "The directory rejected the change: " + err.Error()
}
