package entry

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/tplengine"
)

// CreateFormData drives the F2 wizard.
type CreateFormData struct {
	TemplateName  string
	Title         string
	Description   string
	ObjectClasses []string
	RDN           string
	Container     string
	Pages         []int
	Attributes    []FormField
	Errors        map[string]string
	Autofill      []string
}

// FormField is one rendered control of the F2 form.
type FormField struct {
	ID        string
	Display   string
	HelpText  string
	Kind      string
	Readonly  bool
	Hidden    bool
	Required  bool
	Value     string
	Values    []tplengine.Value
	NoMatches bool
	MaxHit    bool
	Notice    string
	Error     string
	Page      int
	// Edit-flow extensions (the create flow never sets them).
	Multi          bool
	MultiValues    []string
	Redacted       bool
	SchemaRequired bool
	PasswordLink   string
	Hint           string
	Preview        string
}

// CreateForm handles GET /api/template/{name} (F2 form).
func (h *Handler) CreateForm(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	tmpl, err := h.loader.Load(name)
	if err != nil {
		h.logger.Warn("template load failed", "event", "tpl.load_failed", "template", name, "error", err)
		http.NotFound(w, r)
		return
	}
	container := r.URL.Query().Get("container")
	if container == "" {
		container = h.client.BaseDN()
	}
	mc := h.macroContext(r, map[string]string{})
	mc.ParentDN = container
	if err := tmpl.EvaluateMacros(mc); err != nil {
		h.logger.Error("template macro evaluation failed", "event", "tpl.macro_failed", "template", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data := CreateFormData{
		TemplateName:  name,
		Title:         tmpl.Title,
		Description:   tmpl.Description,
		ObjectClasses: tmpl.ObjectClasses,
		RDN:           tmpl.RDN,
		Container:     container,
		Pages:         tmpl.Pages,
		Attributes:    buildFormFields(tmpl),
		Errors:        map[string]string{},
	}
	for _, a := range tmpl.Attributes {
		for _, oc := range a.OnChange {
			if af, err := tplengine.ParseAutoFill(oc); err == nil {
				data.Autofill = append(data.Autofill, af.Emit())
			}
		}
	}
	h.renderPage(w, tmpl.Title+" — ldapact", "create-form-content", data)
}

// CreateSubmit handles POST /api/template/{name}/create (F2 submit).
func (h *Handler) CreateSubmit(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	tmpl, err := h.loader.Load(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request: invalid form", http.StatusBadRequest)
		return
	}
	container := r.FormValue("container")
	if container == "" {
		container = h.client.BaseDN()
	}
	values := map[string]string{}
	for _, a := range tmpl.Attributes {
		if a.Hidden {
			continue
		}
		values[a.ID] = strings.TrimSpace(r.FormValue(a.ID))
	}

	errorsMap := validateRequired(tmpl, values)
	if len(errorsMap) > 0 {
		h.renderCreateErrors(w, r, tmpl, container, values, errorsMap)
		return
	}

	// Apply post hooks (e.g. PasswordEncrypt) after %var% substitution.
	mc := h.macroContext(r, values)
	mc.ParentDN = container
	for _, a := range tmpl.Attributes {
		for _, hook := range a.PostHooks {
			substituted := substituteValues(hook, values)
			res, err := tplengine.Evaluate(mc, substituted)
			if err != nil {
				h.logger.Error("post hook failed", "event", "tpl.post_failed", "attribute", a.ID, "error", err)
				http.Error(w, "Internal Server Error: template post hook failed", http.StatusInternalServerError)
				return
			}
			if s, ok := res.(string); ok {
				values[a.ID] = s
			}
		}
	}

	dn := buildDN(container, tmpl.RDN, values[tmpl.RDN])
	attrs := map[string][]string{"objectClass": tmpl.ObjectClasses}
	for id, v := range values {
		if v != "" {
			attrs[id] = []string{v}
		}
	}
	if h.client.Schema() != nil {
		h.client.Schema().CanonicalAttributes(attrs)
	}
	if err := h.client.Add(r.Context(), dn, attrs); err != nil {
		h.logger.Warn("create failed", "event", "ldap.error", "dn", dn, "error", err)
		errorsMap["_form"] = friendlyCreateError(err)
		h.renderCreateErrors(w, r, tmpl, container, values, errorsMap)
		return
	}
	h.audit(r, "ldap.create", dn, "add")
	w.Header().Set("X-Mutated-Subtree", container)
	h.renderPage(w, "Entry created — ldapact", "result-page", ResultData{
		Title:    "Entry created",
		Message:  fmt.Sprintf("Created %s", dn),
		Link:     "/api/entry/" + url.PathEscape(dn),
		LinkText: "View entry",
	})
}

func validateRequired(tmpl *tplengine.Template, values map[string]string) map[string]string {
	errs := map[string]string{}
	for _, a := range tmpl.RequiredAttributes() {
		if strings.TrimSpace(values[a.ID]) == "" {
			errs[a.ID] = "This field is required"
		}
	}
	return errs
}

func buildFormFields(tmpl *tplengine.Template) []FormField {
	var fields []FormField
	for _, a := range tmpl.Attributes {
		f := FormField{
			ID:       a.ID,
			Display:  a.Display,
			HelpText: a.HelpText,
			Kind:     a.Kind.String(),
			Readonly: a.Readonly,
			Hidden:   a.Hidden,
			Page:     a.Page,
		}
		switch {
		case a.Evaluated != nil && a.Evaluated.Kind == "picklist":
			f.Kind = "select"
			f.Values = a.Evaluated.Values
			f.NoMatches = a.Evaluated.NoMatches
			f.Notice = a.Evaluated.Notice
		case a.Evaluated != nil && a.Evaluated.Kind == "nextnumber":
			f.Value = a.Evaluated.Text
			f.MaxHit = a.Evaluated.MaxHit
			f.Notice = a.Evaluated.Notice
		case len(a.Values) > 0:
			f.Kind = "select"
			f.Values = a.Values
		default:
			f.Value = a.Default
		}
		fields = append(fields, f)
	}
	return fields
}

func (h *Handler) renderCreateErrors(w http.ResponseWriter, r *http.Request, tmpl *tplengine.Template, container string, values map[string]string, errs map[string]string) {
	mc := h.macroContext(r, values)
	mc.ParentDN = container
	_ = tmpl.EvaluateMacros(mc)
	data := CreateFormData{
		TemplateName:  tmpl.Name,
		Title:         tmpl.Title,
		Description:   tmpl.Description,
		ObjectClasses: tmpl.ObjectClasses,
		RDN:           tmpl.RDN,
		Container:     container,
		Pages:         tmpl.Pages,
		Errors:        errs,
	}
	for _, a := range tmpl.Attributes {
		f := buildFormFields(tmpl)[fieldIndex(tmpl, a.ID)]
		f.Value = values[a.ID]
		f.Error = errs[a.ID]
		data.Attributes = append(data.Attributes, f)
		for _, oc := range a.OnChange {
			if af, err := tplengine.ParseAutoFill(oc); err == nil {
				data.Autofill = append(data.Autofill, af.Emit())
			}
		}
	}
	h.renderPage(w, tmpl.Title+" — ldapact", "create-form-content", data)
}

func fieldIndex(tmpl *tplengine.Template, id string) int {
	for i, a := range tmpl.Attributes {
		if a.ID == id {
			return i
		}
	}
	return 0
}

func substituteValues(raw string, values map[string]string) string {
	for k, v := range values {
		raw = strings.ReplaceAll(raw, "%"+k+"%", v)
	}
	// Drop any remaining unresolvable %placeholders% (e.g. a commented-out
	// helper like %enc%) so macros see an empty argument.
	re := regexp.MustCompile(`%[A-Za-z][A-Za-z0-9_]*%`)
	raw = re.ReplaceAllString(raw, "")
	return raw
}

func buildDN(container, rdnAttr, rdnValue string) string {
	if container == "" {
		return rdnAttr + "=" + escapeRDNValue(rdnValue)
	}
	return rdnAttr + "=" + escapeRDNValue(rdnValue) + "," + container
}

func friendlyCreateError(err error) string {
	var lerr *ldapx.LDAPError
	if errors.As(err, &lerr) {
		switch lerr.Code {
		case 68:
			return "Entry already exists — choose a different RDN."
		case 65, 19, 20:
			return "The directory rejected the entry (schema violation). Check required attributes."
		}
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "objectclass"),
		strings.Contains(msg, "Object Class"), strings.Contains(msg, "schema"):
		return "The directory rejected the entry (schema violation). Check required attributes."
	default:
		return "The directory rejected the entry: " + msg
	}
}
