package entry

import (
	"net/http"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/tplengine"
	"github.com/liut/ldapact/pkg/tree"
)

// DetailData drives the F-Detail page.
type DetailData struct {
	DN             string
	RDN            string
	ObjectClasses  []string
	Crumbs         []tree.Crumb
	Attributes     []DetailAttr
	PasswordScheme string
	HasPassword    bool
	EditTemplate   string
}

// DetailAttr is one row of the attribute table.
type DetailAttr struct {
	Name   string
	Values []string
	// Kind is "image" when Values hold <img> src values (photo attributes),
	// "text" otherwise.
	Kind string
}

// Detail handles GET /entry/{dn...}.
func (h *Handler) Detail(w http.ResponseWriter, r *http.Request) {
	dn := r.PathValue("dn")
	if dn == "" {
		http.Error(w, "Bad Request: missing DN", http.StatusBadRequest)
		return
	}
	req := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"*"}, nil)
	res, err := h.client.Search(r.Context(), req)
	if err != nil {
		if isNotFound(err) {
			http.NotFound(w, r)
			return
		}
		h.logger.Error("entry detail search", "event", "ldap.error", "dn", dn, "error", err)
		http.Error(w, "Directory error", http.StatusBadGateway)
		return
	}
	if len(res.Entries) == 0 {
		http.NotFound(w, r)
		return
	}
	e := res.Entries[0]
	data := DetailData{
		DN:           e.DN,
		RDN:          rdnValue(e.DN),
		Crumbs:       tree.Breadcrumbs(e.DN, h.client.BaseDN(), 5),
		EditTemplate: "generic editor",
	}
	if tmpl, err := h.selectModificationTemplate(r, e); err != nil {
		h.logger.Warn("modification template lookup failed", "event", "tpl.load_failed", "dn", e.DN, "error", err)
	} else if tmpl != nil && tmpl.Title != "" {
		data.EditTemplate = tmpl.Title
	}
	data.ObjectClasses = append(data.ObjectClasses, e.GetAttributeValues("objectClass")...)
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, "objectClass") {
			continue
		}
		if strings.EqualFold(a.Name, "userPassword") && len(a.Values) > 0 {
			// The hash itself is directory data, but the UI follows
			// phpLDAPadmin's convention of not echoing password values.
			data.Attributes = append(data.Attributes, DetailAttr{Name: a.Name, Values: []string{"[redacted]"}})
			data.PasswordScheme = tplengine.DetectScheme(a.Values[0])
			data.HasPassword = true
			continue
		}
		if strings.EqualFold(a.Name, "jpegPhoto") {
			var srcs []string
			for i, v := range a.Values {
				if _, _, ok := photoBytes(v); ok {
					srcs = append(srcs, photoURL(e.DN, i))
				}
			}
			if len(srcs) > 0 {
				data.Attributes = append(data.Attributes, DetailAttr{Name: a.Name, Kind: "image", Values: srcs})
				continue
			}
			// Unrecognized photo data: never echo raw octets into the page.
			data.Attributes = append(data.Attributes, DetailAttr{Name: a.Name, Values: []string{"[binary]"}})
			continue
		}
		if strings.EqualFold(a.Name, "avatarPath") {
			var srcs []string
			for _, v := range a.Values {
				if imageURL(v) {
					srcs = append(srcs, strings.TrimSpace(v))
				}
			}
			if len(srcs) > 0 {
				data.Attributes = append(data.Attributes, DetailAttr{Name: a.Name, Kind: "image", Values: srcs})
				continue
			}
		}
		data.Attributes = append(data.Attributes, DetailAttr{Name: a.Name, Values: a.Values})
	}
	h.renderPage(w, r, e.DN+" — ldapact", "entry-detail-content", data)
}

// rdnValue returns the first RDN attribute value (label).
func rdnValue(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) == 0 {
		return dn
	}
	return parsed.RDNs[0].Attributes[0].Value
}
