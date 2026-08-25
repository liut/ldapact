package tree

import (
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Crumb is one breadcrumb link.
type Crumb struct {
	DN    string
	Label string
}

// Ellipsis marks a collapsed middle section in a deep trail.
const Ellipsis = "…"

// Breadcrumbs builds the ancestor trail for dn, root first, stopping at the
// configured base DN (the naming-context root is a single crumb). Deep trails
// (more than maxVisible ancestors) collapse the middle: first 3 + ellipsis +
// last 2 (F1 deep state).
func Breadcrumbs(dn, baseDN string, maxVisible int) []Crumb {
	if maxVisible <= 0 {
		maxVisible = 5
	}
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return []Crumb{{DN: dn, Label: dn}}
	}

	// Walk from the leaf up, stripping one RDN at a time.
	labels := make([]string, 0, len(parsed.RDNs))
	dns := make([]string, 0, len(parsed.RDNs))
	current := dn
	for range parsed.RDNs {
		labels = append(labels, rdnLabel(current))
		dns = append(dns, current)
		if strings.EqualFold(current, baseDN) {
			break
		}
		idx := strings.Index(current, ",")
		if idx < 0 {
			break
		}
		current = current[idx+1:]
	}

	// Reverse to root-first.
	var crumbs []Crumb
	for i := len(labels) - 1; i >= 0; i-- {
		crumbs = append(crumbs, Crumb{DN: dns[i], Label: labels[i]})
	}
	if len(crumbs) <= maxVisible {
		return crumbs
	}

	// Collapse the middle.
	first := crumbs[:3]
	last := crumbs[len(crumbs)-2:]
	collapsed := append([]Crumb{}, first...)
	collapsed = append(collapsed, Crumb{DN: "", Label: Ellipsis})
	return append(collapsed, last...)
}
