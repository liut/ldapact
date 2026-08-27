package entry

import (
	"net/http"
	"strconv"

	"github.com/go-ldap/ldap/v3"
)

// Photo serves a stored jpegPhoto value as an image response so pages can
// reference it with a relative URL. Only recognized image data is served;
// raw octets or base64 text are both accepted (see photoBytes).
func (h *Handler) Photo(w http.ResponseWriter, r *http.Request) {
	dn := r.PathValue("dn")
	idx := 0
	if raw := r.URL.Query().Get("idx"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
			idx = n
		}
	}
	req := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"jpegPhoto"}, nil)
	res, err := h.client.Search(r.Context(), req)
	if err != nil {
		h.dnError(w, r, err)
		return
	}
	if len(res.Entries) == 0 {
		http.NotFound(w, r)
		return
	}
	vals := res.Entries[0].GetAttributeValues("jpegPhoto")
	if idx < 0 || idx >= len(vals) {
		http.NotFound(w, r)
		return
	}
	raw, mime, ok := photoBytes(vals[idx])
	if !ok || len(raw) > maxPhotoBytes {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	w.Header().Set("Cache-Control", "private, max-age=300")
	if _, err := w.Write(raw); err != nil {
		h.logger.Warn("photo write failed", "event", "web.write_failed", "dn", dn, "error", err)
	}
}
