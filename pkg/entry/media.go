package entry

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
)

// maxPhotoBytes caps how large a photo value the photo endpoint serves.
const maxPhotoBytes = 5 * 1024 * 1024

// photoBytes resolves a jpegPhoto attribute value to raw image bytes and a
// mime type, accepting raw binary octets (LDAP binary transfer) or base64
// text stored in the directory. ok is false when the value is not a
// recognized image.
func photoBytes(v string) (raw []byte, mime string, ok bool) {
	if m := imageMime([]byte(v)); m != "" {
		return []byte(v), m, true
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil || len(decoded) == 0 {
		return nil, "", false
	}
	if m := imageMime(decoded); m != "" {
		return decoded, m, true
	}
	return nil, "", false
}

// photoURL builds the relative <img> src for one stored photo value. Pages
// reference the photo endpoint instead of embedding data: URIs, which
// html/template rejects in URL attributes (anti-XSS).
func photoURL(dn string, idx int) string {
	return "/api/entry/" + url.PathEscape(dn) + "/photo?idx=" + strconv.Itoa(idx)
}

// imageMime sniffs common image magic bytes (JPEG/PNG/GIF/WebP).
func imageMime(b []byte) string {
	switch {
	case len(b) >= 3 && b[0] == 0xff && b[1] == 0xd8 && b[2] == 0xff:
		return "image/jpeg"
	case len(b) >= 8 && bytes.Equal(b[:8], []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}):
		return "image/png"
	case len(b) >= 6 && bytes.Equal(b[:6], []byte{'G', 'I', 'F', '8', '7', 'a'}):
		return "image/gif"
	case len(b) >= 6 && bytes.Equal(b[:6], []byte{'G', 'I', 'F', '8', '9', 'a'}):
		return "image/gif"
	case len(b) >= 12 && bytes.Equal(b[:4], []byte{0x52, 0x49, 0x46, 0x46}) && bytes.Equal(b[8:12], []byte{'W', 'E', 'B', 'P'}):
		return "image/webp"
	default:
		return ""
	}
}

// imageURL reports whether a value can be used directly as an <img> src:
// an http(s) URL, an absolute or relative path, or an existing data: URI,
// without whitespace or control characters.
func imageURL(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	lower := strings.ToLower(v)
	switch {
	case strings.HasPrefix(lower, "http://"),
		strings.HasPrefix(lower, "https://"),
		strings.HasPrefix(lower, "data:image/"),
		strings.HasPrefix(v, "/"),
		strings.HasPrefix(v, "./"):
	default:
		return false
	}
	for _, r := range v {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
