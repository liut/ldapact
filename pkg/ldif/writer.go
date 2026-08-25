package ldif

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const foldWidth = 76

// Writer emits RFC 2849 LDIF records: "::" base64 for binary/unsafe values
// and long-line folding.
type Writer struct {
	w *bufio.Writer
}

// NewWriter returns a writer wrapping w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: bufio.NewWriter(w)}
}

// WriteEntry writes one entry (with a leading blank line separating records
// after the first).
func (wr *Writer) WriteEntry(e *Entry) error {
	if e.DN == "" {
		return fmt.Errorf("ldif: entry without dn")
	}
	if err := wr.writeLine("dn", e.DN, needsBase64(e.DN)); err != nil {
		return err
	}
	for _, a := range e.Attrs {
		for _, v := range a.Values {
			binary := needsBase64(v) || strings.Contains(strings.ToLower(a.Name), ";binary")
			if err := wr.writeLine(a.Name, v, binary); err != nil {
				return err
			}
		}
	}
	wr.w.WriteByte('\n')
	return wr.w.Flush()
}

// writeLine emits "name: value" (or "name:: base64"), folding at foldWidth.
func (wr *Writer) writeLine(name, value string, binary bool) error {
	var line string
	if binary {
		line = name + ":: " + base64.StdEncoding.EncodeToString([]byte(value))
	} else {
		line = name + ": " + value
	}
	return wr.fold(line)
}

func (wr *Writer) fold(line string) error {
	for len(line) > foldWidth {
		cut := foldWidth
		// Prefer breaking at a space to avoid splitting multi-byte runes.
		for cut > 0 && line[cut-1] != ' ' && cut < foldWidth+20 {
			cut++
		}
		if cut > len(line) {
			cut = len(line)
		}
		if _, err := wr.w.WriteString(line[:cut] + "\n "); err != nil {
			return err
		}
		line = line[cut:]
	}
	_, err := wr.w.WriteString(line + "\n")
	return err
}

// needsBase64 reports whether a value must be base64-encoded per RFC 2849:
// non-UTF-8 bytes, or characters that would break LDIF line structure.
func needsBase64(v string) bool {
	if !utf8.ValidString(v) {
		return true
	}
	for _, r := range v {
		if r == '\n' || r == '\r' {
			return true
		}
	}
	if strings.HasPrefix(v, " ") || strings.HasPrefix(v, ":") {
		return true
	}
	return false
}
