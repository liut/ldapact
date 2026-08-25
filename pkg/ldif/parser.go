// Package ldif implements RFC 2849 LDIF parsing and writing for F4 (import)
// and F7 (export), with the R11 limits: bounded memory, per-entry error
// collection, and strict attribute value charset validation.
package ldif

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Options carries the R11 sanity caps.
type Options struct {
	MaxEntries       int
	MaxAttrsPerEntry int
	MaxValueBytes    int64
}

// DefaultOptions returns the R11 defaults: 100k entries, 1000 attributes per
// entry, 10 MiB per value.
func DefaultOptions() Options {
	return Options{MaxEntries: 100000, MaxAttrsPerEntry: 1000, MaxValueBytes: 10 << 20}
}

// Attribute is one attribute of an LDIF entry (name + values).
type Attribute struct {
	Name   string
	Values []string
}

// Entry is one parsed LDIF record.
type Entry struct {
	DN        string
	Attrs     []Attribute
	StartLine int
	Raw       string
}

// EntryError reports a single failed record while parsing continues (AE5).
type EntryError struct {
	Line int
	Err  error
	Raw  string
}

func (e *EntryError) Error() string {
	return fmt.Sprintf("line %d: %v", e.Line, e.Err)
}

// Iterator streams LDIF records with constant memory (plan's chaos-test
// requirement: no ReadAll of the full file).
type Iterator struct {
	r       *bufio.Reader
	opts    Options
	lineNo  int
	record  []string
	done    bool
	entries int
}

// NewIterator returns an iterator over r.
func NewIterator(r io.Reader, opts Options) *Iterator {
	return &Iterator{r: bufio.NewReaderSize(r, 64<<10), opts: opts}
}

// Next returns the next entry, or (nil, nil, io.EOF) at the end. A single
// malformed record yields (*EntryError, nil) and iteration continues.
func (it *Iterator) Next() (*Entry, *EntryError, error) {
	if it.done {
		return nil, nil, io.EOF
	}
	for {
		line, err := readLine(it.r, it.opts.MaxValueBytes+4096)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, nil, err
		}
		it.lineNo++
		trimmed := strings.TrimRight(line, "\r\n")

		switch {
		case strings.HasPrefix(trimmed, "#"):
			// Comment: not part of any record.
			continue
		case trimmed == "":
			if len(it.record) == 0 {
				if errors.Is(err, io.EOF) {
					it.done = true
					return nil, nil, io.EOF
				}
				continue
			}
			entry, perr := it.parseRecord()
			it.reset()
			if perr == nil {
				it.entries++
				if it.entries > it.opts.MaxEntries {
					return nil, nil, fmt.Errorf("ldif: entry count exceeds limit (%d)", it.opts.MaxEntries)
				}
			}
			if perr != nil {
				return nil, perr, nil
			}
			return entry, nil, nil
		case strings.HasPrefix(trimmed, " ") || strings.HasPrefix(trimmed, "\t"):
			// Continuation of the previous value line (RFC 2849 folding).
			if len(it.record) == 0 {
				it.record = append(it.record, trimmed)
			} else {
				it.record[len(it.record)-1] += "\n" + trimmed[1:]
			}
		default:
			it.record = append(it.record, trimmed)
		}
		if errors.Is(err, io.EOF) {
			// Flush the final record.
			if len(it.record) == 0 {
				it.done = true
				return nil, nil, io.EOF
			}
			entry, perr := it.parseRecord()
			it.reset()
			it.done = true
			if perr == nil {
				it.entries++
				if it.entries > it.opts.MaxEntries {
					return nil, nil, fmt.Errorf("ldif: entry count exceeds limit (%d)", it.opts.MaxEntries)
				}
			}
			if perr != nil {
				return nil, perr, nil
			}
			return entry, nil, nil
		}
	}
}

func (it *Iterator) reset() {
	it.record = it.record[:0]
}

// parseRecord converts the accumulated raw lines into an Entry.
func (it *Iterator) parseRecord() (*Entry, *EntryError) {
	startLine := it.lineNo - len(it.record)
	raw := strings.Join(it.record, "\n")
	perr := &EntryError{Line: startLine, Raw: raw}
	if len(it.record) == 0 {
		perr.Err = errors.New("empty record")
		return nil, perr
	}
	e := &Entry{StartLine: startLine, Raw: raw}
	for i, line := range it.record {
		if strings.HasPrefix(line, " ") {
			continue // continuation already merged
		}
		name, value, binary, err := splitLine(line)
		if err != nil {
			perr.Err = err
			return nil, perr
		}
		if strings.EqualFold(name, "dn") {
			if e.DN != "" {
				perr.Err = errors.New("duplicate dn")
				return nil, perr
			}
			v, err := decodeValue(value, binary)
			if err != nil {
				perr.Err = fmt.Errorf("dn: %w", err)
				return nil, perr
			}
			e.DN = v
			continue
		}
		if i == 0 && strings.EqualFold(name, "version") {
			// "version: 1" header — only valid as the first line.
			continue
		}
		if name == "" {
			perr.Err = errors.New("attribute line without name")
			return nil, perr
		}
		if !validAttrName(name) {
			perr.Err = fmt.Errorf("invalid attribute name %q", name)
			return nil, perr
		}
		v, err := decodeValue(value, binary)
		if err != nil {
			perr.Err = fmt.Errorf("%s: %w", name, err)
			return nil, perr
		}
		if len(e.Attrs) >= it.opts.MaxAttrsPerEntry {
			perr.Err = fmt.Errorf("attribute count exceeds limit (%d)", it.opts.MaxAttrsPerEntry)
			return nil, perr
		}
		if int64(len(v)) > it.opts.MaxValueBytes {
			perr.Err = fmt.Errorf("%s: value exceeds %d bytes", name, it.opts.MaxValueBytes)
			return nil, perr
		}
		appendAttr(e, name, v)
	}
	if e.DN == "" {
		perr.Err = errors.New("entry missing dn")
		return nil, perr
	}
	return e, nil
}

func appendAttr(e *Entry, name, value string) {
	for i := range e.Attrs {
		if strings.EqualFold(e.Attrs[i].Name, name) {
			e.Attrs[i].Values = append(e.Attrs[i].Values, value)
			return
		}
	}
	e.Attrs = append(e.Attrs, Attribute{Name: name, Values: []string{value}})
}

// splitLine parses "name:value", "name::base64", "name;<opt>:value".
// URL references ("name:<url") are rejected (R11 strict validation).
func splitLine(line string) (name, value string, binary bool, err error) {
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return "", "", false, errors.New("missing ':' separator (line is not folded)")
	}
	name = strings.TrimSpace(line[:colon])
	rest := line[colon+1:]
	switch {
	case strings.HasPrefix(rest, ":"):
		binary = true
		rest = rest[1:]
	case strings.HasPrefix(rest, "<"):
		return "", "", false, errors.New("URL value references are not supported")
	default:
	}
	rest = strings.TrimPrefix(rest, " ")
	return name, rest, binary, nil
}

func decodeValue(v string, binary bool) (string, error) {
	if binary {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
		if err != nil {
			return "", fmt.Errorf("invalid base64: %w", err)
		}
		return string(b), nil
	}
	if !utf8.ValidString(v) {
		return "", errors.New("value is not valid UTF-8")
	}
	return v, nil
}

func validAttrName(name string) bool {
	if name == "" {
		return false
	}
	// RFC 4512 attribute type: leading alpha, then alnum/hyphen, with
	// optional ";options" suffix.
	for i, r := range name {
		switch {
		case r == ';':
			return i > 0
		case r == '-' && i > 0:
			continue
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			continue
		default:
			return false
		}
	}
	return true
}

func readLine(r *bufio.Reader, maxBytes int64) (string, error) {
	var sb strings.Builder
	for {
		chunk, err := r.ReadString('\n')
		sb.WriteString(chunk)
		if int64(sb.Len()) > maxBytes {
			return "", fmt.Errorf("line exceeds maximum length (%d bytes)", maxBytes)
		}
		if err != nil {
			if errors.Is(err, io.EOF) && sb.Len() > 0 {
				return sb.String(), io.EOF
			}
			return sb.String(), err
		}
		if strings.HasSuffix(chunk, "\n") {
			return sb.String(), nil
		}
	}
}
