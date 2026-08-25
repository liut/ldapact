package tplengine

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// ServerFuncsAllowlist is the allowlist of php.* template functions (R8).
// Unknown functions fail at parse time (parser.go validateMacro).
var ServerFuncsAllowlist = map[string]bool{
	"PickList":                true,
	"GetNextNumber":           true,
	"PasswordEncrypt":         true,
	"PasswordEncryptionTypes": true,
	"HashPassword":            true,
	"RandomPassword":          true,
	"Join":                    true,
	"Default":                 true,
	"DN":                      true,
	"Encoded":                 true,
	"Escape":                  true,
	"Binary":                  true,
	"HasMultiples":            true,
	"MultiList":               true,
}

// MacroContext carries the render-time state for server macros.
type MacroContext struct {
	Ctx          context.Context
	Client       Searcher
	AutoSearcher Searcher // independent auto-number pool (R8 rebind); nil falls back to Client
	Logger       *slog.Logger
	BaseDN       string
	ParentDN     string // DN of the new entry's parent
	Values       map[string]string
	// PlainAllowed toggles the {PLAIN} write override (KTD 6).
	PlainAllowed bool
}

// Searcher is the LDAP surface the server macros need. *ldapx.Client
// implements it; unit tests use fakes.
type Searcher interface {
	Search(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error)
}

// EvaluateMacros runs server-side macros for every attribute whose single
// <value> is a macro reference (R8) and fills Helper value macros.
func (t *Template) EvaluateMacros(ctx *MacroContext) error {
	for _, a := range t.Attributes {
		if len(a.Values) == 1 && strings.HasPrefix(strings.TrimSpace(a.Values[0].ID), "=php.") {
			res, err := Evaluate(ctx, a.Values[0].ID)
			if err != nil {
				return fmt.Errorf("tplengine: attribute %q: %w", a.ID, err)
			}
			switch v := res.(type) {
			case *Evaluated:
				a.Evaluated = v
			case string:
				a.Evaluated = &Evaluated{Kind: "text", Text: v}
			default:
				return fmt.Errorf("tplengine: attribute %q: unexpected macro result %T", a.ID, res)
			}
			a.Values = nil
			continue
		}
		if a.Helper != nil {
			for i, hv := range a.Helper.Values {
				if strings.HasPrefix(strings.TrimSpace(hv.ID), "=php.") {
					res, err := Evaluate(ctx, hv.ID)
					if err != nil {
						return fmt.Errorf("tplengine: attribute %q helper: %w", a.ID, err)
					}
					if list, ok := res.([]Value); ok {
						a.Helper.Values = list
						break
					}
					a.Helper.Values[i] = Value{ID: fmt.Sprint(res), Display: fmt.Sprint(res)}
				}
			}
		}
	}
	return nil
}

// Evaluate dispatches a "=php.Func(a;b;c)" macro string.
func Evaluate(ctx *MacroContext, raw string) (any, error) {
	name := macroFuncName(raw)
	if !ServerFuncsAllowlist[name] {
		return nil, fmt.Errorf("tplengine: unknown server macro %q", name)
	}
	args := macroArgs(raw)
	switch name {
	case "PickList":
		return macroPickList(ctx, args)
	case "MultiList":
		return macroPickList(ctx, args)
	case "GetNextNumber":
		return macroGetNextNumber(ctx, args)
	case "PasswordEncrypt":
		return macroPasswordEncrypt(ctx, args)
	case "PasswordEncryptionTypes":
		return passwordEncryptionTypes(), nil
	case "HashPassword":
		if len(args) < 2 {
			return nil, errors.New("HashPassword requires scheme;password")
		}
		h, err := HashPassword(args[0], args[1])
		if err != nil {
			return nil, err
		}
		return h, nil
	case "RandomPassword":
		n := 12
		if len(args) > 0 {
			if parsed, err := strconv.Atoi(args[0]); err == nil && parsed > 0 {
				n = parsed
			}
		}
		return randomPassword(n), nil
	case "Join":
		if len(args) < 2 {
			return "", nil
		}
		parts := make([]string, 0, len(args)-1)
		for _, p := range args[1:] {
			if p != "" {
				parts = append(parts, p)
			}
		}
		return strings.Join(parts, args[0]), nil
	case "Default":
		if len(args) > 0 {
			return args[0], nil
		}
		return "", nil
	case "DN":
		return ctx.ParentDN, nil
	case "Encoded":
		if len(args) > 0 {
			return base64.StdEncoding.EncodeToString([]byte(args[0])), nil
		}
		return "", nil
	case "Escape":
		if len(args) > 0 {
			return ldap.EscapeFilter(args[0]), nil
		}
		return "", nil
	case "Binary":
		if len(args) > 0 {
			return args[0], nil
		}
		return "", nil
	case "HasMultiples":
		// %attr% substitution happens before macro parsing, so a multi-value
		// attribute reaches this function as multiple ;-separated args.
		if len(args) > 1 {
			return "1", nil
		}
		return "0", nil
	default:
		return nil, fmt.Errorf("tplengine: macro %q not implemented", name)
	}
}

// macroPickList implements PickList(base;filter;attr;display;size;max;nobutton;sortby).
// Zero candidates render as a free-text input with a notice (R8.x).
func macroPickList(ctx *MacroContext, args []string) (any, error) {
	if len(args) < 3 {
		return nil, errors.New("PickList requires base;filter;attr")
	}
	base := resolveDN(args[0], ctx.BaseDN)
	filter := strings.TrimSpace(args[1])
	if filter == "" {
		filter = "(objectClass=*)"
	}
	attr := strings.TrimSpace(args[2])
	display := ""
	if len(args) > 3 {
		display = strings.TrimSpace(args[3])
	}
	sortBy := attr
	if len(args) > 7 && strings.TrimSpace(args[7]) != "" {
		sortBy = strings.TrimSpace(args[7])
	}

	req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, []string{attr, sortBy}, nil)
	res, err := ctx.Client.Search(macroCtx(ctx), req)
	if err != nil {
		return nil, fmt.Errorf("PickList search: %w", err)
	}
	type row struct {
		value   string
		display string
		sortKey string
	}
	var rows []row
	for _, e := range res.Entries {
		val := e.GetAttributeValue(attr)
		if val == "" {
			continue
		}
		r := row{value: val, sortKey: e.GetAttributeValue(sortBy)}
		if display == "" {
			r.display = val
		} else {
			r.display = substitutePattern(display, entryValues(e))
		}
		rows = append(rows, r)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].sortKey < rows[j].sortKey })
	values := make([]Value, 0, len(rows))
	for _, r := range rows {
		values = append(values, Value{ID: r.value, Display: r.display})
	}
	if len(values) == 0 {
		if ctx.Logger != nil {
			ctx.Logger.Warn("PickList returned no candidates", "event", "tpl.picklist_empty", "base", base, "attr", attr)
		}
		return &Evaluated{Kind: "picklist", NoMatches: true, Notice: "未找到候选", Values: nil}, nil
	}
	return &Evaluated{Kind: "picklist", Values: values}, nil
}

// macroGetNextNumber implements GetNextNumber(base;attr;mode;filter;poolsize;startmin;max).
// Search mode fills the first gap; pool mode derives the next value from a
// filter that must match at most one entry. The race in pool mode is inherited
// from phpLDAPadmin: this macro is best-effort, never the sole source of
// uniqueness (see plan Risk table).
func macroGetNextNumber(ctx *MacroContext, args []string) (any, error) {
	if len(args) < 2 {
		return nil, errors.New("GetNextNumber requires base;attr")
	}
	base := resolveDN(args[0], ctx.BaseDN)
	attr := strings.TrimSpace(args[1])
	mode := "search"
	if len(args) > 2 && strings.TrimSpace(args[2]) != "" {
		mode = strings.ToLower(strings.TrimSpace(args[2]))
	}
	filter := "(objectClass=*)"
	if len(args) > 3 && strings.TrimSpace(args[3]) != "" {
		filter = strings.TrimSpace(args[3])
	}
	startMinProvided := false
	startMin := 1
	if len(args) > 5 && strings.TrimSpace(args[5]) != "" {
		startMinProvided = true
		if n, err := strconv.Atoi(strings.TrimSpace(args[5])); err == nil {
			startMin = n
		}
	}
	max := 65535
	if len(args) > 6 {
		if n, err := strconv.Atoi(strings.TrimSpace(args[6])); err == nil && n > 0 {
			max = n
		}
	}

	client := ctx.Client
	if ctx.AutoSearcher != nil {
		client = ctx.AutoSearcher
	}
	req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, []string{attr}, nil)
	res, err := client.Search(macroCtx(ctx), req)
	if err != nil {
		return nil, fmt.Errorf("GetNextNumber search: %w", err)
	}
	if mode == "pool" {
		if len(res.Entries) > 1 {
			return nil, errors.New("GetNextNumber pool filter matched more than one entry (R8)")
		}
		next := startMin
		if len(res.Entries) == 1 {
			next = startMin
			for _, v := range res.Entries[0].GetAttributeValues(attr) {
				if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n+1 > next {
					next = n + 1
				}
			}
		}
		if next > max {
			return &Evaluated{Kind: "nextnumber", MaxHit: true, Notice: "已达到配置上限，可手动指定数值", Text: strconv.Itoa(max)}, nil
		}
		return &Evaluated{Kind: "nextnumber", Text: strconv.Itoa(next)}, nil
	}
	used := make(map[int]bool)
	minUsed := 0
	for _, e := range res.Entries {
		for _, v := range e.GetAttributeValues(attr) {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				used[n] = true
				if minUsed == 0 || n < minUsed {
					minUsed = n
				}
			}
		}
	}
	// minNumber mirrors phpLDAPadmin: startmin when given, else smallest
	// existing value + 1 (or 1 when nothing exists).
	minNumber := 1
	if startMinProvided {
		minNumber = startMin
	} else if minUsed > 0 {
		minNumber = minUsed + 1
	}
	if minNumber > max {
		return &Evaluated{Kind: "nextnumber", MaxHit: true, Notice: "已达到配置上限，可手动指定数值", Text: strconv.Itoa(max)}, nil
	}
	next := minNumber
	for used[next] && next < max {
		next++
	}
	if next > max || (next == max && used[max]) {
		return &Evaluated{Kind: "nextnumber", MaxHit: true, Notice: "已达到配置上限，可手动指定数值", Text: strconv.Itoa(max)}, nil
	}
	return &Evaluated{Kind: "nextnumber", Text: strconv.Itoa(next)}, nil
}

func macroPasswordEncrypt(ctx *MacroContext, args []string) (any, error) {
	scheme := ""
	password := ""
	if len(args) > 0 {
		scheme = strings.TrimSpace(strings.ToUpper(args[0]))
	}
	if len(args) > 1 {
		password = args[1]
	}
	if scheme == "" {
		scheme = DefaultHashScheme
	}
	if password == "" {
		return "", nil
	}
	return HashPasswordWithOverride(scheme, password, ctx.PlainAllowed, ctx.Logger)
}

func passwordEncryptionTypes() []Value {
	types := []string{"SSHA512", "SSHA256", "SSHA", "SHA512", "SHA256", "ARGON2ID", "MD4", "MD5", "SHA", "CRYPT", "BLOWFISH"}
	values := make([]Value, 0, len(types))
	for _, s := range types {
		values = append(values, Value{ID: s, Display: s})
	}
	return values
}

func randomPassword(n int) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// resolveDN maps "/" (and empty) to the configured base DN.
func resolveDN(dn, base string) string {
	dn = strings.TrimSpace(dn)
	if dn == "" || dn == "/" {
		return base
	}
	return dn
}

// substitutePattern replaces %field% tokens with entry values (PickList
// display patterns like "%cn%").
func substitutePattern(pattern string, values map[string]string) string {
	var sb strings.Builder
	rest := pattern
	for {
		start := strings.Index(rest, "%")
		if start < 0 {
			sb.WriteString(rest)
			break
		}
		sb.WriteString(rest[:start])
		rest = rest[start+1:]
		end := strings.Index(rest, "%")
		if end < 0 {
			sb.WriteString("%")
			sb.WriteString(rest)
			break
		}
		key := strings.TrimSpace(rest[:end])
		if key != "" {
			sb.WriteString(values[strings.ToLower(key)])
		}
		rest = rest[end+1:]
	}
	return sb.String()
}

func entryValues(e *ldap.Entry) map[string]string {
	m := make(map[string]string, len(e.Attributes))
	for _, a := range e.Attributes {
		if len(a.Values) > 0 {
			m[strings.ToLower(a.Name)] = a.Values[0]
		}
	}
	return m
}

func macroCtx(ctx *MacroContext) context.Context {
	if ctx.Ctx != nil {
		return ctx.Ctx
	}
	return context.Background()
}
