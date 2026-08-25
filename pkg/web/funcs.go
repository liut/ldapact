package web

import (
	"errors"
	"fmt"
	"html/template"
	"strings"
)

// FuncMap returns the base template function registry. U6 fills it with the
// XML macro functions via Parse's extra argument.
func FuncMap() template.FuncMap {
	return template.FuncMap{
		"dict":     dict,
		"join":     strings.Join,
		"safeHTML": func(s string) template.HTML { return template.HTML(s) },
	}
}

// dict builds a map[string]any from alternating key/value arguments.
func dict(values ...any) (map[string]any, error) {
	if len(values)%2 != 0 {
		return nil, errors.New("web: dict requires key/value pairs")
	}
	m := make(map[string]any, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			return nil, fmt.Errorf("web: dict key %v is not a string", values[i])
		}
		m[key] = values[i+1]
	}
	return m, nil
}
