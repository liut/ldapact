package config

import "strings"

// passwordScheme is the LDAPADM_PASSWORD_SCHEME parse view. Its Decode
// normalizes whitespace and case at parse time, so Validate only sees the
// canonical uppercase form; an empty value is preserved and the engine
// default (SSHA512) applies downstream.
type passwordScheme string

// Decode implements envconfig.Decoder.
func (s *passwordScheme) Decode(value string) error {
	*s = passwordScheme(strings.ToUpper(strings.TrimSpace(value)))
	return nil
}
