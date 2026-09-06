// Package pgsafe provides quoting and validation helpers for the few places
// where we must build PostgreSQL statements by string concatenation.
//
// Statements like ALTER ROLE and CREATE ROLE do not accept bind parameters for
// the role name or password, so those values have to be interpolated. Every
// such interpolation must go through this package.
package pgsafe

import (
	"errors"
	"strings"
)

// MaxIdentLen is PostgreSQL's NAMEDATALEN-1: identifiers are truncated past it.
const MaxIdentLen = 63

var (
	// ErrEmptyIdent is returned when an identifier is empty.
	ErrEmptyIdent = errors.New("identifier is empty")
	// ErrIdentTooLong is returned when an identifier exceeds MaxIdentLen bytes.
	ErrIdentTooLong = errors.New("identifier exceeds 63 bytes")
	// ErrIdentCharset is returned when an identifier contains characters
	// outside the allowed set.
	ErrIdentCharset = errors.New("identifier must match [A-Za-z_][A-Za-z0-9_$]*")
)

// QuoteIdent wraps an identifier in double quotes, doubling any embedded
// double quote. Callers should validate with ValidateIdent first; quoting
// alone is safe against statement injection but still permits surprising
// identifiers.
func QuoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// QuoteLiteral wraps a string in single quotes, doubling any embedded single
// quote, and prefixes the literal with E'' escaping when it contains a
// backslash so that standard_conforming_strings=off cannot change its meaning.
func QuoteLiteral(s string) string {
	quoted := `'` + strings.ReplaceAll(s, `'`, `''`) + `'`
	if strings.Contains(s, `\`) {
		return "E" + strings.ReplaceAll(quoted, `\`, `\\`)
	}
	return quoted
}

// ValidateIdent checks that s is usable as a role or database name. It is
// deliberately stricter than PostgreSQL itself: we would rather reject an
// unusual-but-legal name than reason about how it interacts with quoting.
func ValidateIdent(s string) error {
	if s == "" {
		return ErrEmptyIdent
	}
	if len(s) > MaxIdentLen {
		return ErrIdentTooLong
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
			// always allowed
		case (c >= '0' && c <= '9') || c == '$':
			if i == 0 {
				return ErrIdentCharset
			}
		default:
			return ErrIdentCharset
		}
	}
	return nil
}
