// Package references handles ${secret:KEY} interpolation within secret values.
package references

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// refPattern matches ${secret:KEY_NAME} with an optional env scope ${secret:KEY@env-id}
var refPattern = regexp.MustCompile(`\$\{secret:([A-Z0-9_]+)(?:@([a-f0-9-]+))?\}`)

// SecretFetcher is a function that retrieves a decrypted secret value by key and env.
type SecretFetcher func(ctx context.Context, envID uuid.UUID, key string) (string, error)

// Resolve replaces all ${secret:KEY} references in value with their resolved values.
// defaultEnvID is used when no @env-id is specified in the reference.
// maxDepth prevents circular reference infinite loops.
func Resolve(ctx context.Context, value string, defaultEnvID uuid.UUID, fetch SecretFetcher, maxDepth int) (string, error) {
	if maxDepth <= 0 {
		return value, fmt.Errorf("max reference depth exceeded — possible circular reference")
	}

	matches := refPattern.FindAllStringSubmatchIndex(value, -1)
	if len(matches) == 0 {
		return value, nil
	}

	var sb strings.Builder
	last := 0
	for _, m := range matches {
		// Write everything before this match
		sb.WriteString(value[last:m[0]])

		key := value[m[2]:m[3]]
		envID := defaultEnvID

		// If @env-id was specified
		if m[4] != -1 && m[5] != -1 {
			if parsedID, err := uuid.Parse(value[m[4]:m[5]]); err == nil {
				envID = parsedID
			}
		}

		resolved, err := fetch(ctx, envID, key)
		if err != nil {
			// Leave the reference unresolved rather than failing the whole call
			sb.WriteString(value[m[0]:m[1]])
		} else {
			// Recursively resolve references within the resolved value
			inner, err := Resolve(ctx, resolved, envID, fetch, maxDepth-1)
			if err != nil {
				sb.WriteString(resolved) // use unresolved inner on error
			} else {
				sb.WriteString(inner)
			}
		}
		last = m[1]
	}
	sb.WriteString(value[last:])
	return sb.String(), nil
}

// HasReferences returns true if value contains any ${secret:...} references.
func HasReferences(value string) bool {
	return refPattern.MatchString(value)
}

// ExtractRefs returns all referenced keys from a value.
func ExtractRefs(value string) []string {
	matches := refPattern.FindAllStringSubmatch(value, -1)
	keys := make([]string, 0, len(matches))
	for _, m := range matches {
		keys = append(keys, m[1])
	}
	return keys
}
