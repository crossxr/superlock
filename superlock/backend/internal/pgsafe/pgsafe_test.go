package pgsafe

import "testing"

func TestValidateIdent(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		valid bool
	}{
		{"simple", "app_user", true},
		{"leading underscore", "_internal", true},
		{"digits after first", "nano_app_42", true},
		{"dollar after first", "role$1", true},
		{"max length", string(make([]byte, 0, 63)) + repeat("a", 63), true},

		{"empty", "", false},
		{"too long", repeat("a", 64), false},
		{"leading digit", "1role", false},
		{"leading dollar", "$role", false},
		{"hyphen", "app-user", false},
		{"space", "app user", false},
		{"double quote", `app"user`, false},
		{"single quote", "app'user", false},
		{"semicolon injection", "u; DROP DATABASE prod", false},
		{"quote-break injection", `u" WITH SUPERUSER --`, false},
		{"newline", "app\nuser", false},
		{"null byte", "app\x00user", false},
		{"non-ascii", "rôle", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateIdent(tc.in)
			if tc.valid && err != nil {
				t.Fatalf("ValidateIdent(%q) = %v, want nil", tc.in, err)
			}
			if !tc.valid && err == nil {
				t.Fatalf("ValidateIdent(%q) = nil, want error", tc.in)
			}
		})
	}
}

func TestQuoteIdent(t *testing.T) {
	tests := []struct{ in, want string }{
		{"app_user", `"app_user"`},
		{`we"ird`, `"we""ird"`},
		{`a"";b`, `"a"""";b"`},
	}
	for _, tc := range tests {
		if got := QuoteIdent(tc.in); got != tc.want {
			t.Errorf("QuoteIdent(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestQuoteLiteral(t *testing.T) {
	tests := []struct{ in, want string }{
		{"hunter2", `'hunter2'`},
		{"it's", `'it''s'`},
		{`'; DROP TABLE secrets; --`, `'''; DROP TABLE secrets; --'`},
		{`back\slash`, `E'back\\slash'`},
		{`both'\x`, `E'both''\\x'`},
	}
	for _, tc := range tests {
		if got := QuoteLiteral(tc.in); got != tc.want {
			t.Errorf("QuoteLiteral(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
