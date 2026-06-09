package api

import (
	"errors"
	"testing"

	"github.com/c-lgrant/tvault/internal/clierr"
)

func TestResolveField(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		key       string
		want      string
		wantKind  clierr.Kind
		wantError bool
	}{
		{
			name:  "string field happy path",
			value: `{"username":"admin","password":"secret123"}`,
			key:   "password",
			want:  "secret123",
		},
		{
			name:  "number field",
			value: `{"port":5432,"host":"db.local"}`,
			key:   "port",
			want:  "5432",
		},
		{
			name:  "boolean field",
			value: `{"enabled":true,"name":"feature"}`,
			key:   "enabled",
			want:  "true",
		},
		{
			name:  "object field",
			value: `{"config":{"nested":"value"},"name":"test"}`,
			key:   "config",
			want:  `{"nested":"value"}`,
		},
		{
			name:  "array field",
			value: `{"tags":["a","b","c"]}`,
			key:   "tags",
			want:  `["a","b","c"]`,
		},
		{
			name:      "missing key",
			value:     `{"username":"admin","password":"secret"}`,
			key:       "nonexistent",
			wantError: true,
			wantKind:  clierr.KindEmpty,
		},
		{
			name:      "not a JSON object",
			value:     `"plain string"`,
			key:       "foo",
			wantError: true,
			wantKind:  clierr.KindUser,
		},
		{
			name:      "malformed JSON",
			value:     `{not valid json}`,
			key:       "foo",
			wantError: true,
			wantKind:  clierr.KindUser,
		},
		{
			name:      "JSON array not object",
			value:     `["array","not","object"]`,
			key:       "foo",
			wantError: true,
			wantKind:  clierr.KindUser,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveField(tt.value, tt.key)
			if tt.wantError {
				if err == nil {
					t.Fatalf("ResolveField() expected error, got nil")
				}
				var ce *clierr.CLIError
				if !errors.As(err, &ce) {
					t.Fatalf("ResolveField() error is not *clierr.CLIError: %T", err)
				}
				if ce.Kind != tt.wantKind {
					t.Errorf("ResolveField() error Kind = %v, want %v", ce.Kind, tt.wantKind)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveField() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("ResolveField() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestToKV(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		want      string
		wantKind  clierr.Kind
		wantError bool
	}{
		{
			name:  "simple string fields sorted",
			value: `{"username":"admin","password":"secret","host":"db.local"}`,
			want:  "host=db.local\npassword=secret\nusername=admin\n",
		},
		{
			name:  "mixed types sorted",
			value: `{"port":5432,"enabled":true,"host":"localhost"}`,
			want:  "enabled=true\nhost=localhost\nport=5432\n",
		},
		{
			name:  "object and array values",
			value: `{"tags":["a","b"],"config":{"x":1},"name":"test"}`,
			want:  "config={\"x\":1}\nname=test\ntags=[\"a\",\"b\"]\n",
		},
		{
			name:  "empty object",
			value: `{}`,
			want:  "",
		},
		{
			name:      "not a JSON object",
			value:     `"plain string"`,
			wantError: true,
			wantKind:  clierr.KindUser,
		},
		{
			name:      "malformed JSON",
			value:     `{invalid}`,
			wantError: true,
			wantKind:  clierr.KindUser,
		},
		{
			name:      "JSON array not object",
			value:     `[1,2,3]`,
			wantError: true,
			wantKind:  clierr.KindUser,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToKV(tt.value)
			if tt.wantError {
				if err == nil {
					t.Fatalf("ToKV() expected error, got nil")
				}
				var ce *clierr.CLIError
				if !errors.As(err, &ce) {
					t.Fatalf("ToKV() error is not *clierr.CLIError: %T", err)
				}
				if ce.Kind != tt.wantKind {
					t.Errorf("ToKV() error Kind = %v, want %v", ce.Kind, tt.wantKind)
				}
				return
			}
			if err != nil {
				t.Fatalf("ToKV() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("ToKV() = %q, want %q", got, tt.want)
			}
		})
	}
}
