package ref

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		in         string
		defaultEco string
		wantEco    string
		wantName   string
		wantVer    string
		wantErr    bool
	}{
		{"npm:lodash", "", "npm", "lodash", "", false},
		{"npm:lodash@4.17.21", "", "npm", "lodash", "4.17.21", false},
		{"npm:", "", "", "", "", true},
		{"lodash", "npm", "npm", "lodash", "", false},
		{"pypi:requests", "", "PyPI", "requests", "", false},
		{"@scope/pkg", "", "npm", "@scope/pkg", "", false},
		{"", "npm", "", "", "", true},
		{"lodash", "", "", "", "", true},
	}

	for _, tc := range tests {
		got, err := Parse(tc.in, tc.defaultEco)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("Parse(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.in, err)
		}
		if got.Ecosystem != tc.wantEco {
			t.Fatalf("Parse(%q) ecosystem = %q, want %q", tc.in, got.Ecosystem, tc.wantEco)
		}
		if got.Name != tc.wantName {
			t.Fatalf("Parse(%q) name = %q, want %q", tc.in, got.Name, tc.wantName)
		}
		if got.Version != tc.wantVer {
			t.Fatalf("Parse(%q) version = %q, want %q", tc.in, got.Version, tc.wantVer)
		}
	}
}
