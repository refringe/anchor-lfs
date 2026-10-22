package sanitise

import "testing"

func TestEndpoint(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple path", "/org/repo", "org_repo"},
		{"no leading slash", "org/repo", "org_repo"},
		{"multiple slashes", "/org/repo/extra", "org_repo_extra"},
		{"single segment", "/myrepo", "myrepo"},
		{"hyphens and underscores", "/my-org/my_repo", "my-org_my_repo"},
		{"alphanumeric", "/org123/repo456", "org123_repo456"},
		{"backslash separators", `org\repo`, "org_repo"},
		{"dot traversal", "/../etc/passwd", InvalidEndpoint},
		{"double dot", "..", InvalidEndpoint},
		{"single dot", ".", InvalidEndpoint},
		{"embedded traversal", "/org/../secret", InvalidEndpoint},
		{"space in path", "/org/my repo", InvalidEndpoint},
		{"special characters", "/org/repo@v2", InvalidEndpoint},
		{"dots in names", "/my.org/repo.js", "my.org_repo.js"},
		{"git suffix and info path", "/org/repo.git/info/lfs", "org_repo.git_info_lfs"},
		{"dot inside a later segment", "/org/.github", "org_.github"},
		{"leading dot", "/.hidden/repo", InvalidEndpoint},
		{"dot-only segment", "/org/./repo", InvalidEndpoint},
		{"dot-dot segment after backslash", `org\..\repo`, InvalidEndpoint},
		{"trailing dot-dot", "/org/..", InvalidEndpoint},
		{"triple dot segment", "/org/.../repo", "org_..._repo"},
		{"unicode", "/org/r\u00e9po", InvalidEndpoint},
		{"empty string", "", InvalidEndpoint},
		{"only slashes", "///", InvalidEndpoint},
		{"null byte", "/org/repo\x00evil", InvalidEndpoint},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Endpoint(tt.input)
			if got != tt.want {
				t.Errorf("Endpoint(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
