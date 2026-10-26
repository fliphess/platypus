package textclean

import (
	"strings"
	"testing"
)

func TestClean(t *testing.T) {
	tests := []struct {
		name string
		in   string
		opts Options
		want string
	}{
		{"plain text stays", "DO NOT CHANGE THIS PARAM", Options{}, "DO NOT CHANGE THIS PARAM"},
		{"script removed", `hello <script>alert(1)</script>world`, Options{}, "hello world"},
		{"tags removed, text kept", `<b>bold</b> and <a href="x">link</a>`, Options{}, "bold and link"},
		{"event handlers removed", `<img src=x onerror=alert(1)>text`, Options{}, "text"},
		{"encoded tags removed", `&lt;script&gt;alert(1)&lt;/script&gt;ok`, Options{}, "ok"},
		{"comparison survives", "a < b and c > d", Options{}, "a < b and c > d"},
		{"ampersand survives", "Tom & Jerry", Options{}, "Tom & Jerry"},
		{"newlines kept when multiline", "line 1\r\nline 2", Options{Multiline: true}, "line 1\nline 2"},
		{"newlines flattened otherwise", "line 1\nline 2", Options{}, "line 1 line 2"},
		{"control characters dropped", "a\x00b\x07c", Options{}, "abc"},
		{"direction overrides dropped", "abc\u202edef\u2066", Options{}, "abcdef"},
		{"trimmed", "  padded \n", Options{}, "padded"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Clean(tt.in, tt.opts)
			if err != nil {
				t.Fatalf("Clean error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Clean(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCleanRejects(t *testing.T) {
	if _, err := Clean(strings.Repeat("é", 11), Options{MaxLength: 10}); err == nil || !strings.Contains(err.Error(), "at most 10") {
		t.Errorf("too long: err = %v", err)
	}
	if _, err := Clean(strings.Repeat("é", 10), Options{MaxLength: 10}); err != nil {
		t.Errorf("length must count characters, not bytes: %v", err)
	}
	if _, err := Clean("bad \xff utf8", Options{}); err == nil {
		t.Error("invalid UTF-8 should be rejected")
	}
}

func FuzzCleanRemovesTags(f *testing.F) {
	for _, seed := range []string{"<script>x</script>", "&lt;b&gt;", "a<b", "<<script>>", "<img onerror=x>"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out, err := Clean(in, Options{Multiline: true})
		if err != nil {
			return
		}
		lower := strings.ToLower(out)
		if strings.Contains(lower, "<script") || strings.Contains(lower, "<img") {
			t.Fatalf("Clean(%q) = %q still contains a tag", in, out)
		}
	})
}
