package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every form declares how it submits natively. A form that relies on htmx
// alone would, without JavaScript, submit as GET and put its fields in the
// URL — values included. This guard makes that impossible to reintroduce.
func TestEveryFormDeclaresItsMethod(t *testing.T) {
	formTag := regexp.MustCompile(`(?s)<form([^>]*)>`)
	files, err := filepath.Glob("templates/*.html")
	if err != nil || len(files) == 0 {
		t.Fatalf("no templates found: %v", err)
	}
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range formTag.FindAllStringSubmatch(string(content), -1) {
			attrs := match[1]
			if strings.Contains(attrs, "hx-post") && !strings.Contains(attrs, `method="post"`) {
				t.Errorf("%s: a form with hx-post must also declare method=\"post\": %s", file, strings.TrimSpace(attrs))
			}
			if !strings.Contains(attrs, "method=") {
				t.Errorf("%s: form without a method submits as GET: %s", file, strings.TrimSpace(attrs))
			}
		}
	}
}
