package docs

import (
	"html/template"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"platypus/internal/config"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("20-second.txt", "Second page\n\nBody.")
	// The plain-text conventions: a short lead line is a subheading, "- "
	// lines and runs of "term: text" lines are lists, everything else flows.
	write("10-first.txt", ""+
		"First page\n\n"+
		"Intro that spans\ntwo source lines and flows into one.\n\n"+
		"Patterns\nAn exact name.\n\n"+
		"Permissions\nlist: see it.\ncreate: make it.\n\n"+
		"Things to know:\n- one thing.\n- another thing.\n\n"+
		"A stray: line with a colon.\n\n"+
		"Paragraph two <b>not html</b>.\n")
	write("README.md", "ignored")

	library, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	pages := library.Pages()
	if len(pages) != 2 || pages[0].Slug != "first" || pages[1].Slug != "second" {
		t.Fatalf("pages = %+v", pages)
	}
	first, ok := library.Page("first")
	if !ok || first.Title != "First page" {
		t.Fatalf("first = %+v", first)
	}

	want := []Block{
		{Text: "Intro that spans two source lines and flows into one."},
		{Heading: "Patterns", Text: "An exact name."},
		{Heading: "Permissions", Items: []Item{{Term: "list", Text: "see it."}, {Term: "create", Text: "make it."}}},
		{Text: "Things to know:", Items: []Item{{Text: "one thing."}, {Text: "another thing."}}},
		{Text: "A stray: line with a colon."},
		{Text: "Paragraph two <b>not html</b>."},
	}
	if !slices.EqualFunc(first.Blocks, want, func(a, b Block) bool {
		return a.Heading == b.Heading && a.Text == b.Text && slices.Equal(a.Items, b.Items)
	}) {
		t.Errorf("blocks =\n%+v\nwant\n%+v", first.Blocks, want)
	}
}

func TestHTMLText(t *testing.T) {
	got := htmlText("Set PLATYPUS_REVEAL_HIDE_AFTER and AWS_REGION, in JSON too")
	want := template.HTML("Set <code>PLATYPUS_REVEAL_HIDE_AFTER</code> and <code>AWS_REGION</code>, in JSON too")
	if got != want {
		t.Errorf("htmlText = %q, want %q", got, want)
	}
	if escaped := htmlText("<b>bold</b>"); escaped != template.HTML("&lt;b&gt;bold&lt;/b&gt;") {
		t.Errorf("htmlText must escape: %q", escaped)
	}
}

// The generated configuration page renders as one table: every setting on
// the left, its description on the right. A guard, because this regressed
// three times as "a wall of text".
func TestConfigurationPageIsATable(t *testing.T) {
	library, err := Load("pages")
	if err != nil {
		t.Fatalf("load docs: %v", err)
	}
	page, ok := library.Page("configuration")
	if !ok {
		t.Fatal("the configuration page is missing")
	}
	best := Block{}
	for _, block := range page.Blocks {
		if len(block.Items) > len(best.Items) {
			best = block
		}
	}
	if len(best.Items) != len(config.Vars) {
		t.Fatalf("configuration table has %d rows, want one per variable (%d)", len(best.Items), len(config.Vars))
	}
	for _, entry := range best.Items {
		if !strings.HasPrefix(entry.Term, "PLATYPUS_") || entry.Text == "" {
			t.Errorf("row %q is not a setting with a description", entry.Term)
		}
		if entry.Meta == "" {
			t.Errorf("row %q has no default column", entry.Term)
		}
	}
}

func TestLoadRealDocs(t *testing.T) {
	library, err := Load("pages")
	if err != nil {
		t.Fatalf("the docs shipped with platypus don't load: %v", err)
	}
	if _, ok := library.Page("configuration"); !ok {
		t.Error("the generated configuration page is missing")
	}
}

func TestLoadRejectsBadNames(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Bad Name.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Error("a file with spaces in its name should be refused")
	}
}
