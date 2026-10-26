// Package docs loads the documentation shown in the app: plain text files in
// a directory, one page per file. There is no markup and no HTML; the web
// layer escapes everything.
//
// File names set the order and the URL: "10-getting-started.txt" becomes the
// page "getting-started". The first line of a file is its title; blank lines
// separate paragraphs.
package docs

import (
	"fmt"
	"html"
	"html/template"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Page is one documentation page.
type Page struct {
	Slug   string
	Title  string
	Blocks []Block
}

// Block is one rendered piece of a page: an optional subheading, optional
// flowing text, and an optional list. The plain-text sources carry their
// structure by convention (no markup): a short first line without sentence
// punctuation is a subheading, lines starting with "- " are list items, and
// runs of "term: text" lines are lists with the term bolded.
type Block struct {
	Heading string
	Text    string
	Items   []Item
}

// Item is one entry of a list.
type Item struct {
	// Term is the part before the colon ("list: see the item in lists"),
	// shown bold. Empty for "- " bullets.
	Term string
	// Meta is a short middle column (the default of a setting), when the
	// row is written as "term | meta | text".
	Meta string
	Text string
}

// Library holds all pages in order.
type Library struct {
	pages []Page
}

var fileName = regexp.MustCompile(`^(?:\d+-)?([a-z0-9-]+)\.txt$`)

// Load reads every .txt file in dir.
func Load(dir string) (*Library, error) {
	fsys := os.DirFS(dir)
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("read docs directory: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".txt") {
			names = append(names, entry.Name())
		}
	}
	slices.Sort(names)

	library := &Library{}
	for _, name := range names {
		match := fileName.FindStringSubmatch(name)
		if match == nil {
			return nil, fmt.Errorf("docs file %q: use names like 10-topic-name.txt", name)
		}
		content, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("read docs file: %w", err)
		}
		page, err := parse(match[1], string(content))
		if err != nil {
			return nil, fmt.Errorf("docs file %q: %w", name, err)
		}
		library.pages = append(library.pages, page)
	}
	return library, nil
}

// itemLine matches a "term: text" line whose term is short and plain.
var itemLine = regexp.MustCompile(`^[-\w &(]{1,40}:\s+(\S.*)$`)

// isHeading reports whether a line works as a subheading: short, one line,
// and not ending like a sentence or a lead-in to a list.
func isHeading(line string) bool {
	if line == "" || utf8.RuneCountInString(line) > 60 {
		return false
	}
	last, _ := utf8.DecodeLastRuneInString(line)
	return !strings.ContainsRune(".:!?", last)
}

// envToken matches identifiers that read like environment variables or
// settings: PLATYPUS_SOMETHING, AWS_REGION, PLATYPUS_REVEAL_HIDE_AFTER.
var envToken = regexp.MustCompile(`\b(?:PLATYPUS_[A-Z0-9_]+|[A-Z][A-Z0-9]*_[A-Z0-9_]+)\b`)

// htmlText renders flowing text for the page: escaped, with setting names
// shown as inline code so they are recognisable as names rather than
// shouting. The text is escaped first and the tokens (which contain nothing
// escapable) are wrapped afterwards, so nothing user-supplied runs.
func htmlText(text string) template.HTML {
	escaped := html.EscapeString(text)
	//nolint:gosec // escaped above; the wrapped tokens are [A-Z0-9_] only
	return template.HTML(envToken.ReplaceAllString(escaped, "<code>$0</code>"))
}

// HTMLText is htmlText for the templates.
func HTMLText(text string) template.HTML { return htmlText(text) }

// parse splits a page into its title and rendered blocks. Blank lines
// separate blocks; within a block, source line breaks mean nothing (text
// flows at the reader's window) except the list conventions above.
func parse(slug, content string) (Page, error) {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	title, body, _ := strings.Cut(content, "\n")
	title = strings.TrimSpace(title)
	if title == "" {
		return Page{}, fmt.Errorf("the first line must be the title")
	}
	page := Page{Slug: slug, Title: title}
	for raw := range strings.SplitSeq(body, "\n\n") {
		if block := parseBlock(raw); block != nil {
			page.Blocks = append(page.Blocks, *block)
		}
	}
	return page, nil
}

// headingAt reports whether the first line of a block is a subheading:
// unindented, short, not ending like a sentence or a lead-in to a list.
// Indented lines below (as in the generated configuration page) always mean
// deliberate structure; otherwise a continuation starting in lowercase is a
// hard-wrapped sentence, not a heading.
func headingAt(lines []string) (string, bool) {
	first := lines[0]
	if len(lines) < 2 || first != strings.TrimSpace(first) || !isHeading(first) {
		return "", false
	}
	next := -1
	for i, line := range lines[1:] {
		if strings.TrimSpace(line) != "" {
			next = i + 1
			break
		}
	}
	if next < 0 {
		return "", false
	}
	if strings.HasPrefix(lines[next], " ") || strings.HasPrefix(lines[next], "\t") {
		return strings.TrimSpace(first), true
	}
	trimmed := strings.TrimSpace(lines[next])
	if r, _ := utf8.DecodeRuneInString(trimmed); !unicode.IsLower(r) {
		return strings.TrimSpace(first), true
	}
	// Lowercase continuation: a wrapped sentence, unless a list opens right
	// under the heading ("Permissions\nlist: ...").
	if itemish(trimmed) && next+1 < len(lines) && itemish(strings.TrimSpace(lines[next+1])) {
		return strings.TrimSpace(first), true
	}
	return "", false
}

func itemish(line string) bool {
	return strings.HasPrefix(line, "- ") || isItem(line)
}

func parseBlock(raw string) *Block {
	lines := strings.Split(strings.Trim(raw, "\n"), "\n")
	block := &Block{}
	if heading, ok := headingAt(lines); ok {
		block.Heading = heading
		lines = lines[1:]
	}

	// A "term: text" line is a list entry only in company: with another such
	// line or a bullet next to it. A single one is ordinary prose.
	itemRun := make([]bool, len(lines))
	for i, line := range lines {
		if !isItem(line) {
			continue
		}
		neighbour := (i > 0 && (isItem(lines[i-1]) || strings.HasPrefix(strings.TrimSpace(lines[i-1]), "- "))) ||
			(i+1 < len(lines) && (isItem(lines[i+1]) || strings.HasPrefix(strings.TrimSpace(lines[i+1]), "- ")))
		itemRun[i] = neighbour
	}

	var flowing []string
	flush := func() {
		if text := strings.Join(strings.Fields(strings.Join(flowing, " ")), " "); text != "" {
			block.Text = strings.TrimSpace(block.Text + " " + text)
		}
		flowing = nil
	}

	for i, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "- "):
			flush()
			block.Items = append(block.Items, Item{Text: strings.TrimSpace(line[2:])})
		case itemRun[i]:
			flush()
			if parts := strings.Split(line, " | "); len(parts) == 3 {
				block.Items = append(block.Items, Item{
					Term: strings.TrimSpace(parts[0]), Meta: strings.TrimSpace(parts[1]), Text: strings.TrimSpace(parts[2]),
				})
				continue
			}
			term, text, _ := strings.Cut(line, ":")
			block.Items = append(block.Items, Item{Term: strings.TrimSpace(term), Text: strings.TrimSpace(text)})
		default:
			flowing = append(flowing, line)
		}
	}
	flush()

	if block.Heading == "" && block.Text == "" && block.Items == nil {
		return nil
	}
	return block
}

// isItem reports whether a line is a "term: text" or "term | meta | text"
// entry.
func isItem(line string) bool {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "- ") {
		return false
	}
	if len(strings.Split(line, " | ")) == 3 {
		return true
	}
	return itemLine.MatchString(line)
}

// Pages returns all pages in order.
func (l *Library) Pages() []Page {
	return l.pages
}

// Page returns the page with the given slug.
func (l *Library) Page(slug string) (Page, bool) {
	for _, page := range l.pages {
		if page.Slug == slug {
			return page, true
		}
	}
	return Page{}, false
}
