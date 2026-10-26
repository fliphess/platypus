package web

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The page size is a closed list: a crafted request can never ask for zero
// rows or a million, and the default is 50.
func TestPageSizeIsAClosedList(t *testing.T) {
	cases := map[string]int{
		"":               DefaultPageSize,
		"?per_page=10":   10,
		"?per_page=1000": 1000,
		"?per_page=999":  DefaultPageSize,
		"?per_page=0":    DefaultPageSize,
		"?per_page=-5":   DefaultPageSize,
		"?per_page=abc":  DefaultPageSize,
	}
	for query, want := range cases {
		r := httptest.NewRequest("GET", "/ssm"+query, nil)
		if got := pageSize(r); got != want {
			t.Errorf("pageSize(%q) = %d, want %d", query, got, want)
		}
	}
}

func TestPageNumberFloorsAtOne(t *testing.T) {
	for query, want := range map[string]int{"": 1, "?page=3": 3, "?page=0": 1, "?page=-2": 1, "?page=x": 1} {
		r := httptest.NewRequest("GET", "/ssm"+query, nil)
		if got := pageNumber(r); got != want {
			t.Errorf("pageNumber(%q) = %d, want %d", query, got, want)
		}
	}
}

// Links keep the filters, carry the page size only when it is not the
// default, and never carry a stale page number into the pager's own form.
func TestPagerLinksKeepFilters(t *testing.T) {
	values := url.Values{"q": {"payments"}, "per_page": {"20"}, "page": {"2"}}

	next := string(listURL("/ssm", values, 3, 20))
	if !strings.Contains(next, "q=payments") || !strings.Contains(next, "page=3") || !strings.Contains(next, "per_page=20") {
		t.Errorf("next link lost something: %s", next)
	}
	same := string(listURL("/ssm", values, 1, DefaultPageSize))
	if strings.Contains(same, "per_page=") || strings.Contains(same, "page=") {
		t.Errorf("default page size should not be in the URL: %s", same)
	}

	p := newPager("/ssm", "#results", "1–50 of 60", values, 1, 2, DefaultPageSize, 60)
	if p.PrevLink != "" {
		t.Errorf("the first page has a previous link: %s", p.PrevLink)
	}
	if p.NextLink == "" {
		t.Error("the first of two pages has no next link")
	}
	hidden := string(p.Hidden)
	if !strings.Contains(hidden, `name="q"`) || strings.Contains(hidden, `name="page"`) || strings.Contains(hidden, `name="per_page"`) {
		t.Errorf("the page-size form carries the wrong filters: %s", hidden)
	}
}

// Values in hidden inputs are escaped: they come from the query string.
func TestPagerEscapesHiddenFilters(t *testing.T) {
	values := url.Values{"q": {`"><script>alert(1)</script>`}}
	p := newPager("/ssm", "#results", "", values, 1, 2, DefaultPageSize, 1)
	if strings.Contains(string(p.Hidden), "<script>") {
		t.Errorf("a filter value escaped into HTML: %s", p.Hidden)
	}
}
