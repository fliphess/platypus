package web

import (
	"html/template"
	"net/http"
	"net/url"
	"strconv"
)

// DefaultPageSize is how many rows a list shows unless asked otherwise.
const DefaultPageSize = 50

// pageSizes are the sizes every list offers. A request can only pick one of
// these, so ?per_page= can never ask for zero or a million rows.
var pageSizes = []int{10, 20, 50, 100, 200, 500, 1000}

// pageSize reads ?per_page=, falling back to the default for anything else.
func pageSize(r *http.Request) int {
	requested, err := strconv.Atoi(r.URL.Query().Get("per_page"))
	if err != nil {
		return DefaultPageSize
	}
	for _, size := range pageSizes {
		if size == requested {
			return size
		}
	}
	return DefaultPageSize
}

// pageNumber reads ?page=, with 1 as the floor.
func pageNumber(r *http.Request) int {
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		return 1
	}
	return page
}

// pager is everything a list needs to show where it is and to change the page
// size. One struct and one template, shared by every list.
type pager struct {
	Action   string
	Target   string
	Summary  string
	Page     int
	LastPage int
	PerPage  int
	Sizes    []int
	PrevLink template.URL
	NextLink template.URL
	// Hidden keeps the list's filters in the page-size form.
	Hidden template.HTML
}

// listValues are the filter values a list keeps in its links.
func listValues(values url.Values) url.Values {
	kept := url.Values{}
	for key, list := range values {
		if key == "page" || key == "per_page" {
			continue
		}
		kept[key] = append([]string(nil), list...)
	}
	return kept
}

// listURL builds a link to another page, keeping the filters and page size.
func listURL(path string, values url.Values, page, perPage int) template.URL {
	query := listValues(values)
	if page > 1 {
		query.Set("page", strconv.Itoa(page))
	}
	if perPage != DefaultPageSize {
		query.Set("per_page", strconv.Itoa(perPage))
	}
	if len(query) == 0 {
		return template.URL(path) //nolint:gosec // path is built from constants, never the request
	}
	return template.URL(path + "?" + query.Encode()) //nolint:gosec // encoded above
}

// hiddenFilters renders the filter inputs the page-size form must carry over.
func hiddenFilters(values url.Values) template.HTML {
	var out template.HTML
	for key, list := range listValues(values) {
		for _, value := range list {
			if value == "" {
				continue
			}
			//nolint:gosec // both parts escaped
			out += template.HTML(`<input type="hidden" name="` + template.HTMLEscapeString(key) +
				`" value="` + template.HTMLEscapeString(value) + `">`)
		}
	}
	return out
}

// newPager assembles the controls for a list page.
func newPager(path, target, summary string, values url.Values, page, lastPage, perPage int) pager {
	p := pager{
		Action: path, Target: target, Summary: summary,
		Page: page, LastPage: max(lastPage, 1), PerPage: perPage,
		Sizes: pageSizes, Hidden: hiddenFilters(values),
	}
	if page > 1 {
		p.PrevLink = listURL(path, values, page-1, perPage)
	}
	if page < p.LastPage {
		p.NextLink = listURL(path, values, page+1, perPage)
	}
	return p
}
