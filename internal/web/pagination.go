package web

import (
	"html/template"
	"net/http"
	"net/url"
	"sort"
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

// lastPage is the number of pages for total rows at the given size.
func lastPage(total int64, size int) int {
	return int(max((total+int64(size)-1)/int64(size), 1))
}

// pager is everything a list needs to show where it is and to change the page
// size. One struct and one template, shared by every list.
type pager struct {
	Action    string
	Target    string
	Summary   string
	Page      int
	LastPage  int
	PerPage   int
	Total     int64
	Sizes     []int
	FirstLink template.URL
	PrevLink  template.URL
	NextLink  template.URL
	LastLink  template.URL
	// Pages is the numbered window: 1 … 4 5 6 … 20.
	Pages []pageLink
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

// pageLink is one entry in the numbered window. Gap marks an ellipsis.
type pageLink struct {
	Number  int
	URL     template.URL
	Current bool
	Gap     bool
}

// pageWindow is the conventional numbered range: always the first and last
// page, the current one and two either side, with an ellipsis where numbers
// are skipped.
func pageWindow(current, last int, path string, values url.Values, perPage int) []pageLink {
	if last <= 1 {
		return []pageLink{{Number: 1, URL: listURL(path, values, 1, perPage), Current: true}}
	}
	wanted := map[int]bool{1: true, last: true}
	for n := current - 2; n <= current+2; n++ {
		if n >= 1 && n <= last {
			wanted[n] = true
		}
	}
	numbers := make([]int, 0, len(wanted))
	for n := range wanted {
		numbers = append(numbers, n)
	}
	sort.Ints(numbers)
	links := make([]pageLink, 0, len(numbers)+2)
	for i, n := range numbers {
		if i > 0 && n-numbers[i-1] > 1 {
			links = append(links, pageLink{Gap: true})
		}
		links = append(links, pageLink{Number: n, URL: listURL(path, values, n, perPage), Current: n == current})
	}
	return links
}

// newPager assembles the controls for a list page.
func newPager(path, target, summary string, values url.Values, page, lastPage, perPage int, total int64) pager {
	p := pager{
		Action: path, Target: target, Summary: summary,
		Page: page, LastPage: max(lastPage, 1), PerPage: perPage, Total: total,
		Sizes: pageSizes, Hidden: hiddenFilters(values),
	}
	if page > 1 {
		p.FirstLink = listURL(path, values, 1, perPage)
		p.PrevLink = listURL(path, values, page-1, perPage)
	}
	if page < p.LastPage {
		p.NextLink = listURL(path, values, page+1, perPage)
		p.LastLink = listURL(path, values, p.LastPage, perPage)
	}
	p.Pages = pageWindow(page, p.LastPage, path, values, perPage)
	return p
}
