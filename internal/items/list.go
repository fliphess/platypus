package items

import (
	"context"

	"platypus/internal/audit"
	"platypus/internal/authz"
	"platypus/internal/catalog"
	"platypus/internal/item"
	"platypus/internal/problem"
	"platypus/internal/textclean"
)

// PageSize is how many items one page of a list shows.
const PageSize = 100

// maxPage keeps page numbers from the URL in a sane range.
const maxPage = 100_000

// Listing is one page of the parameter or secret list.
type Listing struct {
	Kind   item.Kind
	Search string
	Items  []ListedItem
	// Page counts from 1.
	Page  int
	Total int64
}

// ListedItem is an item in a list.
type ListedItem struct {
	catalog.Summary
	TerraformManaged bool
}

// First and Last number the items on this page, counting from 1.
func (l Listing) First() int { return (l.Page-1)*PageSize + 1 }
func (l Listing) Last() int  { return (l.Page-1)*PageSize + len(l.Items) }

// HasPrevious and HasNext tell whether there are pages around this one.
func (l Listing) HasPrevious() bool { return l.Page > 1 }
func (l Listing) HasNext() bool     { return int64(l.Last()) < l.Total }

// List returns one page of the items the subject may see, ordered by name,
// filtered by a search term on name, description and note.
func (s *Service) List(ctx context.Context, subject authz.Subject, kind item.Kind, search string, page int) (Listing, error) {
	search, err := textclean.Clean(search, textclean.Options{MaxLength: 200})
	if err != nil {
		return Listing{}, problem.Invalid("Search: %v.", err)
	}
	page = min(max(page, 1), maxPage)

	found, total, err := s.catalog.Find(ctx, catalog.Query{
		Kind:    kind,
		Allowed: subject.PatternsWith(authz.List, kind),
		Search:  search,
		Offset:  int32((page - 1) * PageSize),
		Limit:   PageSize,
	})
	if err != nil {
		return Listing{}, err
	}

	listing := Listing{Kind: kind, Search: search, Page: page, Total: total, Items: make([]ListedItem, len(found))}
	for i, summary := range found {
		listing.Items[i] = ListedItem{Summary: summary, TerraformManaged: s.managedByTerraform(summary.Tags)}
	}

	// The audit row names what was listed: the list itself, plus the search
	// term when there was one, so "item.list" is never an anonymous event.
	name := "/ssm"
	if kind == item.KindSecret {
		name = "/secrets"
	}
	if search != "" {
		name += "?q=" + search
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionItemList, Outcome: audit.Allowed,
		Kind: string(kind), Name: name,
		Details: map[string]any{"search": search, "page": page, "results": total}})
	return listing, nil
}
