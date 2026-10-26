package items

import (
	"context"

	"platypus/internal/audit"
	"platypus/internal/authz"
	"platypus/internal/catalog"
	"platypus/internal/item"
	paging "platypus/internal/page"
	"platypus/internal/problem"
	"platypus/internal/textclean"
)

// PageSize is the default number of items one page of a list shows.
const PageSize = 50

// pageClamp bounds a caller's page and size the same way the handlers do.
func pageClamp(number, perPage int) (int, int, int) {
	return paging.Clamp(number, perPage, PageSize)
}

// Listing is one page of the parameter or secret list.
type Listing struct {
	Kind   item.Kind
	Search string
	Items  []ListedItem
	// Page counts from 1; Size is how many rows this page asked for.
	Page  int
	Size  int
	Total int64
}

// ListedItem is an item in a list.
type ListedItem struct {
	catalog.Summary
	TerraformManaged bool
	// Note is the full note, so the list's detail row can show its text
	// without opening the edit form.
	Note *catalog.Note
	// CanEdit and EditDenied mirror the detail page's action, so a list-only
	// viewer is not offered an Edit link that ends in Forbidden.
	CanEdit    bool
	EditDenied string
}

// First and Last number the items on this page, counting from 1.
func (l Listing) First() int { return (l.Page-1)*l.Size + 1 }
func (l Listing) Last() int  { return (l.Page-1)*l.Size + len(l.Items) }

// HasPrevious and HasNext tell whether there are pages around this one.
func (l Listing) HasPrevious() bool { return l.Page > 1 }
func (l Listing) HasNext() bool     { return int64(l.Last()) < l.Total }

// List returns one page of the items the subject may see, ordered by name,
// filtered by a search term on name, description and note.
func (s *Service) List(ctx context.Context, subject authz.Subject, kind item.Kind, search string, page, perPage int) (Listing, error) {
	search, err := textclean.Clean(search, textclean.Options{MaxLength: 200})
	if err != nil {
		return Listing{}, problem.Invalid("Search: %v.", err)
	}
	page, perPage, offset := pageClamp(page, perPage)

	found, total, err := s.catalog.Find(ctx, catalog.Query{
		Kind:    kind,
		Allowed: subject.PatternsWith(authz.List, kind),
		Search:  search,
		Offset:  int32(offset),  //nolint:gosec // bounded by paging.Clamp
		Limit:   int32(perPage), //nolint:gosec // bounded by paging.Clamp
	})
	if err != nil {
		return Listing{}, err
	}

	names := make([]string, len(found))
	for i, summary := range found {
		names[i] = summary.Name
	}
	notes, err := s.catalog.NotesFor(ctx, kind, names)
	if err != nil {
		return Listing{}, err
	}
	listing := Listing{Kind: kind, Search: search, Page: page, Size: perPage, Total: total,
		Items: make([]ListedItem, len(found))}
	for i, summary := range found {
		listing.Items[i] = ListedItem{Summary: summary, TerraformManaged: s.managedByTerraform(summary.Tags)}
		if note, ok := notes[summary.Name]; ok {
			listing.Items[i].Note = &note
		}
		decision := subject.Can(authz.Edit, kind, summary.Name)
		listing.Items[i].CanEdit = decision.Allowed
		listing.Items[i].EditDenied = decision.Reason
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
