package catalog

import (
	"context"
	"fmt"
	"time"

	"platypus/internal/database"
	"platypus/internal/db"
	"platypus/internal/item"
	paging "platypus/internal/page"
)

// Note is a free-text note on an item, kept only in platypus.
type Note struct {
	Body      string
	UpdatedBy string
	UpdatedAt time.Time
}

// Note returns the note on an item, if any.
func (c *Catalog) Note(ctx context.Context, kind item.Kind, name string) (*Note, error) {
	row, err := c.queries.GetNote(ctx, db.GetNoteParams{Kind: string(kind), Name: name})
	if database.IsNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load note: %w", err)
	}
	return &Note{Body: row.Body, UpdatedBy: row.UpdatedBy, UpdatedAt: row.UpdatedAt}, nil
}

// NotesFor returns the notes of these items, keyed by item name, so a list
// page loads only what it shows.
func (c *Catalog) NotesFor(ctx context.Context, kind item.Kind, names []string) (map[string]Note, error) {
	if len(names) == 0 {
		return map[string]Note{}, nil
	}
	rows, err := c.queries.ListNotesForNames(ctx, db.ListNotesForNamesParams{Kind: string(kind), Names: names})
	if err != nil {
		return nil, fmt.Errorf("list notes: %w", err)
	}
	notes := make(map[string]Note, len(rows))
	for _, row := range rows {
		notes[row.Name] = Note{Body: row.Body, UpdatedBy: row.UpdatedBy, UpdatedAt: row.UpdatedAt}
	}
	return notes, nil
}

// SaveNote stores a note; an empty body removes it.
func (c *Catalog) SaveNote(ctx context.Context, kind item.Kind, name, body, updatedBy string) error {
	if body == "" {
		return c.queries.DeleteNote(ctx, db.DeleteNoteParams{Kind: string(kind), Name: name})
	}
	return c.queries.SaveNote(ctx, db.SaveNoteParams{Kind: string(kind), Name: name, Body: body, UpdatedBy: updatedBy})
}

// OrphanedNotesPage returns one page of orphaned notes and the total, so the
// page uses the same pager as every other list.
func (c *Catalog) OrphanedNotesPage(ctx context.Context, page, perPage int) ([]db.Note, int64, error) {
	_, perPage, offset := paging.Clamp(page, perPage, 50)
	total, err := c.queries.CountOrphanedNotes(ctx)
	if err != nil {
		return nil, 0, err
	}
	notes, err := c.queries.ListOrphanedNotesPage(ctx, db.ListOrphanedNotesPageParams{
		MaxRows: int32(perPage), RowOffset: int32(offset), //nolint:gosec // bounded by paging.Clamp
	})
	if err != nil {
		return nil, 0, err
	}
	return notes, total, nil
}
