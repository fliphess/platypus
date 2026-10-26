package catalog

import (
	"context"
	"fmt"
	"time"

	"platypus/internal/database"
	"platypus/internal/db"
	"platypus/internal/item"
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

// SaveNote stores a note; an empty body removes it.
func (c *Catalog) SaveNote(ctx context.Context, kind item.Kind, name, body, updatedBy string) error {
	if body == "" {
		return c.queries.DeleteNote(ctx, db.DeleteNoteParams{Kind: string(kind), Name: name})
	}
	return c.queries.SaveNote(ctx, db.SaveNoteParams{Kind: string(kind), Name: name, Body: body, UpdatedBy: updatedBy})
}

// OrphanedNotes returns notes whose item no longer exists or is hidden.
func (c *Catalog) OrphanedNotes(ctx context.Context) ([]db.Note, error) {
	return c.queries.ListOrphanedNotes(ctx)
}
