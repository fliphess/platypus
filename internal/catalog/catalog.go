// Package catalog is the metadata cache of parameters and secrets in
// Postgres: names, descriptions, types and tags, never values. The worker
// fills it from AWS; the web pods read it for lists and search, and update a
// row right after a change made through platypus.
//
// The catalog doesn't check permissions; package items does.
package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"platypus/internal/authz"
	"platypus/internal/database"
	"platypus/internal/db"
	"platypus/internal/item"
	"platypus/internal/store"
)

// Access says whether platypus itself can access an item in AWS.
type Access string

const (
	AccessUnknown Access = "unknown"
	AccessOK      Access = "ok"
	AccessDenied  Access = "denied"
)

// Catalog reads and writes the cache.
type Catalog struct {
	queries *db.Queries
}

// New returns a Catalog.
func New(queries *db.Queries) *Catalog {
	return &Catalog{queries: queries}
}

// PutParameter stores a parameter seen in AWS at syncedAt. Pass AccessOK when
// platypus just wrote it, AccessUnknown when the sync found it. A zero
// syncedAt means now, by the database clock.
func (c *Catalog) PutParameter(ctx context.Context, p store.Parameter, access Access, syncedAt time.Time) error {
	return c.queries.UpsertParameter(ctx, db.UpsertParameterParams{
		Name:           p.Name,
		Description:    p.Description,
		KMSKeyID:       p.KMSKeyID,
		LastModifiedAt: timePtr(p.LastModified),
		ChangeMarker:   strconv.FormatInt(p.Version, 10),
		SSMType:        p.Type,
		SSMTier:        p.Tier,
		SSMDataType:    p.DataType,
		SSMVersion:     p.Version,
		Access:         string(access),
		SyncedAt:       dbTime(syncedAt),
	})
}

// PutSecret stores a secret seen in AWS at syncedAt; see PutParameter.
func (c *Catalog) PutSecret(ctx context.Context, s store.Secret, access Access, syncedAt time.Time) error {
	tags, err := json.Marshal(s.Tags)
	if err != nil {
		return fmt.Errorf("encode tags: %w", err)
	}
	return c.queries.UpsertSecret(ctx, db.UpsertSecretParams{
		Name:            s.Name,
		Description:     s.Description,
		KMSKeyID:        s.KMSKeyID,
		LastModifiedAt:  timePtr(s.LastChanged),
		ChangeMarker:    s.CurrentVersionID + "@" + s.LastChanged.UTC().Format(time.RFC3339Nano),
		SecretARN:       s.ARN,
		SecretVersionID: s.CurrentVersionID,
		RotationEnabled: s.RotationEnabled,
		DeletedAt:       s.DeletedDate,
		Tags:            tags,
		Access:          string(access),
		SyncedAt:        dbTime(syncedAt),
	})
}

// RemoveNotSyncedSince deletes items a complete listing no longer returned.
func (c *Catalog) RemoveNotSyncedSince(ctx context.Context, kind item.Kind, since time.Time) (int64, error) {
	return c.queries.DeleteItemsNotSyncedSince(ctx, db.DeleteItemsNotSyncedSinceParams{Kind: string(kind), Since: since})
}

// NamesToCheck returns items whose access is unknown or was last checked
// before checkedBefore.
func (c *Catalog) NamesToCheck(ctx context.Context, kind item.Kind, checkedBefore time.Time) ([]string, error) {
	return c.queries.ListItemsToCheck(ctx, db.ListItemsToCheckParams{Kind: string(kind), CheckedBefore: &checkedBefore})
}

// SetAccess records whether platypus can access an item.
func (c *Catalog) SetAccess(ctx context.Context, kind item.Kind, name string, access Access) error {
	return c.queries.SetItemAccess(ctx, db.SetItemAccessParams{Kind: string(kind), Name: name, Access: string(access)})
}

// SetTags caches the tags of an item.
func (c *Catalog) SetTags(ctx context.Context, kind item.Kind, name string, tags map[string]string) error {
	encoded, err := json.Marshal(tags)
	if err != nil {
		return fmt.Errorf("encode tags: %w", err)
	}
	return c.queries.SetItemTags(ctx, db.SetItemTagsParams{Kind: string(kind), Name: name, Tags: encoded})
}

// Entry is an item in the cache. Tags is nil when they haven't been fetched.
type Entry struct {
	Kind            item.Kind
	Name            string
	Description     string
	KMSKeyID        string
	LastModified    *time.Time
	SSMType         string
	SSMTier         string
	SSMDataType     string
	SSMVersion      int64
	SecretARN       string
	SecretVersionID string
	RotationEnabled bool
	// DeletedAt marks a secret scheduled for deletion: it can't be read
	// until it is restored.
	DeletedAt *time.Time
	Tags      map[string]string
}

// Version is the token a change must carry to detect concurrent edits: the
// SSM version number or the current secret version id.
func (e Entry) Version() string {
	if e.Kind == item.KindSSM {
		return strconv.FormatInt(e.SSMVersion, 10)
	}
	return e.SecretVersionID
}

// Get returns an item platypus can access, or false when there is none.
func (c *Catalog) Get(ctx context.Context, kind item.Kind, name string) (Entry, bool, error) {
	row, err := c.queries.GetItem(ctx, db.GetItemParams{Kind: string(kind), Name: name})
	if database.IsNoRows(err) {
		return Entry{}, false, nil
	}
	if err != nil {
		return Entry{}, false, fmt.Errorf("load item: %w", err)
	}
	entry := Entry{
		Kind:            item.Kind(row.Kind),
		Name:            row.Name,
		Description:     row.Description,
		KMSKeyID:        row.KMSKeyID,
		LastModified:    row.LastModifiedAt,
		SSMType:         row.SSMType,
		SSMTier:         row.SSMTier,
		SSMDataType:     row.SSMDataType,
		SSMVersion:      row.SSMVersion,
		SecretARN:       row.SecretARN,
		SecretVersionID: row.SecretVersionID,
		RotationEnabled: row.RotationEnabled,
		DeletedAt:       row.DeletedAt,
	}
	if row.Tags != nil {
		if err := json.Unmarshal(row.Tags, &entry.Tags); err != nil {
			return Entry{}, false, fmt.Errorf("decode tags: %w", err)
		}
	}
	return entry, true, nil
}

// Summary is an item as shown in lists. Tags is nil when they haven't been
// fetched yet (SSM lists don't include them).
type Summary struct {
	Kind            item.Kind
	Name            string
	Description     string
	LastModified    *time.Time
	SSMType         string
	SSMTier         string
	RotationEnabled bool
	SecretARN       string
	HasNote         bool
	DeletedAt       *time.Time
	Tags            map[string]string
}

// Query selects items for a list.
type Query struct {
	Kind item.Kind
	// Allowed are the patterns the user may list; nothing matches without them.
	Allowed []authz.Pattern
	// Search matches name, description and note, case-insensitively.
	Search string
	// Offset and Limit select one page.
	Offset int32
	Limit  int32
}

// Find returns one page of the items matching q, ordered by name, and how
// many match in total.
func (c *Catalog) Find(ctx context.Context, q Query) ([]Summary, int64, error) {
	if len(q.Allowed) == 0 {
		return nil, 0, nil
	}
	allowed := likePatterns(q.Allowed)
	search := ""
	if q.Search != "" {
		search = "%" + escapeLike(q.Search) + "%"
	}

	total, err := c.queries.CountListedItems(ctx, db.CountListedItemsParams{
		Kind: string(q.Kind), Allowed: allowed, Search: search,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("count items: %w", err)
	}
	rows, err := c.queries.ListVisibleItems(ctx, db.ListVisibleItemsParams{
		Kind: string(q.Kind), Allowed: allowed, Search: search, Skip: q.Offset, MaxRows: q.Limit,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("list items: %w", err)
	}

	summaries := make([]Summary, len(rows))
	for i, row := range rows {
		summaries[i] = Summary{
			Kind:            item.Kind(row.Kind),
			Name:            row.Name,
			Description:     row.Description,
			LastModified:    row.LastModifiedAt,
			SSMType:         row.SSMType,
			RotationEnabled: row.RotationEnabled,
			SSMTier:         row.SSMTier,
			SecretARN:       row.SecretARN,
			HasNote:         row.HasNote,
			DeletedAt:       row.DeletedAt,
		}
		if row.Tags != nil {
			if err := json.Unmarshal(row.Tags, &summaries[i].Tags); err != nil {
				return nil, 0, fmt.Errorf("decode tags: %w", err)
			}
		}
	}
	return summaries, total, nil
}

// Count returns how many accessible items match the patterns, for the
// policy editor's preview.
func (c *Catalog) Count(ctx context.Context, kind item.Kind, patterns []authz.Pattern) (int64, error) {
	if len(patterns) == 0 {
		return 0, nil
	}
	return c.queries.CountVisibleItems(ctx, db.CountVisibleItemsParams{Kind: string(kind), Allowed: likePatterns(patterns)})
}

// likePatterns turns rule patterns into SQL LIKE patterns.
func likePatterns(patterns []authz.Pattern) []string {
	likes := make([]string, len(patterns))
	for i, p := range patterns {
		likes[i] = escapeLike(p.Literal())
		if p.IsPrefix() {
			likes[i] += "%"
		}
	}
	return likes
}

// escapeLike makes text match literally in a LIKE pattern (with the default
// backslash escape character).
func escapeLike(text string) string {
	return likeEscaper.Replace(text)
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// dbTime leaves a zero time to the database clock.
func dbTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
