package web

import (
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"platypus/internal/authz"
	"platypus/internal/catalog"
	"platypus/internal/item"
	"platypus/internal/items"
	"platypus/internal/problem"
	"platypus/internal/sensitive"
)

type browseData struct {
	Listing   items.Listing
	CanCreate bool
	HasAccess bool
	Blocked   bool
	// Page links keep the search. They are built here, already encoded,
	// because the template would escape a query string a second time.
	PreviousLink template.URL
	NextLink     template.URL
}

func (s *Server) browse(kind item.Kind) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		viewer := viewerFrom(r.Context())
		query := r.URL.Query()
		pageNumber, _ := strconv.Atoi(query.Get("page"))
		listing, err := s.services.Items.List(r.Context(), viewer.Subject, kind, query.Get("q"), pageNumber)
		if err != nil {
			return err
		}
		data := browseData{
			Listing:   listing,
			CanCreate: viewer.Subject.HasAny(authz.Create, kind),
			HasAccess: viewer.Subject.HasAny(authz.List, kind) || viewer.Subject.HasAny(authz.Create, kind),
			Blocked:   viewer.State.Blocked,
		}
		if listing.HasPrevious() {
			data.PreviousLink = listPageLink(kind, listing.Search, listing.Page-1)
		}
		if listing.HasNext() {
			data.NextLink = listPageLink(kind, listing.Search, listing.Page+1)
		}
		if isHTMX(r) && r.Header.Get("HX-Target") == "results" {
			s.renderFragment(w, r, http.StatusOK, "browse", "results", data)
			return nil
		}
		s.render(w, r, http.StatusOK, "browse", page{Title: kind.Title(), Tab: kindPath(kind), Data: data})
		return nil
	}
}

type itemData struct {
	Detail   items.Detail
	Versions []items.Version
}

func (s *Server) itemDetail(kind item.Kind) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		viewer := viewerFrom(r.Context())
		name := r.URL.Query().Get("name")
		detail, err := s.services.Items.Get(r.Context(), viewer.Subject, kind, name)
		if err != nil {
			return err
		}
		versions, err := s.services.Items.History(r.Context(), viewer.Subject, kind, name)
		if err != nil {
			return err
		}
		s.render(w, r, http.StatusOK, "item", page{Title: name, Tab: kindPath(kind), Data: itemData{Detail: detail, Versions: versions}})
		return nil
	}
}

// revealData is the only place a value is turned into text for a page.
type revealData struct {
	Value     string
	HideAfter int
	// What to reveal again after the value hides itself: the kind, name and
	// version of the item, and the id of the element the fragment lands in.
	Kind    item.Kind
	Name    string
	Version string
	Target  string
}

func (s *Server) reveal(kind item.Kind) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		viewer := viewerFrom(r.Context())
		version := r.PostFormValue("version")
		value, err := s.services.Items.Reveal(r.Context(), viewer.Subject, kind, r.PostFormValue("name"), version)
		if errors.Is(err, items.ErrBinarySecret) {
			s.renderFragment(w, r, http.StatusOK, "item", "binary-refusal", nil)
			return nil
		}
		if err != nil {
			return err
		}
		target := "value"
		if version != "" {
			target = "version-" + version
		}
		s.renderFragment(w, r, http.StatusOK, "item", "revealed", revealData{
			Value:     value.Reveal(),
			HideAfter: int(s.settings.RevealHideAfter.Seconds()),
			Kind:      kind,
			Name:      r.PostFormValue("name"),
			Version:   version,
			Target:    target,
		})
		return nil
	}
}

// undeleteSecret cancels a secret's scheduled deletion.
func (s *Server) undeleteSecret(w http.ResponseWriter, r *http.Request) error {
	name := r.PostFormValue("name")
	if err := s.services.Items.Undelete(r.Context(), viewerFrom(r.Context()).Subject, name); err != nil {
		return err
	}
	s.redirect(w, r, "/secrets/item?name="+url.QueryEscape(name)+"&notice=restored")
	return nil
}

type itemFormData struct {
	IsNew          bool
	Kind           item.Kind
	Name           string
	Version        string
	Description    string
	SSMType        string
	SSMTier        string
	SSMTypes       []string
	SSMTiers       []string
	Teams          []string
	CreatePatterns []string
	// CreateAll is set when a pattern allows creating any name.
	CreateAll  bool
	Note       *catalog.Note
	Value      string
	ValueShown bool
	CanLoad    bool
	Format     string
}

// allowsAll reports whether any of the patterns covers every name.
func allowsAll(patterns []authz.Pattern) bool {
	for _, p := range patterns {
		switch p.String() {
		case "*", "/*":
			return true
		}
	}
	return false
}

func (s *Server) newItemForm(kind item.Kind) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		viewer := viewerFrom(r.Context())
		patterns := viewer.Subject.PatternsWith(authz.Create, kind)
		if len(patterns) == 0 {
			return problem.Forbidden("None of your policies allow creating %s. Ask an admin.", kind.PluralNoun())
		}
		teams, err := s.teamNames(r, viewer)
		if err != nil {
			return err
		}
		data := itemFormData{
			IsNew: true, Kind: kind, Format: "text", Teams: teams, CreateAll: allowsAll(patterns),
			SSMType: item.SSMTypeSecureString, SSMTier: item.SSMTierStandard,
			SSMTypes: item.SSMTypes, SSMTiers: item.SSMTiers,
		}
		for _, p := range patterns {
			data.CreatePatterns = append(data.CreatePatterns, p.String())
		}
		s.render(w, r, http.StatusOK, "item_form", page{Title: "New " + kind.Noun(), Tab: kindPath(kind), Data: data})
		return nil
	}
}

func (s *Server) previewCreate(kind item.Kind) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		viewer := viewerFrom(r.Context())
		teams, err := s.teamNames(r, viewer)
		if err != nil {
			return err
		}
		summary, err := s.services.Items.PreviewCreate(r.Context(), viewer.Subject, teams, newItemFromForm(r, kind))
		if err != nil {
			return err
		}
		s.renderFragment(w, r, http.StatusOK, "item_form", "confirm", confirmChange{
			Summary: summary, Action: "/" + kindPath(kind) + "/new", Form: "item-form",
		})
		return nil
	}
}

func (s *Server) createItem(kind item.Kind) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		viewer := viewerFrom(r.Context())
		teams, err := s.teamNames(r, viewer)
		if err != nil {
			return err
		}
		n := newItemFromForm(r, kind)
		if err := s.services.Items.Create(r.Context(), viewer.Subject, teams, n); err != nil {
			return err
		}
		s.redirect(w, r, itemURL(kind, n.Name)+"&notice=created")
		return nil
	}
}

func (s *Server) editItemForm(kind item.Kind) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		viewer := viewerFrom(r.Context())
		name := r.URL.Query().Get("name")
		detail, err := s.services.Items.Get(r.Context(), viewer.Subject, kind, name)
		if err != nil {
			return err
		}
		if !detail.Permissions.Edit {
			return problem.Forbidden("%s", detail.Denials[authz.Edit])
		}

		if detail.TerraformManaged {
			return problem.Forbidden("%s", detail.TerraformReason)
		}

		// Users who may reveal can load the current value into the editor;
		// others replace the whole value.
		data := itemFormData{
			Kind: kind, Name: name, Version: detail.Version(), Description: detail.Description,
			SSMType: detail.SSMType, SSMTier: detail.SSMTier, SSMTypes: item.SSMTypes, SSMTiers: item.SSMTiers,
			Note: detail.Note, Format: "text", CanLoad: detail.Permissions.Reveal,
		}
		s.render(w, r, http.StatusOK, "item_form", page{Title: "Edit " + name, Tab: kindPath(kind), Data: data})
		return nil
	}
}

// loadValue fills the editor with the current value. It is a reveal and is
// audited as one.
func (s *Server) loadValue(kind item.Kind) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		viewer := viewerFrom(r.Context())
		name := r.PostFormValue("name")
		value, err := s.services.Items.RevealForEditing(r.Context(), viewer.Subject, kind, name)
		if err != nil {
			return err
		}
		data := itemFormData{Kind: kind, Name: name, Value: value.Reveal(), ValueShown: true, Format: "text"}
		// JSON mode only for objects and arrays: a number, a boolean or a
		// quoted string is valid JSON but still a string people edit as text.
		trimmed := strings.TrimSpace(data.Value)
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			if json.Valid([]byte(trimmed)) {
				data.Format = "json"
			}
		}
		s.renderFragment(w, r, http.StatusOK, "item_form", "value-editor", data)
		return nil
	}
}

func (s *Server) previewUpdate(kind item.Kind) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		viewer := viewerFrom(r.Context())
		summary, err := s.services.Items.PreviewUpdate(r.Context(), viewer.Subject, changeFromForm(r, kind))
		if err != nil {
			return err
		}
		s.renderFragment(w, r, http.StatusOK, "item_form", "confirm", confirmChange{
			Summary: summary, Action: "/" + kindPath(kind) + "/edit", Form: "item-form",
		})
		return nil
	}
}

func (s *Server) updateItem(kind item.Kind) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		viewer := viewerFrom(r.Context())
		change := changeFromForm(r, kind)
		if err := s.services.Items.Update(r.Context(), viewer.Subject, change); err != nil {
			return err
		}
		s.redirect(w, r, itemURL(kind, change.Name)+"&notice=saved")
		return nil
	}
}

// rollbackConfirm is the rollback dialog: what will happen, and the value of
// the version being restored when the viewer may reveal it.
type rollbackConfirm struct {
	Title   string
	Message string
	Version string
	Value   string
	Action  string
	Form    string
}

// previewRollback shows what rolling back will do, including the value of
// that version when the viewer may reveal it: picking a version to restore
// is the moment to see what is being restored.
func (s *Server) previewRollback(kind item.Kind) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		viewer := viewerFrom(r.Context())
		name, version := r.PostFormValue("name"), r.PostFormValue("version")
		detail, err := s.services.Items.Get(r.Context(), viewer.Subject, kind, name)
		if err != nil {
			return err
		}
		if !detail.Permissions.Edit {
			return problem.Forbidden("%s", detail.Denials[authz.Edit])
		}
		message := "This version becomes the current value again. Applications pick it up the next time they read it."
		if kind == item.KindSSM {
			message = "Platypus writes the value of this version as a new version. Applications pick it up the next time they read it."
		}
		data := rollbackConfirm{
			Title: "Roll back " + name + "?", Message: message, Version: version,
			Action: "/" + kindPath(kind) + "/rollback", Form: "rollback-" + version,
		}
		if detail.Permissions.Reveal {
			value, err := s.services.Items.Reveal(r.Context(), viewer.Subject, kind, name, version)
			if err == nil {
				data.Value = value.Reveal()
			}
		}
		s.renderFragment(w, r, http.StatusOK, "item", "rollback-confirm", data)
		return nil
	}
}

func (s *Server) rollback(kind item.Kind) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		viewer := viewerFrom(r.Context())
		name := r.PostFormValue("name")
		err := s.services.Items.Rollback(r.Context(), viewer.Subject, kind, name,
			r.PostFormValue("version"), r.PostFormValue("expect_version"))
		if err != nil {
			return err
		}
		s.redirect(w, r, itemURL(kind, name)+"&notice=rolled-back")
		return nil
	}
}

func (s *Server) saveNote(kind item.Kind) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		viewer := viewerFrom(r.Context())
		name := r.PostFormValue("name")
		if err := s.services.Items.SaveNote(r.Context(), viewer.Subject, kind, name, r.PostFormValue("note")); err != nil {
			return err
		}
		s.redirect(w, r, itemURL(kind, name)+"&notice=saved")
		return nil
	}
}

func (s *Server) teamNames(r *http.Request, viewer *Viewer) ([]string, error) {
	detail, err := s.services.Access.UserDetail(r.Context(), viewer.User.ID)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(detail.Teams))
	for i, team := range detail.Teams {
		names[i] = team.Name
	}
	return names, nil
}

func newItemFromForm(r *http.Request, kind item.Kind) items.NewItem {
	return items.NewItem{
		Kind:        kind,
		Name:        strings.TrimSpace(r.PostFormValue("name")),
		Value:       valueFromForm(r),
		IsJSON:      isJSONFormat(r),
		Description: r.PostFormValue("description"),
		SSMType:     r.PostFormValue("ssm_type"),
		SSMTier:     r.PostFormValue("ssm_tier"),
		Team:        r.PostFormValue("team"),
	}
}

func changeFromForm(r *http.Request, kind item.Kind) items.Change {
	change := items.Change{
		Kind:          kind,
		Name:          r.PostFormValue("name"),
		IsJSON:        isJSONFormat(r),
		Description:   r.PostFormValue("description"),
		SSMType:       r.PostFormValue("ssm_type"),
		SSMTier:       r.PostFormValue("ssm_tier"),
		ExpectVersion: r.PostFormValue("expect_version"),
	}
	// An empty value field means: keep the current value.
	if value := valueFromForm(r); !value.IsEmpty() {
		change.Value = &value
	}
	return change
}

// valueFromForm reads the value field. Browsers send textarea line breaks as
// CRLF; they are turned back into LF so multi-line values (keys,
// certificates) arrive unchanged. Nothing else is trimmed or altered.
func valueFromForm(r *http.Request) sensitive.Value {
	return sensitive.New(strings.ReplaceAll(r.PostFormValue("value"), "\r\n", "\n"))
}

func isJSONFormat(r *http.Request) bool {
	format := r.PostFormValue("format")
	return format == "json" || format == "fields"
}

func listPageLink(kind item.Kind, search string, page int) template.URL {
	query := url.Values{"page": {strconv.Itoa(page)}}
	if search != "" {
		query.Set("q", search)
	}
	return template.URL("/" + kindPath(kind) + "?" + query.Encode()) //nolint:gosec // encoded above
}

func itemURL(kind item.Kind, name string) string {
	return "/" + kindPath(kind) + "/item?name=" + url.QueryEscape(name)
}
