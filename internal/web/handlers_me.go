package web

import (
	"net/http"

	"platypus/internal/access"
	"platypus/internal/authz"
	"platypus/internal/docs"
	"platypus/internal/item"
	"platypus/internal/problem"
)

type homeData struct {
	Name      string
	HasAccess bool
	IsAdmin   bool
	Kinds     []homeKind
}

type homeKind struct {
	Kind      item.Kind
	Count     int64
	CanCreate bool
}

// home is the front page: a welcome and what the viewer can reach, without
// listing any items.
func (s *Server) home(w http.ResponseWriter, r *http.Request) error {
	viewer := viewerFrom(r.Context())
	data := homeData{
		Name:      viewer.User.Label(),
		HasAccess: viewer.Subject.HasAnyAccess(),
		IsAdmin:   viewer.User.IsAdmin,
	}
	for _, kind := range item.Kinds {
		count, err := s.services.Catalog.Count(r.Context(), kind, viewer.Subject.PatternsWith(authz.List, kind))
		if err != nil {
			return err
		}
		data.Kinds = append(data.Kinds, homeKind{Kind: kind, Count: count, CanCreate: viewer.Subject.HasAny(authz.Create, kind)})
	}
	s.render(w, r, http.StatusOK, "home", page{Title: "Home", Data: data})
	return nil
}

type permissionsData struct {
	Email   string
	IsAdmin bool
	Rules   map[item.Kind][]authz.Rule
	Kinds   []item.Kind
	Blocked bool
}

// myPermissions shows the viewer's rules: patterns and where they come from,
// never the items they match.
func (s *Server) myPermissions(w http.ResponseWriter, r *http.Request) error {
	viewer := viewerFrom(r.Context())
	data := permissionsData{
		Email:   viewer.User.Email,
		IsAdmin: viewer.User.IsAdmin,
		Rules:   map[item.Kind][]authz.Rule{},
		Kinds:   item.Kinds,
		Blocked: viewer.State.Blocked,
	}
	for _, rule := range viewer.Subject.Rules {
		data.Rules[rule.Kind] = append(data.Rules[rule.Kind], rule)
	}
	s.render(w, r, http.StatusOK, "permissions", page{Title: "My permissions", Tab: "me", Data: data})
	return nil
}

func (s *Server) profilePage(w http.ResponseWriter, r *http.Request) error {
	s.render(w, r, http.StatusOK, "profile", page{Title: "Profile", Tab: "me", Data: viewerFrom(r.Context()).User})
	return nil
}

func (s *Server) updateProfile(w http.ResponseWriter, r *http.Request) error {
	err := s.services.Access.UpdateProfile(r.Context(), viewerFrom(r.Context()).User.ID, access.Profile{
		DisplayName: r.PostFormValue("display_name"),
		Department:  r.PostFormValue("department"),
		Timezone:    r.PostFormValue("timezone"),
	})
	if err != nil {
		return err
	}
	s.redirect(w, r, "/me/profile?notice=saved")
	return nil
}

type docsData struct {
	Pages []docs.Page
	Page  docs.Page
}

func (s *Server) docsPage(w http.ResponseWriter, r *http.Request) error {
	pages := s.services.Docs.Pages()
	if len(pages) == 0 {
		return problem.NotFound("There is no documentation installed.")
	}
	slug := r.PathValue("slug")
	if slug == "" {
		slug = pages[0].Slug
	}
	current, ok := s.services.Docs.Page(slug)
	if !ok {
		return problem.NotFound("This documentation page doesn't exist.")
	}
	s.render(w, r, http.StatusOK, "docs", page{Title: current.Title, Tab: "docs", Data: docsData{Pages: pages, Page: current}})
	return nil
}
