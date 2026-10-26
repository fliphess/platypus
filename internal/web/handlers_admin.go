package web

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"platypus/internal/audit"
	"platypus/internal/db"
)

type adminOverviewData struct {
	Blocked        bool
	BlockedBy      string
	BlockedAt      time.Time
	LatestSync     *db.SyncRun
	RetentionDays  int
	ContactAddress string
}

func (s *Server) adminOverview(w http.ResponseWriter, r *http.Request) error {
	viewer := viewerFrom(r.Context())
	latest, err := s.services.AppState.LatestSync(r.Context())
	if err != nil {
		return err
	}
	data := adminOverviewData{
		Blocked:        viewer.State.Blocked,
		BlockedBy:      viewer.State.BlockedBy,
		BlockedAt:      viewer.State.BlockedAt,
		LatestSync:     latest,
		RetentionDays:  s.settings.AuditRetentionDays,
		ContactAddress: s.settings.BlockContactEmail,
	}
	s.render(w, r, http.StatusOK, "admin", page{Title: "Admin", Tab: "admin", Data: data})
	return nil
}

func (s *Server) previewBlock(w http.ResponseWriter, r *http.Request) error {
	s.renderFragment(w, r, http.StatusOK, "admin", "confirm-action", confirmAction{
		Title:   "Block all access?",
		Message: "Everyone except admins is shut out right away, and nobody can reveal or change values until an admin unblocks platypus.",
		Button:  "Block access",
		Action:  "/admin/block",
		Form:    "block-form",
	})
	return nil
}

func (s *Server) setBlocked(blocked bool) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		if err := s.services.AppState.SetBlocked(r.Context(), blocked); err != nil {
			return err
		}
		notice := "unblocked"
		if blocked {
			notice = "blocked"
		}
		s.redirect(w, r, "/admin?notice="+notice)
		return nil
	}
}

func (s *Server) requestSync(w http.ResponseWriter, r *http.Request) error {
	if err := s.services.AppState.RequestSync(r.Context(), r.PostFormValue("recheck_access") == "on"); err != nil {
		return err
	}
	s.redirect(w, r, "/admin?notice=sync")
	return nil
}

func (s *Server) orphanedNotes(w http.ResponseWriter, r *http.Request) error {
	notes, err := s.services.Catalog.OrphanedNotes(r.Context())
	if err != nil {
		return err
	}
	s.render(w, r, http.StatusOK, "admin_notes", page{Title: "Orphaned notes", Tab: "admin", Data: notes})
	return nil
}

type auditData struct {
	Filter        auditFilterForm
	Events        []db.AuditEvent
	Actions       []audit.Action
	Outcomes      []audit.Outcome
	Users         []db.User
	RetentionDays int
	Page          int
	LastPage      int
	Total         int64
	// Links keep the current filter. They are built here, already encoded,
	// because the template would escape a query string a second time.
	CSVLink template.URL
	Pager   pager
}

// auditFilterForm is the filter as typed in the form, so it can be shown again.
type auditFilterForm struct {
	Since   string
	Until   string
	Actor   string
	Action  string
	Outcome string
	Search  string
}

func parseAuditFilter(r *http.Request) (auditFilterForm, audit.Filter) {
	q := r.URL.Query()
	form := auditFilterForm{
		Since: q.Get("since"), Until: q.Get("until"), Actor: q.Get("actor"),
		Action: q.Get("action"), Outcome: q.Get("outcome"), Search: q.Get("q"),
	}
	filter := audit.Filter{
		ActorEmail: form.Actor, Action: form.Action, Outcome: form.Outcome, Search: form.Search,
	}
	if t, err := time.Parse("2006-01-02", form.Since); err == nil {
		filter.Since = &t
	}
	if t, err := time.Parse("2006-01-02", form.Until); err == nil {
		end := t.AddDate(0, 0, 1) // until includes the whole day
		filter.Until = &end
	}
	return form, filter
}

func (s *Server) auditTrail(w http.ResponseWriter, r *http.Request) error {
	form, filter := parseAuditFilter(r)
	pageNumber := pageNumber(r)
	size := pageSize(r)
	events, total, err := s.services.Trail.Page(r.Context(), filter, pageNumber, int32(size)) //nolint:gosec // pageSizes bounds size
	if err != nil {
		return err
	}
	lastPage := int(max((total+int64(size)-1)/int64(size), 1))
	query := auditQuery(form)
	data := auditData{
		Filter: form, Events: events, Actions: audit.Actions, Outcomes: audit.Outcomes,
		RetentionDays: s.settings.AuditRetentionDays,
		Page:          pageNumber,
		LastPage:      lastPage,
		Total:         total,
		CSVLink:       template.URL("/admin/audit.csv?" + query.Encode()), //nolint:gosec // encoded above
	}
	if data.Users, err = s.services.Access.Users(r.Context(), ""); err != nil {
		return err
	}
	// Paging links keep the filter; the CSV link above exports all of it.
	data.Pager = newPager("/admin/audit", "#audit-results",
		fmt.Sprintf("Page %d of %d · %d events", pageNumber, lastPage, total),
		r.URL.Query(), pageNumber, lastPage, size)
	// Filters swap the results in place; the whole page otherwise.
	if isHTMX(r) {
		s.renderFragment(w, r, http.StatusOK, "admin_audit", "audit-results", data)
		return nil
	}
	s.render(w, r, http.StatusOK, "admin_audit", page{Title: "Audit trail", Tab: "admin", Data: data})
	return nil
}

// auditQuery holds the filter for "older" and CSV links.
func auditQuery(f auditFilterForm) url.Values {
	values := map[string]string{"since": f.Since, "until": f.Until, "actor": f.Actor,
		"action": f.Action, "outcome": f.Outcome, "q": f.Search}
	query := url.Values{}
	for key, value := range values {
		if value != "" {
			query.Set(key, value)
		}
	}
	return query
}

func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request) error {
	_, filter := parseAuditFilter(r)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="platypus-audit-%s.csv"`, s.now().UTC().Format("2006-01-02")))
	return s.services.Trail.WriteCSV(r.Context(), w, filter)
}

func (s *Server) previewPrune(w http.ResponseWriter, r *http.Request) error {
	s.renderFragment(w, r, http.StatusOK, "admin_audit", "confirm-action", confirmAction{
		Title: "Delete old audit events?",
		Message: fmt.Sprintf("All audit events older than %d days are deleted for good. The deletion itself is recorded.",
			s.settings.AuditRetentionDays),
		Button: "Delete old events",
		Action: "/admin/audit/prune",
		Form:   "prune-form",
	})
	return nil
}

func (s *Server) pruneAudit(w http.ResponseWriter, r *http.Request) error {
	if _, err := s.services.Trail.Prune(r.Context(), s.settings.AuditRetentionDays); err != nil {
		return err
	}
	s.redirect(w, r, "/admin/audit?notice=pruned")
	return nil
}
