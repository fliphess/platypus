package web

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"

	"platypus/internal/authz"
	"platypus/internal/docs"
	"platypus/internal/item"
	"platypus/internal/items"
	"platypus/internal/problem"
)

// templates holds one template set per page: the shared layout and
// partials plus the page's own file.
type templates struct {
	pages map[string]*template.Template
}

func loadTemplates(fsys fs.FS) (*templates, error) {
	base, err := template.New("").Funcs(templateFuncs).ParseFS(fsys, "layout.html", "partials.html")
	if err != nil {
		return nil, fmt.Errorf("parse layout: %w", err)
	}
	files, err := fs.Glob(fsys, "*.html")
	if err != nil {
		return nil, err
	}
	t := &templates{pages: map[string]*template.Template{}}
	for _, file := range files {
		name := strings.TrimSuffix(path.Base(file), ".html")
		if name == "layout" || name == "partials" {
			continue
		}
		set, err := template.Must(base.Clone()).ParseFS(fsys, file)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", file, err)
		}
		t.pages[name] = set
	}
	return t, nil
}

var templateFuncs = template.FuncMap{
	// kindPath is the URL segment of a kind: /ssm or /secrets.
	"kindPath": kindPath,
	// Times are emitted as a marker and replaced with a <time> element once
	// the whole page is rendered, in the zone this request asked for. One
	// implementation, no browser-side rewriting, so no swap can show UTC.
	"time": timeMarkerFunc,
	"join": strings.Join,
	"permissions": func(p authz.Permissions) string {
		var granted []string
		for _, permission := range authz.AllPermissions {
			if p.Has(permission) {
				granted = append(granted, string(permission))
			}
		}
		return strings.Join(granted, ", ")
	},
	"has": func(p authz.Permissions, permission string) bool {
		return p.Has(authz.Permission(permission))
	},
	"denial": func(denials map[authz.Permission]string, permission string) string {
		return denials[authz.Permission(permission)]
	},
	// Paths break at their slashes, never in the middle of a segment.
	"breakPath": func(name string) template.HTML {
		escaped := template.HTMLEscapeString(name)
		//nolint:gosec // escaped above; only <wbr> is added
		return template.HTML(strings.ReplaceAll(escaped, "/", "/<wbr>"))
	},
	// Docs pages flow through this so setting names render as inline code.
	"htmlText": docs.HTMLText,
	"dict": func(pairs ...any) (map[string]any, error) {
		if len(pairs)%2 != 0 {
			return nil, fmt.Errorf("dict needs key/value pairs")
		}
		m := make(map[string]any, len(pairs)/2)
		for i := 0; i < len(pairs); i += 2 {
			key, ok := pairs[i].(string)
			if !ok {
				return nil, fmt.Errorf("dict keys must be strings")
			}
			m[key] = pairs[i+1]
		}
		return m, nil
	},
	"list":   func(items ...string) []string { return items },
	"string": func(b []byte) string { return string(b) },
}

// timeMarker wraps an instant so the whole page can be formatted in one pass
// once the request's zone is known. The marker cannot collide with markup.
const (
	timeMarkerStart = "\x00time:"
	timeMarkerEnd   = "\x00"
)

var timeMarkerPattern = regexp.MustCompile("\x00time:([^\x00]+)\x00")

func timeMarkerFunc(value any) template.HTML {
	instant, ok := asInstant(value)
	if !ok {
		return ""
	}
	//nolint:gosec // an RFC3339 timestamp between NULs, expanded below
	return template.HTML(timeMarkerStart + instant.UTC().Format(time.RFC3339) + timeMarkerEnd)
}

func asInstant(value any) (time.Time, bool) {
	switch v := value.(type) {
	case time.Time:
		return v, !v.IsZero()
	case *time.Time:
		if v == nil || v.IsZero() {
			return time.Time{}, false
		}
		return *v, true
	}
	return time.Time{}, false
}

// renderTimes replaces every marker with a <time> element showing the instant
// in loc. A local zone prints a plain 24-hour time; UTC keeps an explicit
// suffix so nobody mistakes it for their own zone.
func renderTimes(page []byte, loc *time.Location) []byte {
	return timeMarkerPattern.ReplaceAllFunc(page, func(marker []byte) []byte {
		match := timeMarkerPattern.FindSubmatch(marker)
		if match == nil {
			return marker
		}
		instant, err := time.Parse(time.RFC3339, string(match[1]))
		if err != nil {
			return marker
		}
		display := instant.In(loc).Format("2006-01-02 15:04")
		if loc == time.UTC {
			display += " UTC"
		}
		utc := instant.UTC().Format("2006-01-02 15:04 UTC")
		//nolint:gosec // formatted timestamps, not user input
		return []byte(`<time datetime="` + instant.UTC().Format(time.RFC3339) +
			`" data-utc="` + utc + `">` + display + `</time>`)
	})
}

func kindPath(k item.Kind) string {
	if k == item.KindSecret {
		return "secrets"
	}
	return "ssm"
}

// zoneCookie is where the browser reports its own time zone. It carries no
// identity and no secret: only a name like Europe/Amsterdam, validated here.
const zoneCookie = "platypus_tz"

// parseZone validates a reported zone. Anything unrecognised falls back to
// UTC, so a bad cookie can never break a page.
func parseZone(name string) (*time.Location, string, bool) {
	if name == "" || len(name) > 64 || name == "Local" {
		return nil, "", false
	}
	// "+01:00" style offsets, for browsers without a zone name.
	if name[0] == '+' || name[0] == '-' {
		offset, err := time.Parse("-07:00", name)
		if err != nil {
			return nil, "", false
		}
		_, minutes := offset.Zone()
		return time.FixedZone(name, minutes), name, true
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, "", false
	}
	return loc, name, true
}

// timeZoneFor picks the zone this request renders times in: the user's profile
// preference, and the zone their browser reported. Only "local" accepts the
// cookie; everyone else sees UTC.
func timeZoneFor(r *http.Request) (*time.Location, string) {
	viewer := viewerFrom(r.Context())
	if viewer == nil || viewer.User.Timezone != "local" {
		return time.UTC, ""
	}
	cookie, err := r.Cookie(zoneCookie)
	if err != nil {
		return time.UTC, ""
	}
	// Browsers percent-encode the value ("Europe%2FAmsterdam"); accept both
	// forms so a plain zone name and an encoded one behave the same.
	name := cookie.Value
	if decoded, err := url.QueryUnescape(name); err == nil {
		name = decoded
	}
	loc, zone, ok := parseZone(name)
	if !ok {
		return time.UTC, ""
	}
	return loc, zone
}

// page is what a page handler passes to its template. Data holds the
// page's own fields.
type page struct {
	Title  string
	Tab    string
	Notice string
	Data   any
}

// layoutData is what the layout template sees.
type layoutData struct {
	page
	Viewer   *Viewer
	TestMode bool
	// CanLogout is set in oidc mode, where platypus owns the login.
	CanLogout bool
	// AssetVersion breaks browser caches when the static files change.
	AssetVersion string
	// Zone is the zone times were rendered in ("utc" when none was known).
	// Exposed in the page so a wrong time explains itself.
	Zone string
}

// render writes a full page.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, p page) {
	if p.Notice == "" {
		p.Notice = notices[r.URL.Query().Get("notice")]
	}
	_, zone := timeZoneFor(r)
	if zone == "" {
		zone = "utc"
	}
	data := layoutData{page: p, Viewer: viewerFrom(r.Context()), TestMode: s.settings.TestMode,
		CanLogout: s.services.Login != nil, AssetVersion: s.assetVersion, Zone: zone}
	s.execute(w, r, status, name, "layout", data)
}

// renderFragment writes one named block of a page, for htmx swaps.
func (s *Server) renderFragment(w http.ResponseWriter, r *http.Request, status int, name, block string, data any) {
	s.execute(w, r, status, name, block, data)
}

func (s *Server) execute(w http.ResponseWriter, r *http.Request, status int, name, block string, data any) {
	loc, _ := timeZoneFor(r)
	set, ok := s.templates.pages[name]
	if !ok {
		s.log.Error("unknown template", zap.String("template", name))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Render into a buffer first, so a template error never leaves half a page.
	var buf bytes.Buffer
	if err := set.ExecuteTemplate(&buf, block, data); err != nil {
		s.log.Error("template failed", zap.String("template", name), zap.String("block", block),
			zap.String("request_id", requestID(r.Context())), zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(renderTimes(buf.Bytes(), loc))
}

// notices are the fixed success messages a redirect can ask for with
// ?notice=. Only known keys show text, so nothing is reflected.
var notices = map[string]string{
	"saved":        "Saved.",
	"created":      "Created.",
	"deleted":      "Deleted.",
	"rolled-back":  "The earlier version is current again.",
	"admin-on":     "Admin mode is on.",
	"admin-off":    "Admin mode is off.",
	"blocked":      "Platypus is blocked. Only admins can use it, and nobody can reveal or change values.",
	"unblocked":    "Platypus is open again.",
	"sync":         "The worker will sync within a minute.",
	"pruned":       "Old audit events were deleted.",
	"factor-added": "Your second factor is set up.",
	"removed":      "Removed.",
}

func isHTMX(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

// redirect sends the browser elsewhere; htmx requests get an HX-Redirect.
// Callers only pass paths built by platypus itself, never a target taken
// from the request, so this can't become an open redirect.
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, path string) {
	if isHTMX(r) {
		w.Header().Set("HX-Redirect", path)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, path, http.StatusSeeOther) //nolint:gosec // see above
}

// handlerFunc is a handler that returns its error instead of writing it.
type handlerFunc func(w http.ResponseWriter, r *http.Request) error

func (s *Server) handle(h handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			s.fail(w, r, err)
		}
	})
}

// fail shows an error. Problems carry a message for the user; anything else
// is logged and shown as a generic error with the request id.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	p, ok := problem.As(err)
	if !ok {
		s.log.Error("request failed", zap.String("request_id", requestID(r.Context())),
			zap.String("path", r.URL.Path), zap.Error(err))
		s.renderInternalError(w, r)
		return
	}
	status := statusFor(p.Kind)
	if isHTMX(r) {
		s.renderFragment(w, r, status, "status", "problem", p.Message)
		return
	}
	s.render(w, r, status, "status", page{Title: "Something is not right", Data: statusContent{
		Title: titleFor(p.Kind), Message: p.Message,
	}})
}

func (s *Server) renderInternalError(w http.ResponseWriter, r *http.Request) {
	message := fmt.Sprintf("Something went wrong on our side. If it keeps happening, report request id %s.", requestID(r.Context()))
	if isHTMX(r) {
		s.renderFragment(w, r, http.StatusInternalServerError, "status", "problem", message)
		return
	}
	s.render(w, r, http.StatusInternalServerError, "status", page{Title: "Error", Data: statusContent{
		Title: "Something went wrong", Message: message,
	}})
}

func statusFor(kind problem.Kind) int {
	switch kind {
	case problem.KindForbidden:
		return http.StatusForbidden
	case problem.KindNotFound:
		return http.StatusNotFound
	case problem.KindConflict:
		return http.StatusConflict
	case problem.KindTooManyRequests:
		return http.StatusTooManyRequests
	default:
		return http.StatusUnprocessableEntity
	}
}

func titleFor(kind problem.Kind) string {
	switch kind {
	case problem.KindForbidden:
		return "Not allowed"
	case problem.KindNotFound:
		return "Not found"
	case problem.KindConflict:
		return "Conflict"
	case problem.KindTooManyRequests:
		return "Slow down"
	default:
		return "Please check your input"
	}
}

// statusContent is a full-page message.
type statusContent struct {
	Title     string
	Message   string
	Contact   string
	LoginLink bool
}

// Full-page states a user can be in.
const (
	statusNotAuthenticated = "not-authenticated"
	statusDisabled         = "disabled"
	statusLocked           = "locked"
	statusBlocked          = "blocked"
)

func (s *Server) renderStatus(w http.ResponseWriter, r *http.Request, status int, which string) {
	content := statusContent{}
	switch which {
	case statusNotAuthenticated:
		content = statusContent{Title: "Not logged in", Message: "Platypus could not tell who you are. Open it through the company login, or contact the platform team."}
	case statusDisabled:
		content = statusContent{Title: "Account disabled", Message: "Your platypus account is disabled. Ask an admin if you think this is a mistake."}
	case statusLocked:
		content = statusContent{Title: "Account locked", Message: "Your account was locked after too many failed second-factor attempts. Ask an admin to unlock it."}
	case statusBlocked:
		content = statusContent{Title: "Platypus is temporarily disabled",
			Message: "An admin has blocked access to platypus until further notice.", Contact: s.settings.BlockContactEmail}
	}
	if isHTMX(r) {
		s.renderFragment(w, r, status, "status", "problem", content.Message)
		return
	}
	s.render(w, r, status, "status", page{Title: content.Title, Data: content})
}

// confirmChange is the data of the "confirm" fragment: the summary of a
// change to an item. Continue posts the form with ID Form to Action.
type confirmChange struct {
	Summary items.Summary
	Action  string
	Form    string
	// After is carried into the final submit ("another" keeps the create form
	// open with a fresh, empty one). It is set by the form's own button and
	// travels through the confirmation step.
	After string
}

// confirmAction is the data of the "confirm-action" fragment: a simple
// action. Continue, labelled Button, posts the form with ID Form to Action.
type confirmAction struct {
	Title   string
	Message string
	Button  string
	Action  string
	Form    string
}

// count writes a number with the right noun: "1 team", "2 teams".
func count(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", n, plural)
}
