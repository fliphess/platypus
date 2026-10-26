package web

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The server formats instants in the requested zone. This is what stops a
// swapped fragment from flashing UTC: the text arrives already local.
func TestTimeFuncRendersTheRequestedZone(t *testing.T) {
	amsterdam, err := time.LoadLocation("Europe/Amsterdam")
	if err != nil {
		t.Fatal(err)
	}
	instant := time.Date(2026, 10, 25, 23, 36, 0, 0, time.UTC)

	render := func(loc *time.Location) string {
		return string(renderTimes([]byte(timeMarkerFunc(instant)), loc))
	}
	local := render(amsterdam)
	if want := `>2026-10-26 00:36</time>`; !regexp.MustCompile(`2026-10-26 00:36</time>`).MatchString(local) {
		t.Errorf("local time renders as %s, want %s", local, want)
	}
	if regexp.MustCompile(` UTC</time>`).MatchString(local) {
		t.Errorf("local time still carries a UTC suffix: %s", local)
	}
	// The instant itself is unchanged, for the browser's own formatting.
	if !regexp.MustCompile(`datetime="2026-10-25T23:36:00Z"`).MatchString(local) {
		t.Errorf("local time lost the canonical instant: %s", local)
	}

	utc := render(time.UTC)
	if !regexp.MustCompile(`>2026-10-25 23:36 UTC</time>`).MatchString(utc) {
		t.Errorf("UTC time renders as %s", utc)
	}
	if strings.ContainsRune(local+utc, 0) {
		t.Error("a time marker leaked into the page")
	}
}

func TestParseZoneRejectsJunk(t *testing.T) {
	for _, name := range []string{"", "Local", "Nowhere/Invalid", "../../etc/passwd", string(make([]byte, 80))} {
		if _, _, ok := parseZone(name); ok {
			t.Errorf("parseZone(%q) was accepted", name)
		}
	}
	if _, _, ok := parseZone("+01:00"); !ok {
		t.Error("a numeric offset should be accepted")
	}
}

// A browser that reports its zone gets server-rendered local times, so no
// JavaScript has to correct them after paint.
func TestAuditTimesRenderInTheReportedZone(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)
	h.get("/admin/audit", admin)

	// The harness client follows the redirect, so this ends on the profile page.
	h.expect(h.post("/me/profile", admin, url.Values{
		"display_name": {"Ada Admin"}, "department": {"Platform"}, "timezone": {"local"},
	}), http.StatusOK)

	// Send the cookie explicitly: the harness client does not keep a jar for
	// this, and the point is the server's rendering, not cookie storage.
	req, err := http.NewRequest(http.MethodGet, h.srv.URL+"/admin/audit", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Auth-Request-Email", admin)
	req.AddCookie(&http.Cookie{Name: zoneCookie, Value: "Europe/Amsterdam"})
	resp, err := h.client(admin).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if !regexp.MustCompile(`data-timezone="local"`).MatchString(body) {
		t.Fatalf("page does not know the preference is local: %s", body[:600])
	}
	match := regexp.MustCompile(`<time datetime="([^"]+)" data-utc="[^"]*">([^<]+)</time>`).FindStringSubmatch(body)
	if match == nil {
		t.Fatal("no time element on the audit page")
	}
	instant, err := time.Parse(time.RFC3339, match[1])
	if err != nil {
		t.Fatal(err)
	}
	amsterdam, err := time.LoadLocation("Europe/Amsterdam")
	if err != nil {
		t.Fatal(err)
	}
	if want := instant.In(amsterdam).Format("2006-01-02 15:04"); match[2] != want {
		t.Errorf("audit time shows %q, want %q (server-side local)", match[2], want)
	}
}
