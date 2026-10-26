package web

import (
	"net/http"
	"slices"
	"strings"

	"platypus/internal/item"
)

// adminModeRoutes are the only routes under /admin that work outside admin
// mode: they are how an admin enters and leaves it.
var adminModeRoutes = []string{
	"GET /admin/elevate",
	"POST /admin/elevate/totp",
	"POST /admin/elevate/recovery",
	"POST /admin/elevate/passkey/begin",
	"POST /admin/elevate/passkey/finish",
	"POST /admin/leave",
}

// routes lists every page and action. Admin routes are in adminRoutes.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	register := func(pattern string, h http.Handler) {
		if underAdmin(pattern) && !slices.Contains(adminModeRoutes, pattern) {
			panic("route " + pattern + " is under /admin: list it in adminRoutes, which require admin mode")
		}
		mux.Handle(pattern, h)
	}
	handle := func(pattern string, h handlerFunc) { register(pattern, s.handle(h)) }
	handleJSON := func(pattern string, h handlerFunc) { register(pattern, s.handleJSON(h)) }

	handle("GET /{$}", s.home)

	for _, kind := range item.Kinds {
		base := "/" + kindPath(kind)
		handle("GET "+base, s.browse(kind))
		handle("GET "+base+"/item", s.itemDetail(kind))
		handle("POST "+base+"/reveal", s.reveal(kind))
		handle("GET "+base+"/new", s.newItemForm(kind))
		handle("POST "+base+"/new/preview", s.previewCreate(kind))
		handle("POST "+base+"/new", s.createItem(kind))
		handle("GET "+base+"/edit", s.editItemForm(kind))
		handle("POST "+base+"/edit/value", s.loadValue(kind))
		handle("POST "+base+"/edit/preview", s.previewUpdate(kind))
		handle("POST "+base+"/edit", s.updateItem(kind))
		handle("POST "+base+"/rollback/preview", s.previewRollback(kind))
		handle("POST "+base+"/rollback", s.rollback(kind))
		handle("POST "+base+"/note", s.saveNote(kind))
	}

	handle("GET /docs", s.docsPage)
	handle("GET /docs/{slug}", s.docsPage)
	handle("GET /me", s.myPermissions)
	handle("GET /me/profile", s.profilePage)
	handle("POST /me/profile", s.updateProfile)

	handle("GET /me/security", s.securityPage)
	handle("POST /me/security/totp", s.startTOTP)
	handle("POST /me/security/totp/confirm", s.confirmTOTP)
	handle("POST /me/security/totp/remove/preview", s.previewRemoveTOTP)
	handle("POST /me/security/totp/remove", s.removeTOTP)
	handle("POST /me/security/passkeys/remove/preview", s.previewRemovePasskey)
	handle("POST /me/security/passkeys/remove", s.removePasskey)
	handle("POST /me/security/recovery-codes/preview", s.previewRecoveryCodes)
	handle("POST /me/security/recovery-codes", s.issueRecoveryCodes)
	handleJSON("POST /me/security/passkeys/begin", s.beginPasskeyRegistration)
	handleJSON("POST /me/security/passkeys/finish", s.finishPasskeyRegistration)

	handle("GET /bootstrap", s.bootstrapPage)
	handle("POST /bootstrap/token", s.enterBootstrapToken)
	handle("POST /bootstrap/complete", s.completeBootstrap)

	handle("GET /admin/elevate", s.elevatePage)
	handle("POST /admin/elevate/totp", s.elevateWithTOTP)
	handle("POST /admin/elevate/recovery", s.elevateWithRecoveryCode)
	handleJSON("POST /admin/elevate/passkey/begin", s.beginPasskeyElevation)
	handleJSON("POST /admin/elevate/passkey/finish", s.finishPasskeyElevation)
	handle("POST /admin/leave", s.leaveAdminMode)
	handle("POST /auth/logout", s.logout)
	handle("POST /secrets/undelete", s.undeleteSecret)

	for _, route := range s.adminRoutes() {
		mux.Handle(route.pattern, s.adminOnly(s.handle(route.handler)))
	}

	return mux
}

type route struct {
	pattern string
	handler handlerFunc
}

// adminRoutes need admin mode. They are a list of their own, so a test can
// check that every one of them refuses everybody else.
func (s *Server) adminRoutes() []route {
	return []route{
		{"GET /admin", s.adminOverview},
		{"POST /admin/block/preview", s.previewBlock},
		{"POST /admin/block", s.setBlocked(true)},
		{"POST /admin/unblock", s.setBlocked(false)},
		{"POST /admin/sync", s.requestSync},
		{"GET /admin/notes", s.orphanedNotes},

		{"GET /admin/users", s.adminUsers},
		{"GET /admin/users/new", s.newUserPage},
		{"POST /admin/users", s.addUser},
		{"GET /admin/users/{id}", s.adminUser},
		{"POST /admin/users/{id}/admin", s.userAction(s.setUserAdmin)},
		{"POST /admin/users/{id}/disabled/preview", s.previewSetUserDisabled},
		{"POST /admin/users/{id}/disabled", s.userAction(s.setUserDisabled)},
		{"POST /admin/users/{id}/unlock", s.userAction(s.unlockUser)},
		{"POST /admin/users/{id}/teams/preview", s.previewUserTeams},
		{"POST /admin/users/{id}/teams", s.userAction(s.setUserTeams)},
		{"POST /admin/users/{id}/policies/preview", s.previewUserPolicies},
		{"POST /admin/users/{id}/policies", s.userAction(s.setUserPolicies)},

		{"GET /admin/teams", s.adminTeams},
		{"GET /admin/teams/new", s.newTeamPage},
		{"POST /admin/teams", s.createTeam},
		{"GET /admin/teams/{id}", s.adminTeam},
		{"POST /admin/teams/{id}", s.teamAction(s.updateTeam)},
		{"POST /admin/teams/{id}/policies/preview", s.previewTeamPolicies},
		{"POST /admin/teams/{id}/policies", s.teamAction(s.setTeamPolicies)},
		{"GET /admin/teams/{id}/candidates", s.teamCandidates},
		{"POST /admin/teams/{id}/members", s.teamAction(s.addTeamMember)},
		{"POST /admin/teams/{id}/members/remove/preview", s.previewRemoveTeamMember},
		{"POST /admin/teams/{id}/members/remove", s.teamAction(s.removeTeamMember)},
		{"POST /admin/teams/{id}/delete/preview", s.previewDeleteTeam},
		{"POST /admin/teams/{id}/delete", s.deleteTeam},

		{"GET /admin/policies", s.adminPolicies},
		{"GET /admin/policies/new", s.newPolicyForm},
		{"POST /admin/policies", s.createPolicy},
		{"POST /admin/policies/preview", s.previewPolicy},
		{"POST /admin/policies/preview-create", s.previewPolicyCreate},
		{"POST /admin/policies/{id}/save/preview", s.previewPolicySave},
		{"GET /admin/policies/{id}", s.editPolicyForm},
		{"POST /admin/policies/{id}", s.updatePolicy},
		{"POST /admin/policies/{id}/delete/preview", s.previewDeletePolicy},
		{"POST /admin/policies/{id}/delete", s.deletePolicy},

		{"GET /admin/audit", s.auditTrail},
		{"GET /admin/audit.csv", s.exportAudit},
		{"POST /admin/audit/prune/preview", s.previewPrune},
		{"POST /admin/audit/prune", s.pruneAudit},
	}
}

// underAdmin reports whether a route pattern's path is in the /admin area.
func underAdmin(pattern string) bool {
	_, path, found := strings.Cut(pattern, " ")
	if !found {
		path = pattern
	}
	return path == "/admin" || strings.HasPrefix(path, "/admin/") || strings.HasPrefix(path, "/admin.")
}
