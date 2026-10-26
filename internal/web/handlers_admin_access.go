package web

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"platypus/internal/access"
	"platypus/internal/auth"
	"platypus/internal/authz"
	"platypus/internal/db"
	"platypus/internal/item"
	"platypus/internal/problem"
)

// Users

type usersData struct {
	Users []access.ListedUser
	// PoliciesByUser lists the policy names reaching each user on this page.
	PoliciesByUser map[int64][]string
	Search         string
	WithoutAccess  bool
	Total          int64
	Page           int
	LastPage       int
	Pager          pager
	// ReturnTo is the list's own URL, sent by the per-row forms so an admin
	// stays on the list.
	ReturnTo string
	// CSRFToken lets the per-row native form work without htmx.
	CSRFToken string
}

// adminUsers lists users, a page at a time. With ?access=none it lists only
// users no policy reaches: people waiting for access, or who shouldn't be
// here at all. Accounts are never created by typing an address
// (typosquatting): people appear here at their first login.
func (s *Server) adminUsers(w http.ResponseWriter, r *http.Request) error {
	pageNumber := pageNumber(r)
	size := pageSize(r)
	filter := access.UserFilter{
		Search: r.URL.Query().Get("q"), WithoutAccess: r.URL.Query().Get("access") == "none",
		Page: pageNumber, PerPage: size,
	}
	users, total, err := s.services.Access.UserList(r.Context(), filter)
	if err != nil {
		return err
	}
	lastPage := lastPage(total, size)
	data := usersData{Users: users, Search: filter.Search, WithoutAccess: filter.WithoutAccess,
		Total: total, Page: pageNumber, LastPage: lastPage, ReturnTo: usersReturnTo(filter, pageNumber),
		CSRFToken: viewerFrom(r.Context()).Session.CSRFToken}
	data.Pager = newPager("/admin/users", "#user-list",
		fmt.Sprintf("Page %d of %d · %d users", pageNumber, lastPage, total),
		r.URL.Query(), pageNumber, lastPage, size, total)
	ids := make([]int64, len(users))
	for i, u := range users {
		ids[i] = u.ID
	}
	data.PoliciesByUser, err = s.services.Access.PolicyNamesForUsers(r.Context(), ids)
	if err != nil {
		return err
	}
	if isHTMX(r) {
		s.renderFragment(w, r, http.StatusOK, "admin_users", "user-list", data)
		return nil
	}
	s.render(w, r, http.StatusOK, "admin_users", page{Title: "Users", Tab: "admin", Data: data})
	return nil
}

// usersReturnTo is the list's own address, keeping the search, the view and
// the page, so actions taken from a row return to the same view.
func usersReturnTo(filter access.UserFilter, page int) string {
	query := url.Values{}
	if filter.WithoutAccess {
		query.Set("access", "none")
	}
	if filter.Search != "" {
		query.Set("q", filter.Search)
	}
	if page > 1 {
		query.Set("page", strconv.Itoa(page))
	}
	if filter.PerPage != DefaultPageSize {
		query.Set("per_page", strconv.Itoa(filter.PerPage))
	}
	if len(query) == 0 {
		return "/admin/users"
	}
	return "/admin/users?" + query.Encode()
}

type userData struct {
	Detail access.UserDetail
	Rules  []authz.Rule
	// Lines are the user's attached teams, with the facts each line shows.
	Lines []teamLine
	// SelectableTeams are the teams a person can be added to by hand.
	SelectableTeams []db.ListTeamsRow
	AllPolicies     []db.ListPoliciesRow
	IsSelf          bool
}

// teamLine is one attached team as the team editor shows it.
type teamLine struct {
	Team     db.Team
	Policies int64
}

func (s *Server) adminUser(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	detail, err := s.services.Access.UserDetail(r.Context(), id)
	if err != nil {
		return err
	}
	rules, err := s.services.Access.Rules(r.Context(), id)
	if err != nil {
		return err
	}
	teams, err := s.services.Access.Teams(r.Context(), "")
	if err != nil {
		return err
	}
	policies, err := s.services.Access.Policies(r.Context(), "")
	if err != nil {
		return err
	}
	counts := make(map[int64]int64, len(teams))
	selectable := make([]db.ListTeamsRow, 0, len(teams))
	for _, team := range teams {
		counts[team.ID] = team.PolicyCount
		if team.IDPGroup == nil {
			selectable = append(selectable, team)
		}
	}
	lines := make([]teamLine, 0, len(detail.Teams))
	for _, team := range detail.Teams {
		lines = append(lines, teamLine{Team: team, Policies: counts[team.ID]})
	}
	data := userData{
		Detail: detail, Rules: rules, AllPolicies: policies,
		Lines: lines, SelectableTeams: selectable,
		IsSelf: id == viewerFrom(r.Context()).User.ID,
	}
	s.render(w, r, http.StatusOK, "admin_user", page{Title: detail.User.Label(), Tab: "admin", Data: data})
	return nil
}

// userAction runs an admin action on the user in the URL and returns to
// their page, or back to the page the form came from (return, a local path:
// the users list sends it so an admin can work through the list).
func (s *Server) userAction(action func(r *http.Request, userID int64) error) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		id, err := pathID(r)
		if err != nil {
			return err
		}
		if err := action(r, id); err != nil {
			return err
		}
		if back := auth.SafeReturnPath(r.PostFormValue("return")); back != "/" {
			sep := "?"
			if strings.Contains(back, "?") {
				sep = "&"
			}
			s.redirect(w, r, back+sep+"notice=saved")
			return nil
		}
		s.redirect(w, r, fmt.Sprintf("/admin/users/%d?notice=saved", id))
		return nil
	}
}

func (s *Server) setUserAdmin(r *http.Request, id int64) error {
	return s.services.Access.SetAdmin(r.Context(), id, r.PostFormValue("admin") == "true")
}

func (s *Server) setUserDisabled(r *http.Request, id int64) error {
	return s.services.Access.SetDisabled(r.Context(), id, r.PostFormValue("disabled") == "true")
}

func (s *Server) unlockUser(r *http.Request, id int64) error {
	return s.services.Access.Unlock(r.Context(), id)
}

func (s *Server) setUserTeams(r *http.Request, id int64) error {
	teamIDs, err := formIDs(r, "team_id")
	if err != nil {
		return err
	}
	return s.services.Access.SetUserTeams(r.Context(), id, teamIDs)
}

// changeMessage is the one sentence a confirmation shows: what is added and
// what is removed, by name.
func changeMessage(added, removed []string) string {
	parts := make([]string, 0, 2)
	if len(added) > 0 {
		parts = append(parts, "Add: "+strings.Join(added, ", "))
	}
	if len(removed) > 0 {
		parts = append(parts, "Remove: "+strings.Join(removed, ", "))
	}
	if len(parts) == 0 {
		return "Nothing changes."
	}
	return strings.Join(parts, ". ") + "."
}

func namesByID(ids []int64, names map[int64]string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, names[id])
	}
	sort.Strings(out)
	return out
}

// selectionDiff reports which ids were added and which removed.
func selectionDiff(current, selected []int64) (added, removed []int64) {
	inCurrent := make(map[int64]bool, len(current))
	for _, id := range current {
		inCurrent[id] = true
	}
	inSelected := make(map[int64]bool, len(selected))
	for _, id := range selected {
		inSelected[id] = true
	}
	for _, id := range selected {
		if !inCurrent[id] {
			added = append(added, id)
		}
	}
	for _, id := range current {
		if !inSelected[id] {
			removed = append(removed, id)
		}
	}
	return added, removed
}

// policyNames is the id-to-name map both policy confirmations show.
func (s *Server) policyNames(r *http.Request) (map[int64]string, error) {
	all, err := s.services.Access.Policies(r.Context(), "")
	if err != nil {
		return nil, err
	}
	names := make(map[int64]string, len(all))
	for _, policy := range all {
		names[policy.ID] = policy.Name
	}
	return names, nil
}

// confirmPage renders the page that shows what a save will change.
func (s *Server) confirmPage(w http.ResponseWriter, r *http.Request, data confirmSave) {
	s.render(w, r, http.StatusOK, "admin_confirm", page{Title: data.Title, Tab: "admin", Data: data})
}

func (s *Server) previewUserPolicies(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	ids, err := formIDs(r, "policy_id")
	if err != nil {
		return err
	}
	detail, err := s.services.Access.UserDetail(r.Context(), id)
	if err != nil {
		return err
	}
	names, err := s.policyNames(r)
	if err != nil {
		return err
	}
	current := make([]int64, 0, len(detail.Policies))
	for _, policy := range detail.Policies {
		current = append(current, policy.ID)
	}
	added, removed := selectionDiff(current, ids)
	s.confirmPage(w, r, confirmSave{
		Section: "users", Title: "Save these policies?",
		Message: changeMessage(namesByID(added, names), namesByID(removed, names)),
		Button:  "Save policies", Action: fmt.Sprintf("/admin/users/%d/policies", id),
		Back: fmt.Sprintf("/admin/users/%d", id), Hidden: hiddenIDs("policy_id", ids),
	})
	return nil
}

func (s *Server) previewTeamPolicies(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	ids, err := formIDs(r, "policy_id")
	if err != nil {
		return err
	}
	detail, err := s.services.Access.TeamDetail(r.Context(), id)
	if err != nil {
		return err
	}
	names, err := s.policyNames(r)
	if err != nil {
		return err
	}
	current := make([]int64, 0, len(detail.Policies))
	for _, policy := range detail.Policies {
		current = append(current, policy.ID)
	}
	added, removed := selectionDiff(current, ids)
	s.confirmPage(w, r, confirmSave{
		Section: "teams", Title: "Save these policies?",
		Message: changeMessage(namesByID(added, names), namesByID(removed, names)),
		Button:  "Save policies", Action: fmt.Sprintf("/admin/teams/%d/policies", id),
		Back: fmt.Sprintf("/admin/teams/%d", id), Hidden: hiddenIDs("policy_id", ids),
	})
	return nil
}

func (s *Server) previewUserTeams(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	ids, err := formIDs(r, "team_id")
	if err != nil {
		return err
	}
	detail, err := s.services.Access.UserDetail(r.Context(), id)
	if err != nil {
		return err
	}
	teams, err := s.services.Access.Teams(r.Context(), "")
	if err != nil {
		return err
	}
	names := make(map[int64]string, len(teams))
	for _, team := range teams {
		names[team.ID] = team.Name
	}
	current := make([]int64, 0, len(detail.Teams))
	linked := false
	for _, team := range detail.Teams {
		if team.IDPGroup != nil {
			// Membership comes from the identity provider: never shown as a change.
			linked = true
			continue
		}
		current = append(current, team.ID)
	}
	added, removed := selectionDiff(current, ids)
	message := changeMessage(namesByID(added, names), namesByID(removed, names))
	if linked {
		message += " Group-linked teams stay as they are."
	}
	s.confirmPage(w, r, confirmSave{
		Section: "users", Title: "Save these teams?", Message: message,
		Button: "Save teams", Action: fmt.Sprintf("/admin/users/%d/teams", id),
		Back: fmt.Sprintf("/admin/users/%d", id), Hidden: hiddenIDs("team_id", ids),
	})
	return nil
}

func (s *Server) setUserPolicies(r *http.Request, id int64) error {
	policyIDs, err := formIDs(r, "policy_id")
	if err != nil {
		return err
	}
	return s.services.Access.SetUserPolicies(r.Context(), id, policyIDs)
}

// newUserPage shows the form that creates an account ahead of someone's
// first login. It is its own page: the users list stays a list.
func (s *Server) newUserPage(w http.ResponseWriter, r *http.Request) error {
	s.render(w, r, http.StatusOK, "admin_user_new", page{Title: "New user", Tab: "admin"})
	return nil
}

func (s *Server) addUser(w http.ResponseWriter, r *http.Request) error {
	user, err := s.services.Access.AddUser(r.Context(), r.PostFormValue("email"))
	if err != nil {
		return err
	}
	s.redirect(w, r, fmt.Sprintf("/admin/users/%d?notice=created", user.ID))
	return nil
}

// Teams

func (s *Server) newTeamPage(w http.ResponseWriter, r *http.Request) error {
	s.render(w, r, http.StatusOK, "admin_team_new", page{Title: "New team", Tab: "admin"})
	return nil
}

type teamsData struct {
	Teams    []db.ListTeamsPageRow
	Search   string
	Page     int
	LastPage int
	Total    int64
	Pager    pager
}

func (s *Server) adminTeams(w http.ResponseWriter, r *http.Request) error {
	search := r.URL.Query().Get("q")
	pageNumber := pageNumber(r)
	size := pageSize(r)
	teams, total, err := s.services.Access.TeamsPage(r.Context(), search, pageNumber, size)
	if err != nil {
		return err
	}
	lastPage := lastPage(total, size)
	data := teamsData{Teams: teams, Search: search, Page: pageNumber, LastPage: lastPage, Total: total}
	data.Pager = newPager("/admin/teams", "#team-list",
		fmt.Sprintf("Page %d of %d · %d teams", pageNumber, lastPage, total),
		r.URL.Query(), pageNumber, lastPage, size, total)
	if isHTMX(r) {
		s.renderFragment(w, r, http.StatusOK, "admin_teams", "team-list", data)
		return nil
	}
	s.render(w, r, http.StatusOK, "admin_teams", page{Title: "Teams", Tab: "admin", Data: data})
	return nil
}

func (s *Server) createTeam(w http.ResponseWriter, r *http.Request) error {
	team, err := s.services.Access.CreateTeam(r.Context(), teamInput(r))
	if err != nil {
		return err
	}
	s.redirect(w, r, fmt.Sprintf("/admin/teams/%d?notice=created", team.ID))
	return nil
}

// teamInput reads the team form: name, description and the optional
// identity-provider group link.
func teamInput(r *http.Request) access.TeamInput {
	return access.TeamInput{
		Name: r.PostFormValue("name"), Description: r.PostFormValue("description"),
		IDPGroup: r.PostFormValue("idp_group"),
	}
}

type teamData struct {
	Detail      access.TeamDetail
	AllPolicies []db.ListPoliciesRow
	// Candidates are the people who are not on the team yet, for the member
	// dropdown.
	Candidates []db.User
}

func (s *Server) adminTeam(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	detail, err := s.services.Access.TeamDetail(r.Context(), id)
	if err != nil {
		return err
	}
	policies, err := s.services.Access.Policies(r.Context(), "")
	if err != nil {
		return err
	}
	users, err := s.services.Access.Users(r.Context(), "")
	if err != nil {
		return err
	}
	members := make(map[int64]bool, len(detail.Members))
	for _, member := range detail.Members {
		members[member.ID] = true
	}
	candidates := make([]db.User, 0, len(users))
	for _, user := range users {
		if !members[user.ID] {
			candidates = append(candidates, user)
		}
	}
	data := teamData{Detail: detail, AllPolicies: policies, Candidates: candidates}
	s.render(w, r, http.StatusOK, "admin_team", page{Title: detail.Team.Name, Tab: "admin", Data: data})
	return nil
}

// teamAction runs an admin action on the team in the URL and returns to its page.
func (s *Server) teamAction(action func(r *http.Request, teamID int64) error) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		id, err := pathID(r)
		if err != nil {
			return err
		}
		if err := action(r, id); err != nil {
			return err
		}
		s.redirect(w, r, fmt.Sprintf("/admin/teams/%d?notice=saved", id))
		return nil
	}
}

func (s *Server) updateTeam(r *http.Request, id int64) error {
	return s.services.Access.UpdateTeam(r.Context(), id, teamInput(r))
}

func (s *Server) setTeamPolicies(r *http.Request, id int64) error {
	policyIDs, err := formIDs(r, "policy_id")
	if err != nil {
		return err
	}
	return s.services.Access.SetTeamPolicies(r.Context(), id, policyIDs)
}

// addTeamMember adds someone picked from the list (user_id). There is
// deliberately no free-text email entry: an open field invites typos that
// hand access to the wrong address (typosquatting).
func (s *Server) addTeamMember(r *http.Request, id int64) error {
	if err := r.ParseForm(); err != nil {
		return problem.Invalid("The form could not be read.")
	}
	// The member editor can hold several lines; add every chosen person.
	added := false
	for _, raw := range r.PostForm["user_id"] {
		if raw == "" {
			continue
		}
		userID, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || userID <= 0 {
			return problem.Invalid("Pick a person from the list.")
		}
		if err := s.services.Access.AddTeamMember(r.Context(), id, userID); err != nil {
			return err
		}
		added = true
	}
	if !added {
		return problem.Invalid("Pick a person from the list.")
	}
	return nil
}

// maxCandidates caps the people the member picker shows at once.
const maxCandidates = 20

type candidatesData struct {
	TeamID int64
	Users  []db.User
	// Capped is set when the list was cut short: typing narrows it.
	Capped bool
}

// teamCandidates lists the people who may join the team: everyone with an
// account who isn't a member yet. The list shows straight away, so nobody
// has to know or type an address, and narrows while typing (name, email or
// its username part).
func (s *Server) teamCandidates(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	detail, err := s.services.Access.TeamDetail(r.Context(), id)
	if err != nil {
		return err
	}
	users, err := s.services.Access.Users(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		return err
	}
	members := map[int64]bool{}
	for _, m := range detail.Members {
		members[m.ID] = true
	}
	data := candidatesData{TeamID: id}
	for _, u := range users {
		if members[u.ID] {
			continue
		}
		if len(data.Users) == maxCandidates {
			data.Capped = true
			break
		}
		data.Users = append(data.Users, u)
	}
	s.renderFragment(w, r, http.StatusOK, "admin_team", "candidates", data)
	return nil
}

func (s *Server) removeTeamMember(r *http.Request, id int64) error {
	userID, err := strconv.ParseInt(r.PostFormValue("user_id"), 10, 64)
	if err != nil {
		return problem.Invalid("Unknown user.")
	}
	return s.services.Access.RemoveTeamMember(r.Context(), id, userID)
}

func (s *Server) previewDeleteTeam(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	detail, err := s.services.Access.TeamDetail(r.Context(), id)
	if err != nil {
		return err
	}
	s.renderFragment(w, r, http.StatusOK, "admin_team", "confirm-action", confirmAction{
		Title: "Delete team " + detail.Team.Name + "?",
		Message: fmt.Sprintf("Its members (%s) lose the policies they had through this team. This can't be undone.",
			count(len(detail.Members), "person", "people")),
		Button: "Delete team",
		Action: fmt.Sprintf("/admin/teams/%d/delete", id),
		Form:   "delete-team",
	})
	return nil
}

func (s *Server) deleteTeam(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	if err := s.services.Access.DeleteTeam(r.Context(), id); err != nil {
		return err
	}
	s.redirect(w, r, "/admin/teams?notice=deleted")
	return nil
}

// Policies

type policiesData struct {
	Policies []db.ListPoliciesPageRow
	Search   string
	Page     int
	LastPage int
	Total    int64
	Pager    pager
}

func (s *Server) adminPolicies(w http.ResponseWriter, r *http.Request) error {
	search := r.URL.Query().Get("q")
	pageNumber := pageNumber(r)
	size := pageSize(r)
	policies, total, err := s.services.Access.PoliciesPage(r.Context(), search, pageNumber, size)
	if err != nil {
		return err
	}
	lastPage := lastPage(total, size)
	data := policiesData{Policies: policies, Search: search, Page: pageNumber, LastPage: lastPage, Total: total}
	data.Pager = newPager("/admin/policies", "#policy-list",
		fmt.Sprintf("Page %d of %d · %d policies", pageNumber, lastPage, total),
		r.URL.Query(), pageNumber, lastPage, size, total)
	if isHTMX(r) {
		s.renderFragment(w, r, http.StatusOK, "admin_policies", "policy-list", data)
		return nil
	}
	s.render(w, r, http.StatusOK, "admin_policies", page{Title: "Policies", Tab: "admin", Data: data})
	return nil
}

type policyFormData struct {
	ID    int64
	Input access.PolicyInput
	Users []db.User
	Teams []db.Team
	Kinds []item.Kind
}

func (s *Server) newPolicyForm(w http.ResponseWriter, r *http.Request) error {
	data := policyFormData{Kinds: item.Kinds, Input: access.PolicyInput{}}
	s.render(w, r, http.StatusOK, "admin_policy", page{Title: "New policy", Tab: "admin", Data: data})
	return nil
}

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) error {
	policy, err := s.services.Access.CreatePolicy(r.Context(), policyFromForm(r))
	if err != nil {
		return err
	}
	s.redirect(w, r, fmt.Sprintf("/admin/policies/%d?notice=created", policy.ID))
	return nil
}

func (s *Server) editPolicyForm(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	detail, err := s.services.Access.PolicyDetail(r.Context(), id)
	if err != nil {
		return err
	}
	data := policyFormData{ID: id, Input: detail.Input(), Users: detail.Users, Teams: detail.Teams, Kinds: item.Kinds}
	s.render(w, r, http.StatusOK, "admin_policy", page{Title: detail.Policy.Name, Tab: "admin", Data: data})
	return nil
}

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	if err := s.services.Access.UpdatePolicy(r.Context(), id, policyFromForm(r)); err != nil {
		return err
	}
	s.redirect(w, r, fmt.Sprintf("/admin/policies/%d?notice=saved", id))
	return nil
}

func (s *Server) previewDeletePolicy(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	detail, err := s.services.Access.PolicyDetail(r.Context(), id)
	if err != nil {
		return err
	}
	s.renderFragment(w, r, http.StatusOK, "admin_policy", "confirm-action", confirmAction{
		Title: "Delete policy " + detail.Policy.Name + "?",
		Message: fmt.Sprintf("%s and %s lose the access this policy gives them. This can't be undone.",
			count(len(detail.Users), "user", "users"), count(len(detail.Teams), "team", "teams")),
		Button: "Delete policy",
		Action: fmt.Sprintf("/admin/policies/%d/delete", id),
		Form:   "delete-policy",
	})
	return nil
}

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	if err := s.services.Access.DeletePolicy(r.Context(), id); err != nil {
		return err
	}
	s.redirect(w, r, "/admin/policies?notice=deleted")
	return nil
}

type rulePreview struct {
	Number  int
	Pattern string
	Kind    item.Kind
	Count   int64
	Problem string
}

// previewPolicy counts how many items each rule matches, so admins see right
// away whether a pattern is too broad or matches nothing. Counts only.
// previewPolicyCreate and previewPolicySave confirm the change before it is
// made: the dialog names what happens, and Continue submits the form itself.
func (s *Server) previewPolicyCreate(w http.ResponseWriter, r *http.Request) error {
	s.renderFragment(w, r, http.StatusOK, "admin_policy", "confirm-action", confirmAction{
		Title: "Create this policy?",
		Message: "It exists from now on and can be assigned to people and teams. " +
			"Nothing is granted until it is assigned.",
		Button: "Create policy", Action: "/admin/policies", Form: "policy-form",
	})
	return nil
}

func (s *Server) previewPolicySave(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	detail, err := s.services.Access.PolicyDetail(r.Context(), id)
	if err != nil {
		return err
	}
	s.renderFragment(w, r, http.StatusOK, "admin_policy", "confirm-action", confirmAction{
		Title: "Save this policy?",
		Message: fmt.Sprintf("Saving changes the rules and permissions in %q for everyone who has it.",
			detail.Policy.Name),
		Button: "Save policy", Action: fmt.Sprintf("/admin/policies/%d", id), Form: "policy-form",
	})
	return nil
}

func (s *Server) previewPolicy(w http.ResponseWriter, r *http.Request) error {
	in := policyFromForm(r)
	previews := make([]rulePreview, 0, len(in.Rules))
	for i, rule := range in.Rules {
		preview := rulePreview{Number: i + 1, Pattern: rule.Pattern, Kind: rule.Kind}
		pattern, err := authz.ParsePattern(rule.Pattern)
		if err != nil {
			preview.Problem = err.Error()
		} else if preview.Count, err = s.services.Catalog.Count(r.Context(), rule.Kind, []authz.Pattern{pattern}); err != nil {
			return err
		}
		previews = append(previews, preview)
	}
	s.renderFragment(w, r, http.StatusOK, "admin_policy", "rule-preview", previews)
	return nil
}

// policyFromForm reads the rule editor. Each rule row has an id; permission
// checkboxes carry "<row id>:<permission>" so unticked boxes don't shift
// rows.
func policyFromForm(r *http.Request) access.PolicyInput {
	_ = r.ParseForm()
	in := access.PolicyInput{Name: r.PostFormValue("name"), Description: r.PostFormValue("description")}
	ids := r.PostForm["rule_id"]
	kinds := r.PostForm["rule_kind"]
	patterns := r.PostForm["rule_pattern"]
	granted := r.PostForm["rule_permission"]
	for i, id := range ids {
		if i >= len(kinds) || i >= len(patterns) {
			break
		}
		has := func(p authz.Permission) bool { return slices.Contains(granted, id+":"+string(p)) }
		in.Rules = append(in.Rules, access.RuleInput{
			Kind:    item.Kind(kinds[i]),
			Pattern: patterns[i],
			Permissions: authz.Permissions{
				List: has(authz.List), Create: has(authz.Create), Edit: has(authz.Edit), Reveal: has(authz.Reveal),
			},
		})
	}
	return in
}

func pathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, problem.NotFound("This page doesn't exist.")
	}
	return id, nil
}

func formIDs(r *http.Request, field string) ([]int64, error) {
	if err := r.ParseForm(); err != nil {
		return nil, problem.Invalid("The form could not be read.")
	}
	ids := make([]int64, 0, len(r.PostForm[field]))
	for _, raw := range r.PostForm[field] {
		// An empty dropdown line is "nothing chosen", not a bad value.
		if raw == "" {
			continue
		}
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, problem.Invalid("The form contains an unknown selection.")
		}
		ids = append(ids, id)
	}
	return ids, nil
}
