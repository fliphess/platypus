package access

import (
	"context"
	"crypto/rand"
	"fmt"
	"slices"
	"strings"
	"time"

	"platypus/internal/audit"
	"platypus/internal/database"
	"platypus/internal/db"
	"platypus/internal/problem"
	"platypus/internal/textclean"
)

// seenInterval limits how often last_seen_at is written: once per interval
// is plenty and saves a write on every request.
const seenInterval = 5 * time.Minute

// UserForLogin returns the user for a verified email address, creating the
// account on first login. Accounts an admin added ahead of time are matched
// by email. name, when the login method knows it, fills in an empty profile
// name. groups is what the login reported for the identity provider's groups:
// nil when this deployment doesn't read groups, otherwise the user's
// memberships in group-linked teams are made to match.
func (s *Service) UserForLogin(ctx context.Context, email, name string, groups []string) (db.User, error) {
	user, err := s.queries.GetUserByEmail(ctx, email)
	if err == nil {
		return s.afterLogin(ctx, user, name, groups)
	}
	if !database.IsNoRows(err) {
		return db.User{}, fmt.Errorf("find user: %w", err)
	}

	user, created, err := s.createUser(ctx, email, nil)
	if err != nil {
		return db.User{}, err
	}
	if created {
		ctx = audit.WithActor(ctx, audit.Actor{UserID: user.ID, Email: user.Email})
		s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionUserCreated, Outcome: audit.Allowed,
			Details: map[string]any{"how": "first login"}})
	}
	return s.afterLogin(ctx, user, name, groups)
}

// afterLogin fills the profile name, records the visit and, when groups are
// read, stores them and syncs linked-team memberships.
func (s *Service) afterLogin(ctx context.Context, user db.User, name string, groups []string) (db.User, error) {
	if groups != nil {
		if err := s.applyGroups(ctx, user, groups); err != nil {
			return db.User{}, err
		}
	}
	return s.fillName(ctx, user, name), s.recordSeen(ctx, user)
}

// applyGroups stores the groups the login reported and moves the user's
// memberships in group-linked teams to match: in the group, in the team;
// out of it, out of the team. Teams without a link are never touched, and
// removing a link keeps members.
func (s *Service) applyGroups(ctx context.Context, user db.User, groups []string) error {
	if _, err := s.queries.SetUserGroups(ctx, db.SetUserGroupsParams{ID: user.ID, Groups: groups}); err != nil {
		return fmt.Errorf("store groups: %w", err)
	}
	added, err := s.queries.AddUserToGroupTeams(ctx, db.AddUserToGroupTeamsParams{UserID: user.ID, Groups: groups})
	if err != nil {
		return fmt.Errorf("join teams of linked groups: %w", err)
	}
	removed, err := s.queries.RemoveUserFromOtherGroupTeams(ctx, db.RemoveUserFromOtherGroupTeamsParams{UserID: user.ID, Groups: groups})
	if err != nil {
		return fmt.Errorf("leave teams of unlinked groups: %w", err)
	}
	if len(added) == 0 && len(removed) == 0 {
		return nil
	}
	details := map[string]any{"user": user.Email, "via": "group sync"}
	if names := s.teamNames(ctx, added); len(names) > 0 {
		details["added_to"] = names
	}
	if names := s.teamNames(ctx, removed); len(names) > 0 {
		details["removed_from"] = names
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionUserTeams, Outcome: audit.Allowed, Details: details})
	return nil
}

// teamNames returns the names of these teams, best effort: it is only used
// in audit details after the change has happened.
func (s *Service) teamNames(ctx context.Context, ids []int64) []string {
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		if team, err := s.queries.GetTeam(ctx, id); err == nil {
			names = append(names, team.Name)
		}
	}
	return names
}

// fillName sets the name from the identity provider when the user has none.
// Failing to do so is not worth failing the login over.
func (s *Service) fillName(ctx context.Context, user db.User, name string) db.User {
	name, err := textclean.Clean(name, textclean.Options{MaxLength: 100})
	if err != nil || name == "" || user.DisplayName != "" {
		return user
	}
	if s.queries.FillDisplayName(ctx, db.FillDisplayNameParams{ID: user.ID, DisplayName: name}) == nil {
		user.DisplayName = name
	}
	return user
}

// createUser inserts a user. When the email exists already (two requests
// racing), it returns the existing user with created false.
func (s *Service) createUser(ctx context.Context, email string, createdBy *string) (db.User, bool, error) {
	handle := make([]byte, 32)
	if _, err := rand.Read(handle); err != nil {
		return db.User{}, false, fmt.Errorf("generate user handle: %w", err)
	}
	user, err := s.queries.CreateUser(ctx, db.CreateUserParams{Email: email, WebAuthnHandle: handle, CreatedBy: createdBy})
	if database.IsNoRows(err) {
		existing, err := s.queries.GetUserByEmail(ctx, email)
		return existing, false, err
	}
	if err != nil {
		return db.User{}, false, fmt.Errorf("create user: %w", err)
	}
	return user, true, nil
}

func (s *Service) recordSeen(ctx context.Context, user db.User) error {
	if user.LastSeenAt != nil && s.now().Sub(*user.LastSeenAt) < seenInterval {
		return nil
	}
	if err := s.queries.RecordUserSeen(ctx, user.ID); err != nil {
		return fmt.Errorf("record user seen: %w", err)
	}
	return nil
}

// Profile is what users tell about themselves.
type Profile struct {
	DisplayName string `json:"display_name"`
	Department  string `json:"department"`
	// Timezone is "utc" (default) or "local" (the browser's time zone).
	Timezone string `json:"timezone"`
}

// UpdateProfile changes the viewer's own name and department.
func (s *Service) UpdateProfile(ctx context.Context, userID int64, p Profile) error {
	user, err := s.User(ctx, userID)
	if err != nil {
		return err
	}
	name, err := textclean.Clean(p.DisplayName, textclean.Options{MaxLength: 100})
	if err != nil {
		return problem.Invalid("Name: %v.", err)
	}
	department, err := textclean.Clean(p.Department, textclean.Options{MaxLength: 100})
	if err != nil {
		return problem.Invalid("Department: %v.", err)
	}
	timezone := p.Timezone
	if timezone != "local" {
		timezone = "utc"
	}
	if err := s.queries.UpdateProfile(ctx, db.UpdateProfileParams{ID: userID, DisplayName: name, Department: department, Timezone: timezone}); err != nil {
		return fmt.Errorf("update profile: %w", err)
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionUserProfile, Outcome: audit.Allowed,
		Details: map[string]any{
			"before": Profile{DisplayName: user.DisplayName, Department: user.Department, Timezone: user.Timezone},
			"after":  Profile{DisplayName: name, Department: department, Timezone: timezone},
		}})
	return nil
}

// User returns a user by id.
func (s *Service) User(ctx context.Context, id int64) (db.User, error) {
	user, err := s.queries.GetUser(ctx, id)
	if database.IsNoRows(err) {
		return db.User{}, problem.NotFound("This user doesn't exist.")
	}
	return user, err
}

// Users lists users whose email contains search (all users when empty).
func (s *Service) Users(ctx context.Context, search string) ([]db.User, error) {
	search, err := textclean.Clean(search, textclean.Options{MaxLength: 200})
	if err != nil {
		return nil, problem.Invalid("Search: %v.", err)
	}
	var filter *string
	if search != "" {
		escaped := likeEscaper.Replace(strings.ToLower(search))
		filter = &escaped
	}
	return s.queries.ListUsers(ctx, filter)
}

// UserFilter selects users for the admin list.
type UserFilter struct {
	Search string
	// WithoutAccess keeps only users no policy reaches.
	WithoutAccess bool
	// Page is the 1-based page number; PerPage is how many rows it asks for.
	Page    int
	PerPage int
}

// UsersPerPage is the default number of users the admin list shows per page.
const UsersPerPage = 50

// ListedUser is a user with the number of policies that reach them, directly
// or through their teams.
type ListedUser struct {
	db.User
	Policies int64
}

// UserList returns one page of users matching filter, and how many match in
// total (for the pager).
func (s *Service) UserList(ctx context.Context, filter UserFilter) ([]ListedUser, int64, error) {
	search, err := textclean.Clean(filter.Search, textclean.Options{MaxLength: 200})
	if err != nil {
		return nil, 0, problem.Invalid("Search: %v.", err)
	}
	perPage := filter.PerPage
	if perPage <= 0 {
		perPage = UsersPerPage
	}
	params := db.ListUsersWithAccessParams{WithoutAccess: filter.WithoutAccess}
	if search != "" {
		escaped := likeEscaper.Replace(strings.ToLower(search))
		params.Search = &escaped
	}
	total, err := s.queries.CountUsersWithAccess(ctx, db.CountUsersWithAccessParams{
		Search: params.Search, WithoutAccess: filter.WithoutAccess})
	if err != nil {
		return nil, 0, err
	}

	page := max(filter.Page, 1)
	page = min(page, 1_000_000)           //nolint:gosec // keeps the offset arithmetic in range
	offset := int32((page - 1) * perPage) //nolint:gosec // page and perPage are bounded above
	params.MaxRows, params.Skip = int32(perPage), offset
	rows, err := s.queries.ListUsersWithAccess(ctx, params)
	if err != nil {
		return nil, 0, err
	}
	users := make([]ListedUser, len(rows))
	for i, row := range rows {
		users[i] = ListedUser{User: row.User, Policies: row.Policies}
	}
	return users, total, nil
}

// PolicyNamesForUsers returns the policy names that reach each of these
// users, directly or through a team, for the admin list.
func (s *Service) PolicyNamesForUsers(ctx context.Context, userIDs []int64) (map[int64][]string, error) {
	rows, err := s.queries.ListPolicyNamesForUsers(ctx, userIDs)
	if err != nil {
		return nil, err
	}
	names := make(map[int64][]string, len(userIDs))
	for _, row := range rows {
		names[row.UserID] = append(names[row.UserID], row.PolicyName)
	}
	return names, nil
}

// CountUsersWithoutAccess counts people who logged in, aren't disabled, and
// have no policy: they are waiting for access, or shouldn't be here at all.
func (s *Service) CountUsersWithoutAccess(ctx context.Context) (int64, error) {
	return s.queries.CountUsersWithoutAccess(ctx)
}

// likeEscaper makes text match literally inside a LIKE pattern.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// UserDetail is a user with their teams and directly assigned policies.
type UserDetail struct {
	User     db.User
	Teams    []db.Team
	Policies []db.Policy
}

// UserDetail returns a user with teams and policies.
func (s *Service) UserDetail(ctx context.Context, id int64) (UserDetail, error) {
	user, err := s.User(ctx, id)
	if err != nil {
		return UserDetail{}, err
	}
	teams, err := s.queries.ListUserTeams(ctx, id)
	if err != nil {
		return UserDetail{}, fmt.Errorf("list user teams: %w", err)
	}
	policies, err := s.queries.ListUserPolicies(ctx, id)
	if err != nil {
		return UserDetail{}, fmt.Errorf("list user policies: %w", err)
	}
	return UserDetail{User: user, Teams: teams, Policies: policies}, nil
}

// AddUser creates an account ahead of the user's first login, so an admin can
// put someone in teams before they arrive. The account is matched by email at
// that first login.
func (s *Service) AddUser(ctx context.Context, rawEmail string) (db.User, error) {
	email, err := ParseEmail(rawEmail, s.allowedDomains)
	if err != nil {
		return db.User{}, err
	}
	addedBy := audit.ActorFrom(ctx).Email
	user, created, err := s.createUser(ctx, email, &addedBy)
	if err != nil {
		return db.User{}, err
	}
	if !created {
		return db.User{}, problem.Conflict("%s already has an account.", email)
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionUserAdded, Outcome: audit.Allowed,
		Details: map[string]any{"user": email}})
	return user, nil
}

// SetAdmin adds a user to or removes them from the admin group. The last
// active admin can't be removed.
func (s *Service) SetAdmin(ctx context.Context, userID int64, isAdmin bool) error {
	user, err := s.User(ctx, userID)
	if err != nil {
		return err
	}
	err = database.InTx(ctx, s.pool, func(q *db.Queries) error {
		if err := q.LockAdminChanges(ctx); err != nil {
			return err
		}
		if !isAdmin {
			if err := ensureAnotherAdmin(ctx, q, user); err != nil {
				return err
			}
			// Leaving the admin group ends admin mode right away.
			if err := q.DeleteUserSessions(ctx, userID); err != nil {
				return err
			}
		}
		return q.SetUserAdmin(ctx, db.SetUserAdminParams{ID: userID, IsAdmin: isAdmin})
	})
	if err != nil {
		return err
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionUserAdminChanged, Outcome: audit.Allowed,
		Details: map[string]any{"user": user.Email, "admin": isAdmin}})
	return nil
}

// SetDisabled disables or enables a user. Disabling ends their sessions. The
// last active admin can't be disabled.
func (s *Service) SetDisabled(ctx context.Context, userID int64, disabled bool) error {
	user, err := s.User(ctx, userID)
	if err != nil {
		return err
	}
	err = database.InTx(ctx, s.pool, func(q *db.Queries) error {
		if err := q.LockAdminChanges(ctx); err != nil {
			return err
		}
		if disabled {
			if err := ensureAnotherAdmin(ctx, q, user); err != nil {
				return err
			}
			if err := q.DeleteUserSessions(ctx, userID); err != nil {
				return err
			}
		}
		return q.SetUserDisabled(ctx, db.SetUserDisabledParams{ID: userID, Disabled: disabled})
	})
	if err != nil {
		return err
	}
	action := audit.ActionUserEnabled
	if disabled {
		action = audit.ActionUserDisabled
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: action, Outcome: audit.Allowed,
		Details: map[string]any{"user": user.Email}})
	return nil
}

// ensureAnotherAdmin refuses to take away the last active admin.
func ensureAnotherAdmin(ctx context.Context, q *db.Queries, user db.User) error {
	if !user.IsAdmin || user.DisabledAt != nil || user.LockedAt != nil {
		return nil
	}
	count, err := q.CountActiveAdmins(ctx)
	if err != nil {
		return err
	}
	if count <= 1 {
		return problem.Conflict("%s is the last active admin; add another admin first.", user.Email)
	}
	return nil
}

// Unlock lifts a lock caused by too many failed second-factor attempts.
func (s *Service) Unlock(ctx context.Context, userID int64) error {
	user, err := s.User(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.queries.UnlockUser(ctx, userID); err != nil {
		return fmt.Errorf("unlock user: %w", err)
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionUserUnlocked, Outcome: audit.Allowed,
		Details: map[string]any{"user": user.Email}})
	return nil
}

// SetUserTeams makes the user a member of exactly these teams. Teams linked
// to an identity-provider group are not part of this: their members come
// from the group, so they are neither added nor removed here.
func (s *Service) SetUserTeams(ctx context.Context, userID int64, teamIDs []int64) error {
	detail, err := s.UserDetail(ctx, userID)
	if err != nil {
		return err
	}
	for _, teamID := range teamIDs {
		team, err := s.queries.GetTeam(ctx, teamID)
		if err != nil {
			return err
		}
		if err := linkedTeamError(team); err != nil {
			return err
		}
	}
	before := teamNames(detail.Teams)

	err = database.InTx(ctx, s.pool, func(q *db.Queries) error {
		for _, team := range detail.Teams {
			if team.IDPGroup != nil || slices.Contains(teamIDs, team.ID) {
				continue
			}
			if err := q.RemoveTeamMember(ctx, db.RemoveTeamMemberParams{TeamID: team.ID, UserID: userID}); err != nil {
				return err
			}
		}
		for _, teamID := range teamIDs {
			err := q.AddTeamMember(ctx, db.AddTeamMemberParams{TeamID: teamID, UserID: userID})
			if database.IsForeignKeyViolation(err) {
				return problem.Invalid("One of the selected teams doesn't exist.")
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	after, err := s.queries.ListUserTeams(ctx, userID)
	if err != nil {
		return err
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionUserTeams, Outcome: audit.Allowed,
		Details: map[string]any{"user": detail.User.Email, "before": before, "after": teamNames(after)}})
	return nil
}

// SetUserPolicies assigns exactly these policies to the user directly.
func (s *Service) SetUserPolicies(ctx context.Context, userID int64, policyIDs []int64) error {
	detail, err := s.UserDetail(ctx, userID)
	if err != nil {
		return err
	}
	before := policyNames(detail.Policies)

	err = database.InTx(ctx, s.pool, func(q *db.Queries) error {
		for _, policy := range detail.Policies {
			if !slices.Contains(policyIDs, policy.ID) {
				if err := q.UnassignPolicyFromUser(ctx, db.UnassignPolicyFromUserParams{UserID: userID, PolicyID: policy.ID}); err != nil {
					return err
				}
			}
		}
		for _, policyID := range policyIDs {
			err := q.AssignPolicyToUser(ctx, db.AssignPolicyToUserParams{UserID: userID, PolicyID: policyID})
			if database.IsForeignKeyViolation(err) {
				return problem.Invalid("One of the selected policies doesn't exist.")
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	after, err := s.queries.ListUserPolicies(ctx, userID)
	if err != nil {
		return err
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionUserPolicies, Outcome: audit.Allowed,
		Details: map[string]any{"user": detail.User.Email, "before": before, "after": policyNames(after)}})
	return nil
}

func teamNames(teams []db.Team) []string {
	names := make([]string, len(teams))
	for i, team := range teams {
		names[i] = team.Name
	}
	return names
}

func policyNames(policies []db.Policy) []string {
	names := make([]string, len(policies))
	for i, policy := range policies {
		names[i] = policy.Name
	}
	return names
}
