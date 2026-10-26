package access

import (
	"context"
	"fmt"
	"slices"

	"platypus/internal/audit"
	"platypus/internal/database"
	"platypus/internal/db"
	"platypus/internal/problem"
	"platypus/internal/textclean"
)

// TeamInput is what an admin enters for a team.
type TeamInput struct {
	Name        string
	Description string
	// IDPGroup links the team to one identity-provider group; empty is no
	// link. A linked team takes its members from the group.
	IDPGroup string
}

func (in TeamInput) clean() (TeamInput, error) {
	name, err := textclean.Clean(in.Name, textclean.Options{MaxLength: 100})
	if err != nil {
		return TeamInput{}, problem.Invalid("Team name: %v.", err)
	}
	if name == "" {
		return TeamInput{}, problem.Invalid("A team needs a name.")
	}
	description, err := textclean.Clean(in.Description, textclean.Options{MaxLength: 500})
	if err != nil {
		return TeamInput{}, problem.Invalid("Team description: %v.", err)
	}
	group, err := textclean.Clean(in.IDPGroup, textclean.GroupOptions)
	if err != nil {
		return TeamInput{}, problem.Invalid("Identity-provider group: %v.", err)
	}
	return TeamInput{Name: name, Description: description, IDPGroup: group}, nil
}

// groupLink is the cleaned group link as stored: nil when there is none.
func (in TeamInput) groupLink() *string {
	if in.IDPGroup == "" {
		return nil
	}
	group := in.IDPGroup
	return &group
}

// Teams lists teams with their member counts, narrowed by the search term
// (name or description; empty lists all).
func (s *Service) Teams(ctx context.Context, search string) ([]db.ListTeamsRow, error) {
	cleaned, err := textclean.Clean(search, textclean.Options{MaxLength: 200})
	if err != nil {
		return nil, problem.Invalid("Search: %v.", err)
	}
	return s.queries.ListTeams(ctx, "%"+likeEscaper.Replace(cleaned)+"%")
}

// TeamDetail is a team with its members and policies.
type TeamDetail struct {
	Team     db.Team
	Members  []db.User
	Policies []db.Policy
}

// TeamDetail returns a team with members and policies.
func (s *Service) TeamDetail(ctx context.Context, id int64) (TeamDetail, error) {
	team, err := s.queries.GetTeam(ctx, id)
	if database.IsNoRows(err) {
		return TeamDetail{}, problem.NotFound("This team doesn't exist.")
	}
	if err != nil {
		return TeamDetail{}, err
	}
	members, err := s.queries.ListTeamMembers(ctx, id)
	if err != nil {
		return TeamDetail{}, fmt.Errorf("list team members: %w", err)
	}
	policies, err := s.queries.ListTeamPolicies(ctx, id)
	if err != nil {
		return TeamDetail{}, fmt.Errorf("list team policies: %w", err)
	}
	return TeamDetail{Team: team, Members: members, Policies: policies}, nil
}

// CreateTeam creates a team.
func (s *Service) CreateTeam(ctx context.Context, in TeamInput) (db.Team, error) {
	in, err := in.clean()
	if err != nil {
		return db.Team{}, err
	}
	team, err := s.queries.CreateTeam(ctx, db.CreateTeamParams{Name: in.Name, Description: in.Description, IDPGroup: in.groupLink()})
	switch {
	case database.IsUniqueViolationOn(err, "teams_name_key"):
		return db.Team{}, problem.Conflict("A team named %q exists already.", in.Name)
	case database.IsUniqueViolationOn(err, "teams_idp_group_key"):
		return db.Team{}, problem.Conflict("Another team is linked to group %q already.", in.IDPGroup)
	case err != nil:
		return db.Team{}, fmt.Errorf("create team: %w", err)
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionTeamCreated, Outcome: audit.Allowed,
		Details: map[string]any{"team": in.Name, "idp_group": in.IDPGroup}})
	return team, nil
}

// UpdateTeam renames a team, changes its description or its group link.
// Removing the link keeps the members.
func (s *Service) UpdateTeam(ctx context.Context, id int64, in TeamInput) error {
	detail, err := s.TeamDetail(ctx, id)
	if err != nil {
		return err
	}
	in, err = in.clean()
	if err != nil {
		return err
	}
	err = s.queries.UpdateTeam(ctx, db.UpdateTeamParams{ID: id, Name: in.Name, Description: in.Description, IDPGroup: in.groupLink()})
	switch {
	case database.IsUniqueViolationOn(err, "teams_name_key"):
		return problem.Conflict("A team named %q exists already.", in.Name)
	case database.IsUniqueViolationOn(err, "teams_idp_group_key"):
		return problem.Conflict("Another team is linked to group %q already.", in.IDPGroup)
	case err != nil:
		return fmt.Errorf("update team: %w", err)
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionTeamUpdated, Outcome: audit.Allowed,
		Details: map[string]any{
			"before": TeamInput{Name: detail.Team.Name, Description: detail.Team.Description, IDPGroup: derefGroup(detail.Team.IDPGroup)},
			"after":  in,
		}})
	return nil
}

func derefGroup(group *string) string {
	if group == nil {
		return ""
	}
	return *group
}

// DeleteTeam deletes a team. Its members lose the team's policies.
func (s *Service) DeleteTeam(ctx context.Context, id int64) error {
	detail, err := s.TeamDetail(ctx, id)
	if err != nil {
		return err
	}
	if err := s.queries.DeleteTeam(ctx, id); err != nil {
		return fmt.Errorf("delete team: %w", err)
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionTeamDeleted, Outcome: audit.Allowed,
		Details: map[string]any{
			"team":     detail.Team.Name,
			"members":  userEmails(detail.Members),
			"policies": policyNames(detail.Policies),
		}})
	return nil
}

// SetTeamPolicies assigns exactly these policies to the team.
func (s *Service) SetTeamPolicies(ctx context.Context, teamID int64, policyIDs []int64) error {
	detail, err := s.TeamDetail(ctx, teamID)
	if err != nil {
		return err
	}
	err = database.InTx(ctx, s.pool, func(q *db.Queries) error {
		for _, policy := range detail.Policies {
			if !slices.Contains(policyIDs, policy.ID) {
				if err := q.UnassignPolicyFromTeam(ctx, db.UnassignPolicyFromTeamParams{TeamID: teamID, PolicyID: policy.ID}); err != nil {
					return err
				}
			}
		}
		for _, policyID := range policyIDs {
			err := q.AssignPolicyToTeam(ctx, db.AssignPolicyToTeamParams{TeamID: teamID, PolicyID: policyID})
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

	after, err := s.queries.ListTeamPolicies(ctx, teamID)
	if err != nil {
		return err
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionTeamPolicies, Outcome: audit.Allowed,
		Details: map[string]any{"team": detail.Team.Name, "before": policyNames(detail.Policies), "after": policyNames(after)}})
	return nil
}

func userEmails(users []db.User) []string {
	emails := make([]string, len(users))
	for i, user := range users {
		emails[i] = user.Email
	}
	return emails
}

// linkedTeamError explains that a linked team's members come from its group:
// membership is read-only, exceptions get their own team or a direct policy.
func linkedTeamError(team db.Team) error {
	if team.IDPGroup == nil {
		return nil
	}
	return problem.Invalid("The members of team %q come from the identity-provider group %s. Add or remove them in the group.", team.Name, *team.IDPGroup)
}

// AddTeamMember adds an existing user to a team.
func (s *Service) AddTeamMember(ctx context.Context, teamID, userID int64) error {
	detail, err := s.TeamDetail(ctx, teamID)
	if err != nil {
		return err
	}
	if err := linkedTeamError(detail.Team); err != nil {
		return err
	}
	user, err := s.User(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.queries.AddTeamMember(ctx, db.AddTeamMemberParams{TeamID: teamID, UserID: userID}); err != nil {
		return fmt.Errorf("add team member: %w", err)
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionUserTeams, Outcome: audit.Allowed,
		Details: map[string]any{"user": user.Email, "added_to": detail.Team.Name}})
	return nil
}

// AddTeamMemberByEmail is gone: members are picked from people who logged
// in, never entered as free-text addresses (typosquatting).

// RemoveTeamMember removes a user from a team.
func (s *Service) RemoveTeamMember(ctx context.Context, teamID, userID int64) error {
	detail, err := s.TeamDetail(ctx, teamID)
	if err != nil {
		return err
	}
	if err := linkedTeamError(detail.Team); err != nil {
		return err
	}
	user, err := s.User(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.queries.RemoveTeamMember(ctx, db.RemoveTeamMemberParams{TeamID: teamID, UserID: userID}); err != nil {
		return fmt.Errorf("remove team member: %w", err)
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionUserTeams, Outcome: audit.Allowed,
		Details: map[string]any{"user": user.Email, "removed_from": detail.Team.Name}})
	return nil
}
