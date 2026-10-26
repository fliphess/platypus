package access

import (
	"context"
	"fmt"

	"platypus/internal/audit"
	"platypus/internal/authz"
	"platypus/internal/database"
	"platypus/internal/db"
	"platypus/internal/item"
	"platypus/internal/problem"
	"platypus/internal/textclean"
)

// PolicyInput is what an admin enters for a policy.
type PolicyInput struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Rules       []RuleInput `json:"rules"`
}

// RuleInput is one rule of a policy.
type RuleInput struct {
	Kind        item.Kind         `json:"kind"`
	Pattern     string            `json:"pattern"`
	Permissions authz.Permissions `json:"permissions"`
}

const maxRulesPerPolicy = 100

func (in PolicyInput) clean() (PolicyInput, error) {
	name, err := textclean.Clean(in.Name, textclean.Options{MaxLength: 100})
	if err != nil {
		return PolicyInput{}, problem.Invalid("Policy name: %v.", err)
	}
	if name == "" {
		return PolicyInput{}, problem.Invalid("A policy needs a name.")
	}
	description, err := textclean.Clean(in.Description, textclean.Options{MaxLength: 500})
	if err != nil {
		return PolicyInput{}, problem.Invalid("Policy description: %v.", err)
	}
	if len(in.Rules) > maxRulesPerPolicy {
		return PolicyInput{}, problem.Invalid("A policy can have at most %d rules.", maxRulesPerPolicy)
	}

	cleaned := PolicyInput{Name: name, Description: description}
	for i, rule := range in.Rules {
		if _, err := item.ParseKind(string(rule.Kind)); err != nil {
			return PolicyInput{}, problem.Invalid("Rule %d: choose SSM parameters or secrets.", i+1)
		}
		if _, err := authz.ParsePattern(rule.Pattern); err != nil {
			return PolicyInput{}, problem.Invalid("Rule %d: %v.", i+1, err)
		}
		if rule.Permissions.IsEmpty() {
			return PolicyInput{}, problem.Invalid("Rule %d grants nothing; tick at least one permission.", i+1)
		}
		cleaned.Rules = append(cleaned.Rules, rule)
	}
	return cleaned, nil
}

// Policies lists all policies with rule and assignment counts.
// PoliciesPage returns one page of policies and the total matching the search.
func (s *Service) PoliciesPage(ctx context.Context, search string, page, perPage int) ([]db.ListPoliciesPageRow, int64, error) {
	cleaned, err := textclean.Clean(search, textclean.Options{MaxLength: 200})
	if err != nil {
		return nil, 0, problem.Invalid("Search: %v.", err)
	}
	if page < 1 {
		page = 1
	}
	// Keep the offset arithmetic in range: the pager never asks for a page
	// this far out, and a crafted ?page= must not overflow.
	page = min(page, 1_000_000)
	if perPage <= 0 {
		perPage = UsersPerPage
	}
	pattern := "%" + likeEscaper.Replace(cleaned) + "%"
	total, err := s.queries.CountPolicies(ctx, pattern)
	if err != nil {
		return nil, 0, err
	}
	rows, err := s.queries.ListPoliciesPage(ctx, db.ListPoliciesPageParams{
		Search: pattern, MaxRows: int32(perPage), RowOffset: int32((page - 1) * perPage), //nolint:gosec // page and perPage are bounded above
	})
	if err != nil {
		return nil, 0, err
	}
	return rows, total, nil
}

func (s *Service) Policies(ctx context.Context, search string) ([]db.ListPoliciesRow, error) {
	cleaned, err := textclean.Clean(search, textclean.Options{MaxLength: 200})
	if err != nil {
		return nil, problem.Invalid("Search: %v.", err)
	}
	return s.queries.ListPolicies(ctx, "%"+likeEscaper.Replace(cleaned)+"%")
}

// PolicyDetail is a policy with its rules and who it is assigned to.
type PolicyDetail struct {
	Policy db.Policy
	Rules  []RuleInput
	Users  []db.User
	Teams  []db.Team
}

// Input returns the policy in the shape of the edit form.
func (d PolicyDetail) Input() PolicyInput {
	return PolicyInput{Name: d.Policy.Name, Description: d.Policy.Description, Rules: d.Rules}
}

// PolicyDetail returns a policy with rules and assignments.
func (s *Service) PolicyDetail(ctx context.Context, id int64) (PolicyDetail, error) {
	policy, err := s.queries.GetPolicy(ctx, id)
	if database.IsNoRows(err) {
		return PolicyDetail{}, problem.NotFound("This policy doesn't exist.")
	}
	if err != nil {
		return PolicyDetail{}, err
	}
	rows, err := s.queries.ListPolicyRules(ctx, id)
	if err != nil {
		return PolicyDetail{}, fmt.Errorf("list policy rules: %w", err)
	}
	users, err := s.queries.ListPolicyUsers(ctx, id)
	if err != nil {
		return PolicyDetail{}, fmt.Errorf("list policy users: %w", err)
	}
	teams, err := s.queries.ListPolicyTeams(ctx, id)
	if err != nil {
		return PolicyDetail{}, fmt.Errorf("list policy teams: %w", err)
	}

	rules := make([]RuleInput, len(rows))
	for i, row := range rows {
		rules[i] = RuleInput{
			Kind:    item.Kind(row.Kind),
			Pattern: row.Pattern,
			Permissions: authz.Permissions{
				List: row.CanList, Create: row.CanCreate, Edit: row.CanEdit, Reveal: row.CanReveal,
			},
		}
	}
	return PolicyDetail{Policy: policy, Rules: rules, Users: users, Teams: teams}, nil
}

// CreatePolicy creates a policy with its rules.
func (s *Service) CreatePolicy(ctx context.Context, in PolicyInput) (db.Policy, error) {
	in, err := in.clean()
	if err != nil {
		return db.Policy{}, err
	}
	var policy db.Policy
	err = database.InTx(ctx, s.pool, func(q *db.Queries) error {
		policy, err = createPolicy(ctx, q, in)
		return err
	})
	if err != nil {
		return db.Policy{}, err
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionPolicyCreated, Outcome: audit.Allowed,
		Details: map[string]any{"policy": in}})
	return policy, nil
}

func createPolicy(ctx context.Context, q *db.Queries, in PolicyInput) (db.Policy, error) {
	policy, err := q.CreatePolicy(ctx, db.CreatePolicyParams{Name: in.Name, Description: in.Description})
	if database.IsUniqueViolation(err) {
		return db.Policy{}, problem.Conflict("A policy named %q exists already.", in.Name)
	}
	if err != nil {
		return db.Policy{}, fmt.Errorf("create policy: %w", err)
	}
	return policy, insertRules(ctx, q, policy.ID, in.Rules)
}

// UpdatePolicy replaces a policy's name, description and rules.
func (s *Service) UpdatePolicy(ctx context.Context, id int64, in PolicyInput) error {
	before, err := s.PolicyDetail(ctx, id)
	if err != nil {
		return err
	}
	in, err = in.clean()
	if err != nil {
		return err
	}
	err = database.InTx(ctx, s.pool, func(q *db.Queries) error {
		err := q.UpdatePolicy(ctx, db.UpdatePolicyParams{ID: id, Name: in.Name, Description: in.Description})
		if database.IsUniqueViolation(err) {
			return problem.Conflict("A policy named %q exists already.", in.Name)
		}
		if err != nil {
			return err
		}
		if err := q.DeletePolicyRules(ctx, id); err != nil {
			return err
		}
		return insertRules(ctx, q, id, in.Rules)
	})
	if err != nil {
		return err
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionPolicyUpdated, Outcome: audit.Allowed,
		Details: map[string]any{"before": before.Input(), "after": in}})
	return nil
}

func insertRules(ctx context.Context, q *db.Queries, policyID int64, rules []RuleInput) error {
	for i, rule := range rules {
		err := q.InsertPolicyRule(ctx, db.InsertPolicyRuleParams{
			PolicyID:  policyID,
			Kind:      string(rule.Kind),
			Pattern:   rule.Pattern,
			CanList:   rule.Permissions.List,
			CanCreate: rule.Permissions.Create,
			CanEdit:   rule.Permissions.Edit,
			CanReveal: rule.Permissions.Reveal,
			Position:  int32(i),
		})
		if err != nil {
			return fmt.Errorf("insert policy rule: %w", err)
		}
	}
	return nil
}

// DeletePolicy deletes a policy; users and teams lose what it granted.
func (s *Service) DeletePolicy(ctx context.Context, id int64) error {
	detail, err := s.PolicyDetail(ctx, id)
	if err != nil {
		return err
	}
	if err := s.queries.DeletePolicy(ctx, id); err != nil {
		return fmt.Errorf("delete policy: %w", err)
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionPolicyDeleted, Outcome: audit.Allowed,
		Details: map[string]any{
			"policy": detail.Input(),
			"users":  userEmails(detail.Users),
			"teams":  teamNames(detail.Teams),
		}})
	return nil
}

// DefaultPolicies are created once, at the first bootstrap. They are not
// assigned to anyone.
var DefaultPolicies = []PolicyInput{
	{
		Name:        "Read-only all",
		Description: "See every parameter and secret in lists and search, without values.",
		Rules: []RuleInput{
			{Kind: item.KindSSM, Pattern: "*", Permissions: authz.Permissions{List: true}},
			{Kind: item.KindSecret, Pattern: "*", Permissions: authz.Permissions{List: true}},
		},
	},
	{
		Name:        "SSM editor all",
		Description: "Create and change every SSM parameter, without seeing values.",
		Rules: []RuleInput{
			{Kind: item.KindSSM, Pattern: "*", Permissions: authz.Permissions{List: true, Create: true, Edit: true}},
		},
	},
	{
		Name:        "Secrets editor all",
		Description: "Create and change every secret, without seeing values.",
		Rules: []RuleInput{
			{Kind: item.KindSecret, Pattern: "*", Permissions: authz.Permissions{List: true, Create: true, Edit: true}},
		},
	},
	{
		Name:        "Full access",
		Description: "Everything on every parameter and secret, including revealing values. Assign with care.",
		Rules: []RuleInput{
			{Kind: item.KindSSM, Pattern: "*", Permissions: authz.Permissions{List: true, Create: true, Edit: true, Reveal: true}},
			{Kind: item.KindSecret, Pattern: "*", Permissions: authz.Permissions{List: true, Create: true, Edit: true, Reveal: true}},
		},
	},
}

// SeedDefaultPolicies creates DefaultPolicies once in the lifetime of the
// database, inside the caller's transaction. It reports whether it did.
func SeedDefaultPolicies(ctx context.Context, q *db.Queries) (bool, error) {
	if _, err := q.ClaimPolicySeeding(ctx); database.IsNoRows(err) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("claim policy seeding: %w", err)
	}
	// Seeding happens during the first bootstrap, before any admin could
	// create policies, so names can't clash.
	for _, in := range DefaultPolicies {
		if _, err := createPolicy(ctx, q, in); err != nil {
			return false, err
		}
	}
	return true, nil
}
