package access

import (
	"context"
	"fmt"

	"platypus/internal/authz"
	"platypus/internal/db"
	"platypus/internal/item"
)

// Rules returns every rule that applies to the user, through policies
// assigned directly and through teams.
func (s *Service) Rules(ctx context.Context, userID int64) ([]authz.Rule, error) {
	rows, err := s.queries.ListRulesForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}
	rules := make([]authz.Rule, 0, len(rows))
	for _, row := range rows {
		rule, err := ruleFromRow(row)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// Subject returns the user as an authz.Subject. blocked is the state of the
// block switch.
func (s *Service) Subject(ctx context.Context, userID int64, blocked bool) (authz.Subject, error) {
	rules, err := s.Rules(ctx, userID)
	if err != nil {
		return authz.Subject{}, err
	}
	return authz.Subject{Rules: rules, Blocked: blocked}, nil
}

func ruleFromRow(row db.ListRulesForUserRow) (authz.Rule, error) {
	kind, err := item.ParseKind(row.Kind)
	if err != nil {
		return authz.Rule{}, fmt.Errorf("stored rule of policy %q: %w", row.PolicyName, err)
	}
	pattern, err := authz.ParsePattern(row.Pattern)
	if err != nil {
		return authz.Rule{}, fmt.Errorf("stored rule of policy %q: %w", row.PolicyName, err)
	}
	return authz.Rule{
		Kind:    kind,
		Pattern: pattern,
		Permissions: authz.Permissions{
			List:   row.CanList,
			Create: row.CanCreate,
			Edit:   row.CanEdit,
			Reveal: row.CanReveal,
		},
		Source: authz.Source{Policy: row.PolicyName, Team: row.TeamName},
	}, nil
}
