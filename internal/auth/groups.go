package auth

import (
	"fmt"
	"slices"
	"strings"

	"platypus/internal/textclean"
)

// maxGroups caps how many groups one login may report. A provider that sends
// more is misconfigured; that is an error rather than a silent truncation,
// which could grant or drop teams unnoticed.
const maxGroups = 50

// groupsFromHeader splits a comma-separated groups header, as login proxies
// send it. A blank header means the user is in no groups: an empty list, not
// nil, so the sync still runs and removes them from linked teams.
func groupsFromHeader(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return []string{}, nil
	}
	return cleanGroups(strings.Split(value, ","))
}

// groupsFromClaim reads the groups claim of a verified token: a list of
// names, or a single name. A missing claim means the user is in no groups
// (an empty list); a claim of any other shape is refused, so a misread claim
// can't silently grant or drop groups.
func groupsFromClaim(claims map[string]any, name string) ([]string, error) {
	raw, ok := claims[name]
	if !ok || raw == nil {
		return []string{}, nil
	}
	switch typed := raw.(type) {
	case []any:
		groups := make([]string, 0, len(typed))
		for _, entry := range typed {
			group, ok := entry.(string)
			if !ok {
				return nil, fmt.Errorf("the %q claim holds a group name that is not a string", name)
			}
			groups = append(groups, group)
		}
		return cleanGroups(groups)
	case string:
		return cleanGroups([]string{typed})
	default:
		return nil, fmt.Errorf("the %q claim is not a group or a list of groups", name)
	}
}

// cleanGroups normalises group names: each through the same cleaning as a
// team's group link, empty names dropped, duplicates merged, sorted so the
// same set always stores the same way. A list that is too long, or a name
// that doesn't survive cleaning, is an error (fail closed).
func cleanGroups(raw []string) ([]string, error) {
	groups := make([]string, 0, len(raw))
	for _, name := range raw {
		group, err := textclean.Identifier(name, 200)
		if err != nil {
			return nil, fmt.Errorf("group name: %w", err)
		}
		if group == "" || slices.Contains(groups, group) {
			continue
		}
		groups = append(groups, group)
	}
	if len(groups) > maxGroups {
		return nil, fmt.Errorf("the identity provider reports %d groups, at most %d are read", len(groups), maxGroups)
	}
	slices.Sort(groups)
	return groups, nil
}
