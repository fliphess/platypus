package auth

import "testing"

// Two provider group names stay distinct even when one would have been
// rewritten into the other by tag cleaning. Authorization keys are exact.
func TestGroupNamesAreNotAliased(t *testing.T) {
	groups, err := cleanGroups([]string{"payments", "<b>payments</b>", " payments "})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{" payments ", "<b>payments</b>", "payments"}
	// cleanGroups trims surrounding whitespace but must not strip markup.
	if len(groups) != 2 {
		t.Fatalf("groups = %v, want two distinct names", groups)
	}
	seen := map[string]bool{}
	for _, group := range groups {
		seen[group] = true
	}
	if !seen["payments"] || !seen["<b>payments</b>"] {
		t.Errorf("groups = %v, want the exact names preserved (%v)", groups, want)
	}
}
