package items

import (
	"bytes"
	"encoding/json"
	"slices"

	"platypus/internal/item"
	"platypus/internal/problem"
	"platypus/internal/sensitive"
)

// validateValue checks a new value before it goes to AWS, so users get a
// clear message instead of an AWS error.
func validateValue(kind item.Kind, ssmTier string, value sensitive.Value, isJSON bool) error {
	if value.IsEmpty() {
		return problem.Invalid("The value can't be empty.")
	}
	if limit := item.MaxValueBytes(kind, ssmTier); value.Len() > limit {
		hint := ""
		if kind == item.KindSSM && ssmTier != item.SSMTierAdvanced {
			hint = " Choose the Advanced tier for values up to 8 KB."
		}
		return problem.Invalid("The value is %d bytes; AWS accepts at most %d.%s", value.Len(), limit, hint)
	}
	if isJSON && !json.Valid([]byte(value.Reveal())) {
		return problem.Invalid("The value is not valid JSON; fix it or switch the editor to plain text.")
	}
	return nil
}

// KeyChanges lists which keys of a JSON object a change touches. It never
// holds values.
type KeyChanges struct {
	Added     []string
	Removed   []string
	Changed   []string
	Unchanged int
}

// IsEmpty reports whether no key changes.
func (k KeyChanges) IsEmpty() bool {
	return len(k.Added) == 0 && len(k.Removed) == 0 && len(k.Changed) == 0
}

// compareJSONKeys compares two JSON objects by key. It returns false when
// either value isn't a JSON object.
func compareJSONKeys(before, after sensitive.Value) (KeyChanges, bool) {
	old, ok := jsonObject(before)
	if !ok {
		return KeyChanges{}, false
	}
	updated, ok := jsonObject(after)
	if !ok {
		return KeyChanges{}, false
	}

	var changes KeyChanges
	for key, value := range updated {
		previous, existed := old[key]
		switch {
		case !existed:
			changes.Added = append(changes.Added, key)
		case !sameJSON(previous, value):
			changes.Changed = append(changes.Changed, key)
		default:
			changes.Unchanged++
		}
	}
	for key := range old {
		if _, kept := updated[key]; !kept {
			changes.Removed = append(changes.Removed, key)
		}
	}
	slices.Sort(changes.Added)
	slices.Sort(changes.Removed)
	slices.Sort(changes.Changed)
	return changes, true
}

func jsonObject(value sensitive.Value) (map[string]json.RawMessage, bool) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(value.Reveal()), &object); err != nil || object == nil {
		return nil, false
	}
	return object, true
}

func sameJSON(a, b json.RawMessage) bool {
	var compactA, compactB bytes.Buffer
	if json.Compact(&compactA, a) != nil || json.Compact(&compactB, b) != nil {
		return bytes.Equal(a, b)
	}
	return bytes.Equal(compactA.Bytes(), compactB.Bytes())
}
