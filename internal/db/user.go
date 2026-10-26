package db

// This file is not generated: it adds behaviour to generated types.

// Label is how a user is shown: their name when they gave one, else their email.
func (u User) Label() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Email
}
