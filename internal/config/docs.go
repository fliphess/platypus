package config

import (
	"fmt"
	"strings"
)

//go:generate go run ./gendocs -out ../docs/pages/90-configuration.txt

// Documentation renders the configuration page shown in the in-app docs.
// The file in docs/ is generated from it; a test fails when they differ.
// The variables are one contiguous run of "NAME | default | description"
// lines, which the docs renderer shows as a three-column table: the setting,
// its default (or "required"/"optional"), and what it does. No blank lines
// between entries, or each entry would stand alone as prose.
func Documentation() string {
	var b strings.Builder
	b.WriteString("Configuration\n\n")
	b.WriteString("Platypus is configured with environment variables only; there is no config file.\n")
	b.WriteString("This page is generated from the code, so it always matches what platypus reads.\n")

	b.WriteString("\n")
	for _, v := range Vars {
		defaultValue := "—"
		switch {
		case v.Required:
			defaultValue = "required"
		case v.Default != "":
			defaultValue = v.Default
		}
		fmt.Fprintf(&b, "%s | %s | ", v.Name, defaultValue)
		b.WriteString(strings.TrimSpace(v.Description))
		if v.Secret {
			b.WriteString(" Secret: deliver it through a Kubernetes secret, never in plain values.")
		}
		b.WriteString("\n")
	}
	return b.String()
}
