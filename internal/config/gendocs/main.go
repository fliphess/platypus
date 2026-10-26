// Command gendocs writes the configuration docs page. Run it with go generate.
package main

import (
	"flag"
	"log"
	"os"

	"platypus/internal/config"
)

func main() {
	out := flag.String("out", "", "file to write")
	flag.Parse()
	if *out == "" {
		log.Fatal("-out is required")
	}
	// A documentation file in the repository: readable by everyone on purpose.
	if err := os.WriteFile(*out, []byte(config.Documentation()), 0o644); err != nil { //nolint:gosec // see above
		log.Fatal(err)
	}
}
