// Command passh is a password manager whose vault is one age-encrypted
// file (spec.md). The commands live in internal/cli.
package main

import (
	"os"

	"github.com/devapro/passh/internal/cli"
	"github.com/devapro/passh/internal/harden"
)

// version is set at build time, e.g.
// go build -ldflags "-X main.version=v1.0.0" ./cmd/passh (.goreleaser.yaml).
var version = "dev"

func main() {
	// S7: before anything else, so no secret can end up in a core file.
	// cli.Main prints the failure as a warning, in the user's language.
	hardenErr := harden.DisableCoreDumps()
	cli.Version = version
	var warnings []error
	if hardenErr != nil {
		warnings = append(warnings, hardenErr)
	}
	os.Exit(cli.Main(os.Args[1:], warnings...))
}
