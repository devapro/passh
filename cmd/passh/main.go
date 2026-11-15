// Command passh is a password manager whose vault is one age-encrypted
// file (spec.md). The commands live in internal/cli.
package main

import (
	"fmt"
	"os"

	"github.com/devapro/passh/internal/cli"
	"github.com/devapro/passh/internal/harden"
)

// version is set at build time, e.g.
// go build -ldflags "-X main.version=v1.0.0" ./cmd/passh (.goreleaser.yaml).
var version = "dev"

func main() {
	// S7: before anything else, so no secret can end up in a core file.
	if err := harden.DisableCoreDumps(); err != nil {
		fmt.Fprintf(os.Stderr, "passh: warning: %v\n", err)
	}
	cli.Version = version
	os.Exit(cli.Main(os.Args[1:]))
}
