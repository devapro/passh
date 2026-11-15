package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestVersion: `passh --version` and `passh version` print the version,
// "dev" by default and the -X main.version value of a release build
// (.goreleaser.yaml).
func TestVersion(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, args := range [][]string{{"--version"}, {"version"}} {
		if r := e.ok(args...); r.stdout != "passh dev\n" || r.stderr != "" {
			t.Errorf("passh %v: %s", args, r)
		}
	}
	e.fail(2, "version", "extra")

	bin := filepath.Join(e.root, "passh-release")
	build := exec.Command(goTool(), "build", "-ldflags", "-X main.version=1.2.3-test", "-o", bin, "github.com/devapro/passh/cmd/passh")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	for _, args := range [][]string{{"--version"}, {"version"}} {
		cmd := exec.Command(bin, args...)
		cmd.Env = e.vars
		cmd.Dir = e.root
		cmd.Stderr = os.Stderr
		out, err := cmd.Output()
		if err != nil || string(out) != "passh 1.2.3-test\n" {
			t.Errorf("release build, passh %v: %q, %v", args, out, err)
		}
	}
}
