package harden

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const helperEnv = "PASSH_HARDEN_TEST_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		// Child: disable core dumps, then report the limits it sees.
		if err := DisableCoreDumps(); err != nil {
			os.Stdout.WriteString("error: " + err.Error())
			os.Exit(1)
		}
		var lim unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil {
			os.Exit(1)
		}
		ok, _ := CoreDumpsDisabled()
		// Raising the soft limit again must fail: the hard limit is 0.
		raise := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 1 << 20, Max: 1 << 20})
		if lim.Cur == 0 && lim.Max == 0 && ok && raise != nil {
			os.Stdout.WriteString("disabled")
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// The limit is changed in a child process so the test binary keeps its own.
func TestDisableCoreDumps(t *testing.T) {
	var before unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &before); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helper: %v, output %q", err, out)
	}
	if strings.TrimSpace(string(out)) != "disabled" {
		t.Fatalf("helper output %q, want %q", out, "disabled")
	}
	// Only the child changed: this process's limit is untouched.
	var after unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("parent limit changed from %+v to %+v", before, after)
	}
}

func TestCoreDumpsDisabled(t *testing.T) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil {
		t.Fatal(err)
	}
	got, err := CoreDumpsDisabled()
	if err != nil {
		t.Fatal(err)
	}
	if got != (lim.Cur == 0) {
		t.Errorf("CoreDumpsDisabled = %v with soft limit %d", got, lim.Cur)
	}
}
