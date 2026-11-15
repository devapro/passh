package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// shortSock is a socket name that fits in any test's state folder.
const shortSock = "s.sock"

// isolateAgent is isolate, plus a temporary folder in place of /tmp, so the
// fallback never touches the real /tmp.
func isolateAgent(t *testing.T) {
	t.Helper()
	isolate(t)
	old := lastTmp
	lastTmp = t.TempDir()
	t.Cleanup(func() { lastTmp = old })
}

// longSock returns a socket name that fits exactly in passh-<uid> in
// $TMPDIR but not in the (longer) state folder.
func longSock(t *testing.T) string {
	t.Helper()
	tmp := os.Getenv("TMPDIR")
	if tmp == "" {
		tmp = lastTmp
	}
	tmpDir := filepath.Join(tmp, "passh-"+strconv.Itoa(os.Getuid()))
	n := MaxSocketPathLen - len(tmpDir) - 1
	state, _ := StateDir()
	if n < 8 || len(filepath.Join(state, "agent")) <= len(tmpDir) {
		t.Fatalf("test folders too long: %s", tmpDir)
	}
	return strings.Repeat("x", n-5) + ".sock"
}

func TestAgentDir(t *testing.T) {
	isolate(t)
	uid := strconv.Itoa(os.Getuid())

	t.Setenv("XDG_STATE_HOME", "/xdg/state")
	if d, err := AgentDir("agent-0123456789abcdef.sock"); err != nil || d != "/xdg/state/passh/agent" {
		t.Errorf("AgentDir = %q, %v", d, err)
	}

	// A socket path of exactly MaxSocketPathLen bytes still fits; one more
	// byte moves the socket to the fallback folder.
	const sock = "agent-0123456789abcdef.sock"
	base := "/xdg/state/passh/agent/" + sock
	state := "/xdg/" + strings.Repeat("s", MaxSocketPathLen-len(base)-1) + "/state"
	t.Setenv("XDG_STATE_HOME", state)
	if d, _ := AgentDir(sock); d != state+"/passh/agent" {
		t.Errorf("AgentDir(%d-byte path) = %q, want the state folder", MaxSocketPathLen, d)
	}
	t.Setenv("XDG_STATE_HOME", state+"s")
	for _, tc := range []struct{ tmp, want string }{
		{"/var/folders/xy/T/", "/var/folders/xy/T/passh-"},
		{"/t", "/t/passh-"},
		{"", "/tmp/passh-"},
		{"relative", "/tmp/passh-"},
		{"/" + strings.Repeat("long", 20), "/tmp/passh-"}, // $TMPDIR too long as well
	} {
		t.Setenv("TMPDIR", tc.tmp)
		want := tc.want + uid
		if d, err := AgentDir(sock); err != nil || d != want {
			t.Errorf("AgentDir(TMPDIR=%q) = %q, %v; want %q", tc.tmp, d, err, want)
		}
	}

	if _, err := AgentDir(strings.Repeat("z", MaxSocketPathLen)); err == nil {
		t.Error("a socket name too long for /tmp was accepted")
	}
	for _, bad := range []string{"", ".", "..", "a/b", "a\x00b"} {
		if _, err := AgentDir(bad); err == nil {
			t.Errorf("socket name %q accepted", bad)
		}
	}
	t.Setenv("HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	if _, err := AgentDir(shortSock); err == nil {
		t.Error("AgentDir without HOME succeeded")
	}
}

func TestEnsureAgentDirCreates(t *testing.T) {
	isolateAgent(t)
	// A umask that would leave the folders unusable is overridden.
	old := unix.Umask(0o277)
	defer unix.Umask(old)

	dir, err := EnsureAgentDir(shortSock)
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(os.Getenv("XDG_STATE_HOME"), "passh")
	if want := filepath.Join(state, "agent"); dir != want {
		t.Errorf("dir = %q, want %q", dir, want)
	}
	for _, d := range []string{state, dir} {
		assertPrivateDir(t, d)
	}
	// Idempotent.
	if again, err := EnsureAgentDir(shortSock); err != nil || again != dir {
		t.Errorf("second call = %q, %v", again, err)
	}
	if err := CheckAgentDir(dir); err != nil {
		t.Errorf("CheckAgentDir: %v", err)
	}
}

func TestEnsureStateDir(t *testing.T) {
	isolateAgent(t)
	// Missing parents are created as well.
	t.Setenv("XDG_STATE_HOME", filepath.Join(t.TempDir(), "a", "b"))
	old := unix.Umask(0o077)
	defer unix.Umask(old)
	dir, err := EnsureStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(os.Getenv("XDG_STATE_HOME"), "passh"); dir != want {
		t.Errorf("dir = %q, want %q", dir, want)
	}
	assertPrivateDir(t, dir)

	// An existing state folder is left alone, whatever its mode: only the
	// agent folder inside it must be private.
	must(t, os.Chmod(dir, 0o755))
	if _, err := EnsureStateDir(); err != nil {
		t.Errorf("existing state folder: %v", err)
	}
	if _, err := EnsureAgentDir(shortSock); err != nil {
		t.Errorf("agent folder in a 0755 state folder: %v", err)
	}

	t.Setenv("HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	if _, err := EnsureStateDir(); err == nil {
		t.Error("EnsureStateDir without HOME succeeded")
	}
}

func TestEnsureAgentDirTmpFallback(t *testing.T) {
	isolateAgent(t)
	longSock := longSock(t)
	dir, err := EnsureAgentDir(longSock)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(os.Getenv("TMPDIR"), "passh-"+strconv.Itoa(os.Getuid()))
	if dir != want {
		t.Errorf("dir = %q, want %q", dir, want)
	}
	assertPrivateDir(t, dir)
	if len(filepath.Join(dir, longSock)) > MaxSocketPathLen {
		t.Errorf("socket path %q is too long", filepath.Join(dir, longSock))
	}
	// The state folder isn't needed for the fallback and isn't created.
	if _, err := os.Lstat(filepath.Join(os.Getenv("XDG_STATE_HOME"), "passh")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("state folder created for the fallback: %v", err)
	}
}

func TestEnsureAgentDirRefuses(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, dir string)
		want    string
	}{
		{"symlink to own folder", func(t *testing.T, dir string) {
			target := filepath.Join(t.TempDir(), "elsewhere")
			mustMkdir(t, target, 0o700)
			must(t, os.Symlink(target, dir))
		}, "not a directory"},
		{"dangling symlink", func(t *testing.T, dir string) {
			must(t, os.Symlink(filepath.Join(t.TempDir(), "nothing"), dir))
		}, "not a directory"},
		{"regular file", func(t *testing.T, dir string) {
			must(t, os.WriteFile(dir, nil, 0o600))
		}, "not a directory"},
		{"group-readable folder", func(t *testing.T, dir string) {
			mustMkdir(t, dir, 0o750)
		}, "mode 0750"},
		{"world-writable folder", func(t *testing.T, dir string) {
			mustMkdir(t, dir, 0o777)
		}, "mode 0777"},
		{"setgid folder", func(t *testing.T, dir string) {
			mustMkdir(t, dir, 0o700|os.ModeSetgid)
		}, "mode 2700"},
	}
	for _, fallback := range []bool{false, true} {
		for _, tc := range tests {
			t.Run(tc.name+"/"+strconv.FormatBool(fallback), func(t *testing.T) {
				isolateAgent(t)
				sock := shortSock
				if fallback {
					sock = longSock(t)
				}
				dir, err := AgentDir(sock)
				if err != nil {
					t.Fatal(err)
				}
				must(t, os.MkdirAll(filepath.Dir(dir), 0o700))
				tc.prepare(t, dir)
				_, err = EnsureAgentDir(sock)
				if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "refusing") {
					t.Errorf("err = %v, want a refusal mentioning %q", err, tc.want)
				}
				if err := CheckAgentDir(dir); err == nil {
					t.Error("CheckAgentDir accepted it")
				}
				// Refused, not fixed.
				if fi, err := os.Lstat(dir); err == nil && fi.IsDir() && fi.Mode().Perm() == 0o700 && fi.Mode()&os.ModeSetgid == 0 {
					t.Errorf("folder was changed to %v", fi.Mode())
				}
			})
		}
	}
}

// TestEnsureAgentDirOtherOwner simulates /tmp/passh-<uid> (or the state
// agent folder) pre-created by another user (a real one needs root to set
// up).
func TestEnsureAgentDirOtherOwner(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		isolateAgent(t)
		sock := shortSock
		if fallback {
			sock = longSock(t)
		}
		dir, _ := AgentDir(sock)
		must(t, os.MkdirAll(filepath.Dir(dir), 0o700))
		mustMkdir(t, dir, 0o700)
		getuid = func() int { return os.Getuid() + 1 }
		_, err := EnsureAgentDir(sock)
		getuid = os.Getuid
		if err == nil || !strings.Contains(err.Error(), "belongs to uid") {
			t.Errorf("%s: err = %v, want an ownership refusal", dir, err)
		}
	}
}

func TestEnsureAgentDirMissingTmp(t *testing.T) {
	isolateAgent(t)
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "gone"))
	sock := longSock(t)
	if dir, err := EnsureAgentDir(sock); err == nil {
		t.Errorf("succeeded with a missing $TMPDIR: %s", dir)
	}
}

// TestEnsureAgentDirLastTmp: with $TMPDIR unset, the fallback is in /tmp
// (here a stand-in for it).
func TestEnsureAgentDirLastTmp(t *testing.T) {
	isolateAgent(t)
	t.Setenv("TMPDIR", "")
	dir, err := EnsureAgentDir(longSock(t))
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(lastTmp, "passh-"+strconv.Itoa(os.Getuid())); dir != want {
		t.Errorf("dir = %q, want %q", dir, want)
	}
	assertPrivateDir(t, dir)
}

func TestCheckAgentDirMissing(t *testing.T) {
	err := CheckAgentDir(filepath.Join(t.TempDir(), "missing"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want fs.ErrNotExist", err)
	}
}

func assertPrivateDir(t *testing.T, dir string) {
	t.Helper()
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 || fi.Mode()&(os.ModeSetgid|os.ModeSetuid|os.ModeSticky) != 0 {
		t.Errorf("%s: mode = %v, want drwx------", dir, fi.Mode())
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	must(t, os.Mkdir(dir, 0o700))
	must(t, os.Chmod(dir, mode))
}
