package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/devapro/passh/internal/vaultfile"
)

// copyEnv is a vault to copy and an empty destination folder.
func copyEnv(t *testing.T) (e *env, orig []byte, destDir string) {
	t.Helper()
	e = newEnv(t)
	destDir = filepath.Join(t.TempDir(), "usb")
	if err := os.Mkdir(destDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return e, e.read(), destDir
}

// nothingAt checks that dst doesn't exist and that no temporary file is
// left in its folder.
func nothingAt(t *testing.T, dst string) {
	t.Helper()
	if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s exists after a failed copy: %v", dst, err)
	}
	if left := temps(t, filepath.Dir(dst)); len(left) > 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

// TestCopyChecked (§4.8, CLI-003): the copy is the vault, byte for byte,
// mode 0600, with its SHA-256; a non-canonical vault is copied in
// canonical form; nothing else is left in the folder.
func TestCopyChecked(t *testing.T) {
	e, orig, dir := copyEnv(t)
	dst := filepath.Join(dir, "copy.passh")
	res, err := CopyChecked(t.Context(), e.path, dst)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || !bytes.Equal(got, orig) {
		t.Fatalf("copy differs from the vault: %v", err)
	}
	if res.SHA256 != sha256.Sum256(orig) || res.Size != len(orig) || !res.Canonical {
		t.Errorf("result %+v", res)
	}
	if m := mode(t, dst); m != 0o600 {
		t.Errorf("mode %o, want 600", m)
	}
	if left := temps(t, dir); len(left) > 0 {
		t.Errorf("temporary files left: %v", left)
	}

	// A copy that went through email (CRLF): the copy is canonical again.
	crlf := filepath.Join(t.TempDir(), "email.passh")
	if err := os.WriteFile(crlf, bytes.ReplaceAll(orig, []byte("\n"), []byte("\r\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	dst2 := filepath.Join(dir, "canonical.passh")
	res, err = CopyChecked(t.Context(), crlf, dst2)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dst2); !bytes.Equal(got, orig) || res.Canonical || res.SHA256 != sha256.Sum256(orig) {
		t.Errorf("canonical copy: %+v", res)
	}

	// A file that fails the structure check isn't copied.
	bad := filepath.Join(t.TempDir(), "bad.passh")
	if err := os.WriteFile(bad, orig[:len(orig)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CopyChecked(t.Context(), bad, filepath.Join(dir, "bad.passh")); !errors.Is(err, vaultfile.ErrTruncated) ||
		!strings.Contains(err.Error(), "isn't copied") {
		t.Errorf("truncated source: %v", err)
	}
	nothingAt(t, filepath.Join(dir, "bad.passh"))
}

// TestCopyCheckedRefusesExisting: a file at the destination is never
// replaced, whether it is there from the start or appears just before the
// rename, and also on file systems without a no-replace rename or hard
// links (FAT, exFAT).
func TestCopyCheckedRefusesExisting(t *testing.T) {
	e, _, dir := copyEnv(t)
	dst := filepath.Join(dir, "copy.passh")
	if err := os.WriteFile(dst, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CopyChecked(t.Context(), e.path, dst); !errors.Is(err, ErrExists) {
		t.Errorf("existing destination: %v, want ErrExists", err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "mine" {
		t.Errorf("the existing file was replaced: %q", b)
	}

	for _, fat := range []bool{false, true} {
		name := map[bool]string{false: "native", true: "fat"}[fat]
		t.Run(name, func(t *testing.T) {
			if fat {
				noRenameNoReplace(t)
				setLink(t, func(string, string) error { return syscall.EPERM })
			}
			dst := filepath.Join(dir, "late-"+name+".passh")
			setHook(t, func(p, _ string) {
				if p == hookCopyVerified {
					if err := os.WriteFile(dst, []byte("appeared"), 0o600); err != nil {
						t.Error(err)
					}
				}
			})
			if _, err := CopyChecked(t.Context(), e.path, dst); !errors.Is(err, ErrExists) {
				t.Errorf("destination appearing before the rename: %v, want ErrExists", err)
			}
			if b, _ := os.ReadFile(dst); string(b) != "appeared" {
				t.Errorf("the file that appeared was replaced: %q", b)
			}
			if left := temps(t, dir); len(left) > 0 {
				t.Errorf("temporary files left: %v", left)
			}
		})
	}
}

// TestCopyCheckedOnFAT: without a no-replace rename and without hard
// links, the copy still lands under its name, complete.
func TestCopyCheckedOnFAT(t *testing.T) {
	e, orig, dir := copyEnv(t)
	noRenameNoReplace(t)
	setLink(t, func(string, string) error { return syscall.EPERM })
	dst := filepath.Join(dir, "copy.passh")
	if _, err := CopyChecked(t.Context(), e.path, dst); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dst); !bytes.Equal(got, orig) {
		t.Error("copy differs from the vault")
	}
	if left := temps(t, dir); len(left) > 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

// TestCopyCheckedFailures: a copy that reads back differently, a failed
// fsync and an ended context leave nothing under the final name and no
// temporary file.
func TestCopyCheckedFailures(t *testing.T) {
	e, _, dir := copyEnv(t)

	t.Run("read-back mismatch", func(t *testing.T) {
		dst := filepath.Join(dir, "mismatch.passh")
		setHook(t, func(p, file string) {
			if p == hookCopySynced {
				// The medium returns something else than was written.
				if err := os.WriteFile(file, []byte("flipped bits"), 0o600); err != nil {
					t.Error(err)
				}
			}
		})
		if _, err := CopyChecked(t.Context(), e.path, dst); !errors.Is(err, ErrCopyVerify) {
			t.Errorf("read-back mismatch: %v, want ErrCopyVerify", err)
		}
		nothingAt(t, dst)
	})
	t.Run("failed fsync", func(t *testing.T) {
		dst := filepath.Join(dir, "nosync.passh")
		setSyncFile(t, func(*os.File) error { return syscall.EIO })
		if _, err := CopyChecked(t.Context(), e.path, dst); !errors.Is(err, syscall.EIO) {
			t.Errorf("failed fsync: %v, want EIO", err)
		}
		nothingAt(t, dst)
	})
	t.Run("ended context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		dst := filepath.Join(dir, "cancelled.passh")
		setHook(t, func(p, _ string) {
			if p == hookCopySynced {
				cancel()
			}
		})
		if _, err := CopyChecked(ctx, e.path, dst); !errors.Is(err, context.Canceled) {
			t.Errorf("ended context: %v, want context.Canceled", err)
		}
		nothingAt(t, dst)
	})
}

// TestCopyCheckedCrash: a copy killed at any step leaves nothing under the
// destination's name (FILE-2); the next copy removes the temporary file
// the killed one left and succeeds.
func TestCopyCheckedCrash(t *testing.T) {
	e, orig, dir := copyEnv(t)
	for _, point := range []string{hookCopyCreated, hookCopyWritten, hookCopySynced, hookCopyVerified} {
		t.Run(point, func(t *testing.T) {
			dst := filepath.Join(dir, point+".passh")
			cmd := exec.Command(os.Args[0], "-test.run=^$")
			cmd.Env = append(os.Environ(),
				childEnv+"=copy-crash",
				childPathEnv+"="+e.path,
				childDestEnv+"="+dst,
				childCrashEnv+"="+point,
			)
			out, err := cmd.CombinedOutput()
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("child: %v, output %q", err, out)
			}
			if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
				t.Fatalf("child wasn't killed at %s: %v, output %q", point, err, out)
			}
			if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("killed at %s: %s exists: %v", point, dst, err)
			}
			if _, err := CopyChecked(t.Context(), e.path, dst); err != nil {
				t.Fatalf("copy after the crash: %v", err)
			}
			if got, _ := os.ReadFile(dst); !bytes.Equal(got, orig) {
				t.Error("copy after the crash differs from the vault")
			}
			for _, l := range temps(t, dir) {
				if strings.HasPrefix(l, tempPrefix(filepath.Base(dst))) {
					t.Errorf("the killed copy's temporary file is still there: %s", l)
				}
			}
		})
	}
}
