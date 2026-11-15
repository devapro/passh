package importpass

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

var testNow = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

// writeScript writes an executable shell script and returns its path.
func writeScript(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-gpg")
	if err := os.WriteFile(p, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeGPG is a stand-in gpg that records its arguments, GPG_TTY and stdin
// in dir, then prints out (with printf) on stdout, status (with printf)
// on fd 3 and human on stderr, and exits with code.
func fakeGPG(t *testing.T, dir, out, status, human string, code int) string {
	t.Helper()
	return writeScript(t, `#!/bin/sh
printf '%s\n' "$@" > '`+dir+`/args'
printf '%s' "$GPG_TTY" > '`+dir+`/tty'
cat > '`+dir+`/stdin'
printf '`+out+`'
printf '`+status+`' >&3
printf '`+human+`' >&2
exit `+string(rune('0'+code))+`
`)
}

func oneFileStore(t *testing.T, content string) string {
	t.Helper()
	store := t.TempDir()
	writeStore(t, store, []storeFile{{name: "sub/entry.gpg", raw: []byte(content)}})
	return store
}

func TestStatusJudgement(t *testing.T) {
	const okay = `[GNUPG:] BEGIN_DECRYPTION\n[GNUPG:] DECRYPTION_OKAY\n[GNUPG:] GOODMDC\n[GNUPG:] END_DECRYPTION\n`
	cases := []struct {
		name, out, status, human string
		code                     int
		wantFailure              string // "" means imported
	}{
		{"okay", `pw\nuser: u\n`, okay, ``, 0, ""},
		{"human text is ignored", `pw\n`, okay, `gpg: decryption failed: No secret key\n`, 0, ""},
		{"exit 0, no status", `pw\n`, ``, `gpg: decryption okay\n`, 0, "gpg did not report a successful decryption"},
		{"exit 0, NODATA only (truncated file)", ``, `[GNUPG:] NODATA 3\n`, ``, 0, "not an OpenPGP message"},
		{"okay then BADMDC", `pw\n`, `[GNUPG:] DECRYPTION_OKAY\n[GNUPG:] BADMDC\n`, ``, 0, "gpg reported BADMDC"},
		{"okay then DECRYPTION_FAILED", `pw\n`, `[GNUPG:] DECRYPTION_OKAY\n[GNUPG:] DECRYPTION_FAILED\n`, ``, 0, "DECRYPTION_FAILED"},
		{"okay with ERROR", `pw\n`, `[GNUPG:] DECRYPTION_OKAY\n[GNUPG:] ERROR decrypt 1\n`, ``, 0, "ERROR decrypt 1"},
		{"okay but exit 2", `pw\n`, okay, ``, 2, "gpg failed (exit status 2)"},
		{"exit 2 without status", ``, ``, ``, 2, "gpg failed (exit status 2)"},
		{"no secret key", ``, `[GNUPG:] NO_SECKEY 93DE7CA0368F2915\n[GNUPG:] BEGIN_DECRYPTION\n[GNUPG:] DECRYPTION_FAILED\n`, ``, 2, "no secret key for key ID 93DE7CA0368F2915"},
		{"one of two keys missing", `pw\n`, `[GNUPG:] NO_SECKEY AAAA\n` + okay, ``, 0, ""},
		{"bad passphrase", ``, `[GNUPG:] BAD_PASSPHRASE 1234\n[GNUPG:] DECRYPTION_FAILED\n`, ``, 2, "bad passphrase"},
		{"missing passphrase", ``, `[GNUPG:] MISSING_PASSPHRASE\n[GNUPG:] DECRYPTION_FAILED\n`, ``, 2, "no passphrase given"},
		{"not a status line", `pw\n`, `DECRYPTION_OKAY\n[GNUPG:]DECRYPTION_OKAY\n`, ``, 0, "did not report"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := t.TempDir()
			store := oneFileStore(t, "CIPHERTEXT\x00\x01\xff")
			res, err := Run(t.Context(), Options{
				Dir: store,
				GPG: GPG{Program: fakeGPG(t, rec, c.out, c.status, c.human, c.code), TTY: "/dev/pts/42"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if c.wantFailure == "" {
				if len(res.Items) != 1 || len(res.Skipped) != 0 || res.Items[0].Entry.Password != "pw" {
					t.Fatalf("not imported: %+v", res)
				}
			} else {
				if len(res.Items) != 0 || len(res.Skipped) != 1 {
					t.Fatalf("imported: %+v", res)
				}
				s := res.Skipped[0]
				if s.Reason != DecryptFailed || !strings.Contains(s.Detail, c.wantFailure) {
					t.Errorf("skip = %+v, want detail with %q", s, c.wantFailure)
				}
			}

			// The ciphertext goes through stdin; no path is passed.
			args, _ := os.ReadFile(filepath.Join(rec, "args"))
			if want := "--quiet\n--status-fd\n3\n--decrypt\n"; string(args) != want {
				t.Errorf("args = %q, want %q", args, want)
			}
			stdin, _ := os.ReadFile(filepath.Join(rec, "stdin"))
			if string(stdin) != "CIPHERTEXT\x00\x01\xff" {
				t.Errorf("stdin = %q", stdin)
			}
			if tty, _ := os.ReadFile(filepath.Join(rec, "tty")); string(tty) != "/dev/pts/42" {
				t.Errorf("GPG_TTY = %q", tty)
			}
		})
	}
}

func TestGPGArgsAndTTY(t *testing.T) {
	rec := t.TempDir()
	store := oneFileStore(t, "x")
	fake := fakeGPG(t, rec, `pw\n`, `[GNUPG:] DECRYPTION_OKAY\n`, ``, 0)

	// Extra options go first; GPG_TTY is inherited when set.
	t.Setenv("GPG_TTY", "/dev/pts/77")
	if _, err := Run(t.Context(), Options{Dir: store, GPG: GPG{Program: fake, Args: []string{"--homedir", "/h", "--batch"}}}); err != nil {
		t.Fatal(err)
	}
	args, _ := os.ReadFile(filepath.Join(rec, "args"))
	if want := "--homedir\n/h\n--batch\n--quiet\n--status-fd\n3\n--decrypt\n"; string(args) != want {
		t.Errorf("args = %q", args)
	}
	if tty, _ := os.ReadFile(filepath.Join(rec, "tty")); string(tty) != "/dev/pts/77" {
		t.Errorf("GPG_TTY = %q", tty)
	}

	// The option wins over the environment.
	if _, err := Run(t.Context(), Options{Dir: store, GPG: GPG{Program: fake, TTY: "/dev/ttys004"}}); err != nil {
		t.Fatal(err)
	}
	if tty, _ := os.ReadFile(filepath.Join(rec, "tty")); string(tty) != "/dev/ttys004" {
		t.Errorf("GPG_TTY = %q", tty)
	}

	// gpg's messages reach Stderr when asked for.
	var stderr strings.Builder
	fake2 := fakeGPG(t, rec, `pw\n`, `[GNUPG:] DECRYPTION_OKAY\n`, `gpg: hello\n`, 0)
	if _, err := Run(t.Context(), Options{Dir: store, GPG: GPG{Program: fake2, Stderr: &stderr}}); err != nil {
		t.Fatal(err)
	}
	if stderr.String() != "gpg: hello\n" {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestPinentryCanceledStops(t *testing.T) {
	rec := t.TempDir()
	store := t.TempDir()
	writeStore(t, store, []storeFile{{name: "a.gpg", raw: []byte("x")}, {name: "b.gpg", raw: []byte("x")}})
	// gpg-agent's GPG_ERR_CANCELED (99) from source 5: 83886179.
	for _, status := range []string{
		`[GNUPG:] ERROR pkdecrypt_failed 83886179\n[GNUPG:] DECRYPTION_FAILED\n`,
		`[GNUPG:] FAILURE decrypt 83886278\n`, // GPG_ERR_FULLY_CANCELED (198)
	} {
		var calls int
		_, err := Run(t.Context(), Options{
			Dir:      store,
			Progress: func(int, int, string) { calls++ },
			GPG:      GPG{Program: fakeGPG(t, rec, ``, status, ``, 2)},
		})
		if !errors.Is(err, ErrCanceled) || calls != 1 {
			t.Errorf("error = %v after %d files", err, calls)
		}
	}
}

func TestContextCanceled(t *testing.T) {
	store := t.TempDir()
	writeStore(t, store, []storeFile{{name: "a.gpg", raw: []byte("x")}, {name: "b.gpg", raw: []byte("x")}})
	fake := writeScript(t, "#!/bin/sh\ncat >/dev/null\nexec sleep 10\n")
	ctx, cancel := context.WithCancel(t.Context())
	var calls int
	start := time.Now()
	_, err := Run(ctx, Options{
		Dir: store,
		Progress: func(int, int, string) {
			calls++
			time.AfterFunc(100*time.Millisecond, cancel)
		},
		GPG: GPG{Program: fake},
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Errorf("error = %v after %d files", err, calls)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("cancel didn't stop gpg")
	}

	// Already canceled: no gpg at all.
	calls = 0
	if _, err := Run(ctx, Options{Dir: store, Progress: func(int, int, string) { calls++ }, GPG: GPG{Program: fake}}); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Errorf("error = %v after %d files", err, calls)
	}
}

func TestPlaintextTooLarge(t *testing.T) {
	store := oneFileStore(t, "x")
	fake := writeScript(t, "#!/bin/sh\ncat >/dev/null\necho '[GNUPG:] DECRYPTION_OKAY' >&3\nhead -c 5000000 /dev/zero\n")
	res, err := Run(t.Context(), Options{Dir: store, GPG: GPG{Program: fake}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Reason != DecryptFailed || !strings.Contains(res.Skipped[0].Detail, "larger than 4 MiB") {
		t.Errorf("result = %+v", res)
	}
}

// TestStatusPipeHeldOpen: a process that outlives gpg with the status pipe
// open (as a careless gpg-agent start could) doesn't hang the import.
func TestStatusPipeHeldOpen(t *testing.T) {
	store := oneFileStore(t, "x")
	fake := writeScript(t, "#!/bin/sh\ncat >/dev/null\nprintf 'pw\\n'\necho '[GNUPG:] DECRYPTION_OKAY' >&3\n(sleep 4 >/dev/null 2>&1 </dev/null &)\n")
	start := time.Now()
	res, err := Run(t.Context(), Options{Dir: store, GPG: GPG{Program: fake}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 1 {
		t.Errorf("result = %+v", res)
	}
	if d := time.Since(start); d > statusTimeout+time.Second {
		t.Errorf("took %v", d)
	}
}

func TestParseStatus(t *testing.T) {
	st := parseStatus([]byte("[GNUPG:] NO_SECKEY A\r\n[GNUPG:] NO_SECKEY B\n[GNUPG:] \n[GNUPG:] ERROR x notanumber\ngarbage\n[GNUPG:] DECRYPTION_OKAY\n"))
	if !st.okay || !slices.Equal(st.noSecKey, []string{"A", "B"}) || st.canceled || len(st.failures) != 1 || st.ok() {
		t.Errorf("status = %+v", st)
	}
	if got := (gpgStatus{noSecKey: []string{"A", "B"}}).failure(nil); got != "no secret key for key ID A, B" {
		t.Error(got)
	}
}

func TestTTYName(t *testing.T) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Skip("no pty:", err)
	}
	defer ptmx.Close()
	defer tty.Close()

	if got := ttyName(tty); got != tty.Name() {
		t.Errorf("ttyName = %q, want %q", got, tty.Name())
	}
	devNull, _ := os.Open(os.DevNull)
	defer devNull.Close()
	if got := terminalName(devNull, nil, tty); got != tty.Name() {
		t.Errorf("terminalName = %q", got)
	}
	if got := terminalName(devNull); got != "" {
		t.Errorf("terminalName(/dev/null) = %q", got)
	}

	// The /dev scan used where there is no /proc.
	var st syscall.Stat_t
	if err := syscall.Fstat(int(tty.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	if got := findDevice(&st, "/nonexistent", filepath.Dir(tty.Name())); got != tty.Name() {
		t.Errorf("findDevice = %q, want %q", got, tty.Name())
	}
	if isTTYPath("/dev/tty") || !isTTYPath("/dev/pts/1") || isTTYPath("pts/1") {
		t.Error("isTTYPath")
	}
}
