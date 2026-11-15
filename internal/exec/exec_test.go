package exec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The test binary doubles as the child program: TestMain checks helperEnv
// and, if set, behaves as the named helper instead of running tests.
const helperEnv = "PASSH_EXEC_HELPER"

func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "":
		os.Exit(m.Run())
	case "args":
		_ = json.NewEncoder(os.Stdout).Encode(os.Args[1:])
	case "env":
		_ = json.NewEncoder(os.Stdout).Encode(os.Environ())
	case "cat":
		_, _ = io.Copy(os.Stdout, os.Stdin)
	case "exit3":
		os.Exit(3)
	case "sleep":
		time.Sleep(time.Minute) // a child that runs until the test kills it
	case "detached":
		detachedHelper()
	default:
		os.Exit(100)
	}
	os.Exit(0)
}

// detachedReport is what the detached helper sees about itself.
type detachedReport struct {
	Args         []string
	Environ      []string
	ProcCmdline  string
	ProcEnviron  string
	Stdin        string
	Pid, Sid     int
	Dir          string
	StdoutIsNull bool
	StderrIsNull bool
}

// detachedHelper reads its stdin to EOF, then reports on fd 3.
func detachedHelper() {
	in, _ := io.ReadAll(os.Stdin)
	rep := detachedReport{
		Args:    os.Args,
		Environ: os.Environ(),
		Stdin:   string(in),
		Pid:     os.Getpid(),
	}
	rep.Sid, _ = unix.Getsid(0)
	rep.Dir, _ = os.Getwd()
	if b, err := os.ReadFile("/proc/self/cmdline"); err == nil {
		rep.ProcCmdline = string(b)
	}
	if b, err := os.ReadFile("/proc/self/environ"); err == nil {
		rep.ProcEnviron = string(b)
	}
	null, _ := os.Stat(os.DevNull)
	if fi, err := os.Stdout.Stat(); err == nil {
		rep.StdoutIsNull = os.SameFile(fi, null)
	}
	if fi, err := os.Stderr.Stat(); err == nil {
		rep.StderrIsNull = os.SameFile(fi, null)
	}
	out := os.NewFile(3, "report")
	_ = json.NewEncoder(out).Encode(rep)
	out.Close()
}

func helper(mode string, args ...string) Command {
	return Command{Name: os.Args[0], Args: args, Env: []string{helperEnv + "=" + mode}}
}

func TestArgumentsReachChildLiterally(t *testing.T) {
	dir := t.TempDir()
	pwned := filepath.Join(dir, "pwned")
	args := []string{
		"two words",
		`"double quoted"`,
		`'single quoted'`,
		"$(touch " + pwned + ")",
		"`touch " + pwned + "`",
		"a; touch " + pwned,
		"a && b || c | d > " + pwned,
		"$HOME",
		"~",
		"*",
		"",
		"-",
		"--",
		`back\slash`,
		"new\nline\ttab",
		"ünïcödé 日本",
	}
	var out bytes.Buffer
	c := helper("args", args...)
	c.Stdout = &out
	if err := Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	var got []string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decoding %q: %v", out.String(), err)
	}
	if !reflect.DeepEqual(got, args) {
		t.Errorf("child args =\n%q\nwant\n%q", got, args)
	}
	if _, err := os.Stat(pwned); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s exists: something interpreted an argument", pwned)
	}
}

func TestSystemProgramViaPath(t *testing.T) {
	out, err := Output(context.Background(), Command{
		Name: "printf",
		Args: []string{"%s|", "a b", "$(id)", ";", `"q"`, "'s'"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := `a b|$(id)|;|"q"|'s'|`; string(out) != want {
		t.Errorf("printf output = %q, want %q", out, want)
	}
	if p, err := LookPath("printf"); err != nil || !filepath.IsAbs(p) {
		t.Errorf("LookPath(printf) = %q, %v", p, err)
	}
}

func TestStdinStdoutStderr(t *testing.T) {
	var out bytes.Buffer
	c := helper("cat")
	c.Stdin = strings.NewReader("piped secret\n")
	c.Stdout = &out
	if err := Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if out.String() != "piped secret\n" {
		t.Errorf("stdout = %q", out.String())
	}
	// Output with Stdout already set is a programming error.
	if _, err := Output(context.Background(), c); err == nil {
		t.Error("Output with Stdout set succeeded")
	}
}

func childEnv(t *testing.T, c Command) []string {
	t.Helper()
	out, err := Output(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	var env []string
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestEnvironment(t *testing.T) {
	t.Setenv("PASSH_EXEC_TEST_INHERITED", "yes")
	t.Setenv("PASSH_EXEC_TEST_OVERRIDE", "old")

	c := helper("env")
	c.Env = append(c.Env, "GPG_TTY=/dev/pts/9", "PASSH_EXEC_TEST_OVERRIDE=new")
	env := childEnv(t, c)
	for _, want := range []string{"PASSH_EXEC_TEST_INHERITED=yes", "GPG_TTY=/dev/pts/9", "PASSH_EXEC_TEST_OVERRIDE=new"} {
		if !slices.Contains(env, want) {
			t.Errorf("child env lacks %q", want)
		}
	}
	n := 0
	for _, kv := range env {
		if strings.HasPrefix(kv, "PASSH_EXEC_TEST_OVERRIDE=") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("PASSH_EXEC_TEST_OVERRIDE appears %d times, want 1", n)
	}

	c.CleanEnv = true
	env = childEnv(t, c)
	slices.Sort(env)
	want := []string{"GPG_TTY=/dev/pts/9", helperEnv + "=env", "PASSH_EXEC_TEST_OVERRIDE=new"}
	slices.Sort(want)
	if !reflect.DeepEqual(env, want) {
		t.Errorf("clean env = %q, want %q", env, want)
	}

	for _, bad := range []string{"NOEQUALS", "=value"} {
		c := helper("env")
		c.Env = append(c.Env, bad)
		if err := Run(context.Background(), c); err == nil {
			t.Errorf("Env entry %q accepted", bad)
		}
	}
}

func TestErrors(t *testing.T) {
	ctx := context.Background()
	if err := Run(ctx, Command{}); err == nil {
		t.Error("empty program name accepted")
	}
	if err := Run(ctx, Command{Name: "passh-no-such-program-xyz"}); err == nil {
		t.Error("missing program accepted")
	}
	err := Run(ctx, helper("exit3"))
	var ee *ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Errorf("Run(exit3) = %v, want ExitError with code 3", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := Run(ctx, helper("sleep")); err == nil {
		t.Error("cancelled Run succeeded")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("cancel took %v", d)
	}
}

func TestStartDetached(t *testing.T) {
	secret := []byte("AGE-SECRET-KEY-1QQQ $(rm -rf /); \"quoted\" 'x'\nsecond line")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	c := helper("detached", "--hidden-agent", "/vault/path")
	c.ExtraFiles = []*os.File{w}
	proc, err := StartDetached(c, secret)
	w.Close()
	if err != nil {
		t.Fatal(err)
	}
	var rep detachedReport
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		t.Fatalf("reading report: %v", err)
	}
	st, err := proc.Wait()
	if err != nil || !st.Success() {
		t.Fatalf("child: %v, %v", st, err)
	}

	if rep.Stdin != string(secret) {
		t.Errorf("child stdin = %q, want the secret", rep.Stdin)
	}
	if !reflect.DeepEqual(rep.Args[1:], []string{"--hidden-agent", "/vault/path"}) {
		t.Errorf("child args = %q", rep.Args)
	}
	for name, s := range map[string]string{
		"args":          strings.Join(rep.Args, "\x00"),
		"environ":       strings.Join(rep.Environ, "\x00"),
		"cmdline":       rep.ProcCmdline,
		"/proc environ": rep.ProcEnviron,
	} {
		if strings.Contains(s, "AGE-SECRET-KEY") || strings.Contains(s, string(secret)) {
			t.Errorf("secret found in child %s", name)
		}
	}
	if runtime.GOOS == "linux" && rep.ProcCmdline == "" {
		t.Error("could not read /proc/self/cmdline in the child")
	}
	if rep.Sid != rep.Pid {
		t.Errorf("child sid = %d, pid = %d: not a session leader", rep.Sid, rep.Pid)
	}
	if rep.Dir != "/" {
		t.Errorf("child dir = %q, want /", rep.Dir)
	}
	if !rep.StdoutIsNull || !rep.StderrIsNull {
		t.Errorf("child stdout/stderr not /dev/null: %v/%v", rep.StdoutIsNull, rep.StderrIsNull)
	}
}

func TestStartDetachedRejectsIO(t *testing.T) {
	c := helper("detached")
	c.Stdout = io.Discard
	if _, err := StartDetached(c, nil); !errors.Is(err, ErrDetachedIO) {
		t.Errorf("StartDetached with Stdout = %v, want ErrDetachedIO", err)
	}
	if _, err := StartDetached(Command{Name: "passh-no-such-program-xyz"}, nil); err == nil {
		t.Error("StartDetached of a missing program succeeded")
	}
}

func TestSelf(t *testing.T) {
	p, err := Self()
	if err != nil || !filepath.IsAbs(p) {
		t.Errorf("Self() = %q, %v", p, err)
	}
}
