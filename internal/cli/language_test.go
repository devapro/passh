package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/importpass"
	"github.com/devapro/passh/internal/paths"
)

func TestGlobalFlags(t *testing.T) {
	cases := []struct {
		args          []string
		config, vault string
	}{
		{nil, "", ""},
		{[]string{"ls"}, "", ""},
		{[]string{"--config", "a.toml", "ls"}, "a.toml", ""},
		{[]string{"ls", "--config=b.toml", "--vault", "v.passh"}, "b.toml", "v.passh"},
		{[]string{"--config", "a", "--config=b"}, "b", ""},
		{[]string{"show", "--", "--config", "a"}, "", ""},
		{[]string{"--vault=", "--config"}, "", ""},
		{[]string{"--configx", "a", "--vault-x=b"}, "", ""},
	}
	for _, tc := range cases {
		c, v := globalFlags(tc.args)
		if c != tc.config || v != tc.vault {
			t.Errorf("globalFlags(%q) = %q, %q, want %q, %q", tc.args, c, v, tc.config, tc.vault)
		}
	}
}

func TestLanguage(t *testing.T) {
	dir := t.TempDir()
	for _, k := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR"} {
		t.Setenv(k, dir)
	}
	t.Setenv("PASSH_CONFIG", filepath.Join(dir, "missing.toml"))
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ru := write("ru.toml", "vault = \"/v\"\nlanguage = \"ru\"\n")
	sr := write("sr.toml", "language = \"sr\"\n") // no vault: loads only with --vault
	bad := write("bad.toml", "vault = \"/v\"\nlanguage = \"ru\"\ntypo = 1\n")
	cases := []struct {
		args []string
		want i18n.Lang
	}{
		{[]string{"ls"}, i18n.En},
		{[]string{"--config", ru, "ls"}, i18n.Ru},
		{[]string{"--config", sr, "ls"}, i18n.En},
		{[]string{"--config", sr, "--vault", "/v", "ls"}, i18n.Sr},
		{[]string{"--config", bad, "ls"}, i18n.En},
		{[]string{"--vault", "/v", "ls"}, i18n.En},
		{[]string{"__agent", "--config", ru}, i18n.En},
	}
	for _, tc := range cases {
		if got := language(tc.args); got != tc.want {
			t.Errorf("language(%q) = %v, want %v", tc.args, got, tc.want)
		}
	}
	t.Setenv("PASSH_CONFIG", ru)
	if got := language([]string{"ls"}); got != i18n.Ru {
		t.Errorf("language with $PASSH_CONFIG = %v, want ru", got)
	}
}

// TestUsageLikeCobra: in English, passh's usage text (help.go) is exactly
// cobra's and pflag's, for every command.
func TestUsageLikeCobra(t *testing.T) {
	a := &app{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr}
	root := a.rootCommand()
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		ours := c.UsageString()
		root.SetUsageFunc(nil) // cobra's default
		theirs := c.UsageString()
		root.SetUsageFunc(a.usage)
		if ours != theirs {
			t.Errorf("%s: usage differs from cobra's:\n--- passh\n%s\n--- cobra\n%s", c.CommandPath(), ours, theirs)
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)

	// In another language the headings and cobra's flag texts change, the
	// names don't.
	a = &app{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, p: i18n.New(i18n.Sr)}
	root = a.rootCommand()
	got := root.UsageString()
	for _, want := range []string{"Upotreba:", "Dostupne komande:", "Opcije:", "pomoć za passh", "verzija programa passh", "  passh [command]", "--config string"} {
		if !strings.Contains(got, want) {
			t.Errorf("sr usage: no %q in:\n%s", want, got)
		}
	}
}

// TestFlagErrors: pflag's parse errors keep their English text, type and
// usage-error status, and are shown translated (flagError).
func TestFlagErrors(t *testing.T) {
	cases := []struct {
		args    []string
		en, ru  string
		notExst bool
	}{
		{[]string{"ls", "--nope"}, "unknown flag: --nope", "неизвестный флаг: --nope", true},
		{[]string{"ls", "-zq"}, "unknown shorthand flag: 'z' in -zq", "неизвестный короткий флаг 'z' в -zq", true},
		{[]string{"unlock", "--ttl"}, "flag needs an argument: --ttl", "флагу нужно значение: --ttl", false},
		{[]string{"export", "-o"}, "flag needs an argument: 'o' in -o", "флагу нужно значение: 'o' в -o", false},
		{[]string{"unlock", "--ttl=x"}, `invalid argument "x" for "--ttl" flag: time: invalid duration "x"`,
			`недопустимое значение "x" для флага "--ttl": time: invalid duration "x"`, false},
		{[]string{"rm", "-f=maybe", "a"}, `invalid argument "maybe" for "-f, --force" flag: strconv.ParseBool: parsing "maybe": invalid syntax`,
			`недопустимое значение "maybe" для флага "-f, --force": strconv.ParseBool: parsing "maybe": invalid syntax`, false},
		{[]string{"ls", "---x"}, "bad flag syntax: ---x", "неверный синтаксис флага: ---x", false},
	}
	ru := i18n.New(i18n.Ru)
	for _, tc := range cases {
		a := &app{stdin: os.Stdin, stdout: devNull(t), stderr: devNull(t), p: ru}
		root := a.rootCommand()
		root.SetArgs(tc.args)
		root.SetOut(devNull(t))
		root.SetErr(devNull(t))
		err := root.Execute()
		var ue *usageError
		if !errors.As(err, &ue) {
			t.Errorf("%q: %v is not a usage error", tc.args, err)
			continue
		}
		if err.Error() != tc.en {
			t.Errorf("%q: English %q, want %q", tc.args, err.Error(), tc.en)
		}
		if got := ru.Error(err); got != tc.ru {
			t.Errorf("%q: ru %q, want %q", tc.args, got, tc.ru)
		}
		var ne *pflag.NotExistError
		if errors.As(err, &ne) != tc.notExst {
			t.Errorf("%q: errors.As(*pflag.NotExistError) = %v", tc.args, !tc.notExst)
		}
	}
}

// TestDoctorReportColumns: the doctor's columns are as wide as their
// longest text in the language, counted in characters.
func TestDoctorReportColumns(t *testing.T) {
	for _, l := range i18n.Langs() {
		out, err := os.CreateTemp(t.TempDir(), "doctor")
		if err != nil {
			t.Fatal(err)
		}
		a := &app{stdout: out, p: i18n.New(l)}
		d := &doctor{a: a}
		d.addf(levelOK, chkVault, "%s is writable", "~/x")
		d.addf(levelError, chkEditTemp, "none")
		d.addf(levelWarn, chkCoreDumps, "not disabled: a crash could write secrets to a core file")
		if err := d.report(); !errors.Is(err, errReported) {
			t.Errorf("%v: report: %v", l, err)
		}
		data, err := os.ReadFile(out.Name())
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
		if len(lines) != 4 {
			t.Fatalf("%v: report:\n%s", l, data)
		}
		// The message column starts where the longest label ends, plus two.
		p := i18n.New(l)
		levelW := 0
		for lv := range numLevels {
			levelW = max(levelW, len([]rune(lv.name(p))))
		}
		labelW := max(len([]rune(chkVault.name(p))), len([]rune(chkEditTemp.name(p))), len([]rune(chkCoreDumps.name(p))))
		for i, f := range d.findings {
			want := f.msg
			if got := string([]rune(lines[i])[levelW+2+labelW+2:]); got != want {
				t.Errorf("%v: line %q: message column %q, want %q", l, lines[i], got, want)
			}
		}
		if l == i18n.En && lines[3] != "1 error, 1 warning." {
			t.Errorf("en summary %q", lines[3])
		}
	}
}

// TestImportReportRu: the import report in Russian; names stay as they are.
func TestImportReportRu(t *testing.T) {
	res := &importpass.Result{
		Dir:    "/store",
		DryRun: true,
		Items: []importpass.Item{
			{File: "a.gpg", Path: paths.MustParse("a"), Replace: true},
			{File: "b.gpg", Path: paths.MustParse("b")},
		},
		Skipped: []importpass.Skip{{File: "x.gpg", Reason: importpass.InvalidPath}},
	}
	out := importReportIn(i18n.New(i18n.Ru), res, 1)
	for _, want := range []string{
		"Пробный запуск: ничего не расшифровано и не сохранено. Хранилище pass: /store\n",
		"Будут импортированы 2 записи:\n",
		"  a  (заменит запись в хранилище)\n",
		"  b\n",
		"Будут импортированы 2 записи (1 из них заменяет запись, уже имеющуюся в хранилище).\n",
		"Будет пропущен 1 файл (",
		" — 1).\n",
		"  x.gpg — ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	res.DryRun = false
	out = importReportIn(i18n.New(i18n.Ru), res, 0)
	if !strings.Contains(out, "Импортированы 2 записи из /store.\n") || !strings.Contains(out, "Пропущен 1 файл (") {
		t.Errorf("report:\n%s", out)
	}
}
