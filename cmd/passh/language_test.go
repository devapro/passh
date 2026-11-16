package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
)

// The language config key (§3.3): everything passh writes for people is in
// the config's language, help included; data and names are not.

// TestLanguageHelp: --help follows the config's language, found by the
// §3.3 rules before the arguments are parsed; without a usable config file
// it is English.
func TestLanguageHelp(t *testing.T) {
	t.Parallel()
	english := []string{"Usage:", "Available Commands:", "Flags:", "help for passh",
		"passh keeps passwords in one age-encrypted vault file."}
	cases := []struct {
		lang      string
		want, not []string
		global    string // the heading of init's global flags
	}{
		{"en", english, []string{"Использование:", "Upotreba:"}, "Global Flags:"},
		{"ru", []string{"Использование:", "Доступные команды:", "Флаги:", "справка по passh", "версия passh",
			"passh хранит пароли в одном файле хранилища", "Подробнее о команде: \"passh [command] --help\"."}, []string{"Usage:", "Flags:"}, "Глобальные флаги:"},
		{"sr", []string{"Upotreba:", "Dostupne komande:", "Opcije:", "pomoć za passh",
			"passh čuva lozinke u jednoj datoteci trezora"}, []string{"Usage:", "Flags:"}, "Globalne opcije:"},
	}
	for _, tc := range cases {
		e := newEnv(t)
		e.writeConfig("language = \"" + tc.lang + "\"\n")
		r := e.ok("--help")
		mustContain(t, tc.lang+" --help", r.stdout, tc.want...)
		mustNotContain(t, tc.lang+" --help", r.stdout, tc.not...)
		// Command and flag names, Use lines and the version stay as they are.
		mustContain(t, tc.lang+" --help", r.stdout, "passh [command]", "--config", "  unlock ", "-v, --version")
		r = e.ok("init", "--help")
		mustContain(t, tc.lang+" init --help", r.stdout, "passh init [--vault file] [flags]", tc.global)
		if r := e.ok("--version"); r.stdout != "passh dev\n" {
			t.Errorf("%s --version: %s", tc.lang, r)
		}
	}

	// No config file, --vault alone: English.
	e := newEnv(t)
	r := e.ok("--vault", filepath.Join(e.root, "v.passh"), "--help")
	mustContain(t, "no config", r.stdout, english...)

	// --config wins over $PASSH_CONFIG, in both spellings; after "--" it is
	// no flag.
	ru := filepath.Join(e.root, "ru.toml")
	if err := os.WriteFile(ru, []byte("vault = \"/v.passh\"\nlanguage = \"ru\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.writeConfig("language = \"sr\"\n")
	mustContain(t, "--config ru", e.ok("--config", ru, "--help").stdout, "Использование:")
	mustContain(t, "--config=ru", e.ok("--config="+ru, "--help").stdout, "Использование:")
	mustContain(t, "$PASSH_CONFIG sr", e.ok("--help").stdout, "Upotreba:")
	r = e.fail(2, "ls", "--", "--config", ru)
	mustContain(t, "after --", r.stderr, "Pomoć: 'passh --help'")

	// A usage error: the hint after the error is translated too.
	e.writeConfig("language = \"ru\"\n")
	r = e.fail(2, "ls", "--no-such-flag")
	mustContain(t, "ru usage error", r.stderr, "Справка: 'passh --help' или 'passh <command> --help'.")
}

// TestLanguageInvalid: an unknown language is a config error, reported in
// English (the config didn't load), like any other; help still works.
func TestLanguageInvalid(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, bad := range []string{"de", "RU", ""} {
		e.writeConfig("language = \"" + bad + "\"\n")
		r := e.fail(1, "ls")
		mustContain(t, "language "+bad, r.stderr, `language: "`+bad+`" is not one of "en", "ru" or "sr"`)
		mustContain(t, "language "+bad+" --help", e.ok("--help").stdout, "Usage:")
	}
}

// TestLanguageErrors: an error from the vault package (a wrong passphrase,
// keys.ErrWrongPassphrase inside a vault.OpenError) is shown in the
// config's language.
func TestLanguageErrors(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("three scrypt runs per language")
	}
	for lang, want := range map[string]string{
		"ru": "неверная парольная фраза или повреждён блок ключа",
		"sr": "pogrešna pristupna fraza ili je blok ključa oštećen",
	} {
		e := newEnv(t)
		e.withVault()
		e.writeConfig("language = \"" + lang + "\"\n")
		s := e.start(sessOpts{}, "ls")
		for range 3 {
			s.expectSecretPrompt(": ")
			s.send("not the passphrase\r")
		}
		r := s.wait()
		if r.code != 1 || !strings.Contains(r.out, "passh: ") || !strings.Contains(r.out, want) {
			t.Errorf("%s: wrong passphrase: want exit 1 and %q, got %s", lang, want, r)
		}
		mustNotContain(t, lang+" wrong passphrase", r.out, "wrong passphrase, or the key block is damaged")
	}
}

// TestLanguageInit: `passh init` with an existing config file in Russian
// explains, asks and confirms in Russian; the config file isn't changed.
func TestLanguageInit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.writeConfig("language = \"ru\"\n")
	before, err := os.ReadFile(e.config)
	if err != nil {
		t.Fatal(err)
	}
	const pass = "copper lantern meadow orbit quartz plum"
	s := e.start(sessOpts{}, "init")
	s.expect("Создание хранилища ")
	s.expect("Придумайте парольную фразу")
	s.expectSecretPrompt("Новая парольная фраза: ")
	s.send(pass + "\r")
	s.expectSecretPrompt("Повторите парольную фразу: ")
	s.send(pass + "\r")
	s.expect("Хранилище ")
	s.expect(" создано.")
	s.expect("Распечатать ключ восстановления сейчас? [Д/н]")
	s.send("n\r")
	r := s.waitOK()
	mustNotContain(t, "ru init", r.out, "Creating the vault", "New passphrase:", "Created the vault")
	if after, _ := os.ReadFile(e.config); string(after) != string(before) {
		t.Errorf("init changed the config file:\n%s", after)
	}
	if _, err := os.Stat(e.vault); err != nil {
		t.Errorf("no vault: %v", err)
	}
}

// TestLanguageCommandHelp: each command's help (Short in the list, Long,
// flag texts) follows the config's language; Use lines, command and flag
// names and the typed confirmation phrases don't.
func TestLanguageCommandHelp(t *testing.T) {
	t.Parallel()
	cases := []struct {
		lang string
		want map[string][]string // command -> texts its help shows
		root []string            // command lines of passh --help
	}{
		{"ru", map[string][]string{
			"show": {"Выводит запись в текстовой форме", "вывести только это поле: password, username, url, tags, notes",
				"выводить точные байты", "  passh show work/github --field password | pbcopy"},
			"unlock": {"Спрашивает парольную фразу и запускает агент", "остановить новый агент через это время"},
			"export": {"Экспортирует записи в csv", "EXPORT PLAINTEXT", "подтвердить экспорт в открытом виде",
				"только записи с этим тегом", "(по умолчанию"},
			"doctor": {"Проверяет всё, от чего зависит passh, ничего не меняя"},
		}, []string{"  show         Вывести запись (текстовая форма) или одно поле", "  rm           Удалить запись (с подтверждением)",
			"конфигурационный файл (по умолчанию $PASSH_CONFIG"}},
		{"sr", map[string][]string{
			"show": {"Prikazuje stavku u tekstualnom obliku", "ispiši samo ovo polje: password, username, url, tags, notes",
				"ispiši tačne bajtove", "  passh show work/github --field password | pbcopy"},
			"unlock": {"Traži pristupnu frazu i pokreće agenta", "zaustavi novog agenta posle ovoliko vremena"},
			"export": {"Izvozi stavke kao csv", "EXPORT PLAINTEXT", "potvrdi izvoz kao otvoreni tekst",
				"samo stavke sa ovom oznakom", "(podrazumevano"},
			"doctor": {"Proverava, samo čitanjem, sve od čega passh zavisi"},
		}, []string{"  show         Prikaži stavku (tekstualni oblik) ili jedno polje", "  rm           Obriši stavku (uz potvrdu)",
			"konfiguraciona datoteka (podrazumevano $PASSH_CONFIG"}},
	}
	uses := map[string]string{
		"show":   "passh show <path> [flags]",
		"unlock": "passh unlock [--ttl d] [flags]",
		"export": "passh export --format <csv|json|bitwarden-json> [flags]",
		"doctor": "passh doctor [flags]",
	}
	flags := map[string][]string{
		"show":   {"--field string", "--raw"},
		"unlock": {"--ttl duration"},
		"export": {"--age string", "--confirm-plaintext", "-o, --output string", "--spreadsheet-safe", "--tag strings"},
	}
	for _, tc := range cases {
		e := newEnv(t)
		e.writeConfig("language = \"" + tc.lang + "\"\n")
		r := e.ok("--help")
		mustContain(t, tc.lang+" --help", r.stdout, tc.root...)
		for cmd, want := range tc.want {
			r := e.ok(cmd, "--help")
			what := tc.lang + " " + cmd + " --help"
			mustContain(t, what, r.stdout, want...)
			mustContain(t, what, r.stdout, uses[cmd])
			mustContain(t, what, r.stdout, flags[cmd]...)
		}
	}
}

// TestLanguageUsageErrors: usage errors made by passh, cobra and pflag are
// translated, with exit status 2 and the translated hint.
func TestLanguageUsageErrors(t *testing.T) {
	t.Parallel()
	cases := map[string][][]string{ // args, then wanted texts
		"ru": {
			{"ls --no-such-flag", "passh: неизвестный флаг: --no-such-flag"},
			{"ls -x", "passh: неизвестный короткий флаг 'x' в -x"},
			{"unlock --ttl", "passh: флагу нужно значение: --ttl"},
			{"unlock --ttl xx", `passh: недопустимое значение "xx" для флага "--ttl": time: invalid duration "xx"`},
			{"show", "passh: принимает аргументов: 1, получено: 0"},
			{"verify a b", "passh: принимает от 0 до 1 аргументов, получено: 2"},
			{"tags x", `passh: неизвестная команда "x" для "passh tags"`},
			{"nosuch", `passh: неизвестная команда "nosuch" для passh`},
			{"generate a b", `passh: длина "b": укажите число от 1 до 4096`},
			{"import", "passh: укажите, откуда импортировать, например `passh import pass`"},
		},
		"sr": {
			{"ls --no-such-flag", "passh: nepoznata opcija: --no-such-flag"},
			{"unlock --ttl", "passh: opciji je potrebna vrednost: --ttl"},
			{"show", "passh: prihvata argumenata: 1, primljeno: 0"},
			{"recovery-key nosuch", `passh: nepoznata komanda "nosuch" za "passh recovery-key"`},
			{"tag a", "passh: navedite --add i/ili --remove"},
		},
	}
	hint := map[string]string{
		"ru": "Справка: 'passh --help' или 'passh <command> --help'.",
		"sr": "Pomoć: 'passh --help' ili 'passh <command> --help'.",
	}
	for lang, list := range cases {
		e := newEnv(t)
		e.writeConfig("language = \"" + lang + "\"\n")
		for _, c := range list {
			r := e.fail(2, strings.Fields(c[0])...)
			mustContain(t, lang+" "+c[0], r.stderr, c[1], hint[lang])
			mustNotContain(t, lang+" "+c[0], r.stderr, "Run 'passh --help'")
		}
	}
}

// TestLanguageDoctor: doctor's report is for people, so it is translated:
// the level and check columns, the messages and the summary; paths and
// names stay as they are.
func TestLanguageDoctor(t *testing.T) {
	t.Parallel()
	want := map[string][]string{
		"ru": {"ок ", "конфигурация", "хранилище ", "vault.passh: структура в порядке, ", " байт",
			"права хранилища", "папка состояния", "терминал", "нет: запросы невозможны", "ошиб", "предупрежд"},
		"sr": {"ok ", "konfiguracija", "trezor ", "vault.passh: struktura je u redu, ", " bajt",
			"dozvole trezora", "fascikla stanja", "terminal", "nema: upiti nisu mogući", "greš", "upozor"},
	}
	for lang, w := range want {
		e := newEnv(t)
		e.withVault()
		e.writeConfig("language = \"" + lang + "\"\n")
		r := e.run("doctor")
		mustContain(t, lang+" doctor", r.stdout, w...)
		mustNotContain(t, lang+" doctor", r.stdout, "structure OK", "vault mode", "state folder")
	}
}

// TestLanguageStatusAndData: with the agent running, status lines are
// translated, and the data on stdout (ls, show, find, tags, verify,
// export) is byte for byte the same in every language.
func TestLanguageStatusAndData(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.withVault()
	e.addEntries(
		model.Entry{Path: paths.MustParse("work/github"), Password: "s3cr3t", Username: "arsenii", URL: "https://github.com",
			Tags: []string{"dev"}, Notes: "line one\nline two"},
		model.Entry{Path: paths.MustParse("bank/card"), Password: "1234", Tags: []string{"money"}},
	)
	e.unlock(fixturePass) // English: the config names no language yet
	defer e.ok("lock")

	data := func(lang string) map[string]string {
		e.writeConfig("language = \"" + lang + "\"\n")
		out := map[string]string{}
		for _, args := range [][]string{
			{"ls"}, {"ls", "work"}, {"show", "work/github"}, {"show", "work/github", "--field", "username"},
			{"find", "gthb"}, {"tags"}, {"verify"}, {"backups"},
			{"export", "--format", "json", "--confirm-plaintext"}, {"export", "--format", "csv", "--confirm-plaintext"},
		} {
			r := e.ok(args...)
			// The export time differs from run to run.
			out[strings.Join(args, " ")] = exportedAt.ReplaceAllString(r.stdout, `"exported_at": "…"`)
		}
		return out
	}
	en := data("en")
	for _, lang := range []string{"ru", "sr"} {
		got := data(lang)
		for k, v := range en {
			if got[k] != v {
				t.Errorf("%s: stdout of %s differs from English:\n%s\n--- en ---\n%s", lang, k, got[k], v)
			}
		}
	}

	e.writeConfig("language = \"ru\"\n")
	mustStatus(t, "ru tag", e.ok("tag", "work/github", "--add", "x"), "work/github: теги dev, x")
	mustStatus(t, "ru tag again", e.ok("tag", "work/github", "--add", "x"), "work/github: теги dev, x (без изменений)")
	mustStatus(t, "ru mv", e.ok("mv", "work/github", "work/gh"), "Запись work/github перемещена в work/gh.")
	mustStatus(t, "ru mv folder", e.ok("mv", "work", "old"), "Папка work/ перемещена в old/ (1 запись).")
	mustStatus(t, "ru rm", e.ok("rm", "--force", "old/gh"), "Запись old/gh удалена.")
	// The length and the bits each agree with their own number.
	mustStatus(t, "ru generate", e.ok("generate", "bank/ru", "21"),
		"Запись bank/ru сохранена: новый пароль из 21 символа (буквы и цифры, 125 бит).\nПоказать его: passh show bank/ru --field password")
	r := e.fail(1, "show", "nope/x")
	mustContain(t, "ru show missing", r.stderr, "passh: nope/x: ")
	r = e.fail(1, "show", "bank")
	mustContain(t, "ru show folder", r.stderr, "passh: bank — папка, а не запись: её содержимое покажет `passh ls bank`")
	r = e.ok("verify", "--full")
	mustContain(t, "ru verify --full", r.stdout, ": OK\n", "  SHA-256   ", "  revision  ", "  rollback  OK: ")
	mustContain(t, "ru verify --full", r.stdout, "компьютер")

	e.writeConfig("language = \"sr\"\n")
	mustStatus(t, "sr tag", e.ok("tag", "bank/card", "--remove", "money"), "bank/card: nema oznaka")
	mustStatus(t, "sr generate", e.ok("generate", "bank/new", "12"),
		"Stavka bank/new je sačuvana: nova lozinka od 12 znakova (slova i cifre, 71 bit).\nPrikažite je komandom: passh show bank/new --field password")
	r = e.ok("verify", "--full")
	mustContain(t, "sr verify --full", r.stdout, "  rollback  OK: ", "računar")
	mustStatus(t, "sr lock", e.ok("lock"), "Zaključano: agent (pid ")
	mustStatus(t, "sr lock again", e.ok("lock"), "Za ~/.local/share/passh/vault.passh ne radi nijedan agent.")
	r = e.fail(1, "ls")
	mustContain(t, "sr locked", r.stderr, "passh: trezor je zaključan: pokrenite `passh unlock` u terminalu")
}

// exportedAt matches the export time in a json export.
var exportedAt = regexp.MustCompile(`"exported_at": "[^"]*"`)
