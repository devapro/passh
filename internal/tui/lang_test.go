package tui

// The TUI in Russian and Serbian (spec §3.3 `language`): the screens are
// translated, the keys stay the same, values and field names from the
// vault are not translated, and every frame still fits the window.

import (
	"context"
	"strings"
	"syscall"
	"testing"

	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/vault"
)

// langText is what the tests look for in each language.
type langText struct {
	lang        i18n.Lang
	title       string // the lock text in the frame's title
	tabs        string // the Folders/Tags tabs
	unlocked    string // the status after the unlock (6 entries)
	hints       []string
	narrowHints string
	tagsNote    string // the heading of the entries with the tag 2fa
	help        []string
	deleteQ     string // the delete question for work/github
	confirmKeys string
	notDeleted  string
	deleted     string
	locked      []string // the lock screen after L
	lockPass    []string // the lock screen asking for the passphrase
	wrongPass   string
	lockErr     string // an error rendered with Printer.Error: "Not deleted: the session is locked"
	noClip      string // why there is no clipboard
	printSetup  []string
	printDlg    []string
}

var langTexts = []langText{
	{
		lang:        i18n.Ru,
		title:       "разблокировано · блокировка через 5:00",
		tabs:        "ВИД: [Папки]  Теги",
		unlocked:    "Разблокировано: 6 записей, ревизия 1.",
		hints:       []string{"c копир. пароль", "u копир. логин", "d удалить", "/ поиск", "L заблокировать", "? справка", "q выйти"},
		narrowHints: "↵ открыть · c копировать · / поиск",
		tagsNote:    "── 2fa: 2 записи ──",
		help:        []string{"Клавиши", "переместить (переименовать) запись", "заблокировать сейчас (в текстовом поле L — это буква)"},
		deleteQ:     "Удалить work/github? [y/N]",
		confirmKeys: "y да · любая другая клавиша: нет",
		notDeleted:  "Не удалено.",
		deleted:     "Запись work/github удалена.",
		locked:      []string{"passh — хранилище заблокировано", "Парольная фраза", "Заблокировано. Буфер обмена очищен."},
		lockPass:    []string{"Парольная фраза", "Enter разблокировать · Esc очистить"},
		wrongPass:   "Неверная парольная фраза или повреждён блок ключа. Попробуйте ещё раз.",
		lockErr:     "Не удалено: сеанс заблокирован",
		noClip:      "буфер обмена не настроен",
		printSetup:  []string{"Страница печати: что печатать", "(•) все записи (6 записей)", "[x] password", "[x] username", "[x] url", "[ ] дополнительные поля"},
		printDlg:    []string{"Страница печати", "(1 из 2, Tab: следующий)", "Отпечаток сертификата (SHA-256)", "c копировать URL", "Остановится через 5:00"},
	},
	{
		lang:        i18n.Sr,
		title:       "otključano · zaključava se za 5:00",
		tabs:        "PRIKAZ: [Fascikle]  Oznake",
		unlocked:    "Otključano: 6 stavki, revizija 1.",
		hints:       []string{"c kopiraj lozinku", "u kopiraj kor. ime", "d obriši", "/ pretraga", "L zaključaj", "? pomoć", "q izađi"},
		narrowHints: "↵ otvori · c kopiraj · / pretraga",
		tagsNote:    "── 2fa: 2 stavke ──",
		help:        []string{"Tasteri", "premesti (preimenuj) stavku", "zaključaj odmah (u tekstualnom polju L je slovo)"},
		deleteQ:     "Obrisati work/github? [y/N]",
		confirmKeys: "y da · bilo koji drugi taster: ne",
		notDeleted:  "Nije obrisano.",
		deleted:     "Stavka work/github je obrisana.",
		locked:      []string{"passh — trezor je zaključan", "Pristupna fraza", "Zaključano. Ostava je očišćena."},
		lockPass:    []string{"Pristupna fraza", "Enter otključaj · Esc očisti"},
		wrongPass:   "Pogrešna pristupna fraza ili je blok ključa oštećen. Pokušajte ponovo.",
		lockErr:     "Nije obrisano: sesija je zaključana",
		noClip:      "ostava nije podešena",
		printSetup:  []string{"Stranica za štampu: šta štampati", "(•) sve stavke (6 stavki)", "[x] password", "[x] username", "[x] url", "[ ] dodatna polja"},
		printDlg:    []string{"Stranica za štampu", "(1 od 2, Tab: sledeći)", "Otisak sertifikata (SHA-256)", "c kopiraj URL", "Zaustavlja se za 5:00"},
	},
}

// English texts that must not show in a translated TUI.
var englishOnly = []string{"unlocked", "Folders", "copy pw", "search", "help", "quit", "Unlocked:", "entries"}

// sizes are the windows the translated screens are checked at: the
// mockup's 80×24, a narrow 60×20 and a phone's 40×16.
var sizes = [][2]int{{80, 24}, {60, 20}, {40, 16}}

func TestLangMainScreens(t *testing.T) {
	for _, lt := range langTexts {
		t.Run(lt.lang.String(), func(t *testing.T) {
			h := newHarness(t, sampleEntries(), withLang(lt.lang))
			h.resize(80, 24)
			h.contains("┌ passh ── "+lt.title, lt.tabs, lt.unlocked)
			h.contains(lt.hints...)
			h.lacks(englishOnly...)
			// Field names and values from the vault stay as they are.
			h.selectPath("work/github")
			h.contains("username  arsenii", "password  ••••••••", "url       https://github.com", "recovery-email", "notes     Recovery codes in notes.")
			// Tags: the plural heading of the selected tag's entries.
			h.press("tab", "space")
			h.contains(lt.tagsNote, "bank/revolut", "work/github")
			h.press("esc", "tab")

			for _, sz := range sizes {
				w, hh := sz[0], sz[1]
				h.resize(w, hh)
				check := func(what string) {
					t.Helper()
					h.checkFits(w, hh, what)
					h.checkInert(what)
				}
				check("main")
				if w < wideMin {
					h.contains(lt.narrowHints)
				}
				h.selectPath("work/github")
				h.press("enter")
				check("detail")
				h.press("r")
				check("revealed")
				h.press("r", "esc", "?")
				check("help")
				h.press("pgdown", "down", "down", "down", "down", "down", "down", "down", "down", "down", "down", "down", "down")
				check("help scrolled")
				h.press("x", "tab", "space", "down", "space")
				check("tags")
				h.press("tab", "/")
				h.typeText("git")
				check("search")
				h.press("esc")
				h.selectPath("work/github")
				h.press("d")
				check("confirm")
				h.press("n", "m")
				check("move prompt")
				h.press("esc", "t")
				check("tags prompt")
				h.press("esc", "e")
				check("form")
				h.press("esc")
				h.m.changedOnDisk = true
				check("changed on disk")
				h.press("e")
				check("changes refused")
				h.m.changedOnDisk = false
				h.m.confirm = &confirm{kind: confirmRollback, text: "the vault is older than one seen before."}
				check("rollback question")
				h.press("n")
			}
		})
	}
}

func TestLangHelp(t *testing.T) {
	for _, lt := range langTexts {
		t.Run(lt.lang.String(), func(t *testing.T) {
			h := newHarness(t, sampleEntries(), withLang(lt.lang))
			h.resize(80, 40)
			h.press("?")
			h.contains(lt.help...)
			// The keys are the same in every language.
			p := h.plain()
			for _, k := range []string{"↑ ↓  k j", "Enter  →", "←  Esc", "Tab ", "Space ", "c  u", "e  a"} {
				if !strings.Contains(p, k) {
					t.Fatalf("the help lacks the key %q:\n%s", k, p)
				}
			}
			h.checkFits(80, 40, "help")
			h.lacks("move (rename) an entry", "this help")
		})
	}
}

func TestLangDelete(t *testing.T) {
	for _, lt := range langTexts {
		t.Run(lt.lang.String(), func(t *testing.T) {
			h := newHarness(t, sampleEntries(), withLang(lt.lang))
			h.resize(80, 24)
			h.selectPath("work/github")
			h.press("d")
			h.contains(lt.deleteQ, lt.confirmKeys)
			h.checkFits(80, 24, "confirm")
			h.press("n")
			h.contains(lt.notDeleted)
			if _, ok := h.diskEntry("work/github"); !ok {
				t.Fatal("deleted after n")
			}
			// y answers yes in every language.
			h.press("d", "y")
			h.contains(lt.deleted)
			if _, ok := h.diskEntry("work/github"); ok {
				t.Fatal("not deleted after y")
			}
		})
	}
}

// removeFails is a vault whose deletes fail with err.
type removeFails struct {
	*vault.Vault
	err error
}

func (f removeFails) RemoveContext(context.Context, paths.Path) error { return f.err }

func TestLangLockScreen(t *testing.T) {
	for _, lt := range langTexts {
		t.Run(lt.lang.String(), func(t *testing.T) {
			h := newHarness(t, sampleEntries(), withLang(lt.lang), withPassphrase())
			for _, sz := range sizes {
				h.resize(sz[0], sz[1])
				h.checkFits(sz[0], sz[1], "lock screen")
			}
			h.resize(80, 24)
			h.contains(lt.lockPass...)
			h.lacks("Passphrase", "unlock")
			h.typeText("wrong")
			h.press("enter")
			h.contains(lt.wrongPass)
			for _, sz := range sizes {
				h.resize(sz[0], sz[1])
				h.checkFits(sz[0], sz[1], "wrong passphrase")
			}
			h.resize(80, 24)
			// The rollback question while unlocking.
			h.m.lk.ask = "the vault is older than one seen before."
			for _, sz := range sizes {
				h.resize(sz[0], sz[1])
				h.checkFits(sz[0], sz[1], "rollback question")
			}
			h.m.lk.ask = ""
			h.resize(80, 24)
			h.typeText(testPass)
			h.press("enter")
			h.mustUnlocked()
			h.contains(lt.unlocked)
			h.selectPath("work/github")
			h.press("c", "L")
			h.contains(lt.locked...)
			for _, sz := range sizes {
				h.resize(sz[0], sz[1])
				h.checkFits(sz[0], sz[1], "locked")
			}
		})
	}
}

// An error from another package is rendered in the language (Printer.Error),
// not with its English Error().
func TestLangError(t *testing.T) {
	for _, lt := range langTexts {
		t.Run(lt.lang.String(), func(t *testing.T) {
			h := newHarness(t, sampleEntries(), withLang(lt.lang), func(h *harness, d *deps) {
				h.wrap = func(v *vault.Vault) Vault { return removeFails{Vault: v, err: errLocked} }
			})
			h.resize(80, 24)
			h.selectPath("work/github")
			h.press("d", "y")
			h.contains(lt.lockErr)
			h.lacks("the session is locked")

			// No clipboard: the reason the TUI gives is translated (an
			// i18n.Mark key rendered by clipboard.NoClipboardError); the
			// hint is a command, the same in every language.
			h = newHarness(t, sampleEntries(), withLang(lt.lang), func(h *harness, d *deps) { d.clip, d.clipErr = nil, nil })
			h.resize(80, 24)
			h.selectPath("work/github")
			h.press("c")
			h.contains(lt.noClip, "passh show work/github --field password | pbcopy")
			h.lacks("no clipboard is configured")
		})
	}
	p := i18n.New(i18n.Ru)
	if got := p.Error(&SignalError{Signal: syscall.SIGTERM}); !strings.HasPrefix(got, "заблокировано и остановлено: получен сигнал ") {
		t.Errorf("SignalError in Russian: %q", got)
	}
	if got := (&SignalError{Signal: syscall.SIGTERM}).Error(); got != "locked and stopped: received terminated" {
		t.Errorf("SignalError in English: %q", got)
	}
}

func TestLangPrintPage(t *testing.T) {
	for _, lt := range langTexts {
		t.Run(lt.lang.String(), func(t *testing.T) {
			h := newHarness(t, sampleEntries(), withLang(lt.lang), func(h *harness, d *deps) { h.cfg.PrintWeb.Enabled = true })
			h.resize(80, 24)
			h.selectPath("readme")
			h.press("P")
			h.contains(lt.printSetup...)
			for _, sz := range sizes {
				h.resize(sz[0], sz[1])
				h.checkFits(sz[0], sz[1], "print setup")
			}
			h.press("esc")

			h, _, _ = printHarness(t, withLang(lt.lang))
			h.resize(80, 24)
			h.contains(lt.printDlg...)
			for _, sz := range sizes {
				h.resize(sz[0], sz[1])
				h.checkFits(sz[0], sz[1], "print dialog")
				h.checkInert("print dialog")
			}
		})
	}
}
