package vaultfile

import (
	"errors"
	"strings"
	"testing"

	"github.com/devapro/passh/internal/i18n"
)

// englishTexts returns the English text of each message.
func englishTexts(ms []i18n.Message) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.String()
	}
	return out
}

// TestMessagesTranslated renders the errors and warnings of Parse in
// Russian and Serbian: the text is translated, numbers and names are kept,
// and English stays what Error returns.
func TestMessagesTranslated(t *testing.T) {
	fx := newFixture(t)
	ru, sr := i18n.New(i18n.Ru), i18n.New(i18n.Sr)

	_, err := Parse([]byte("hello\n"))
	if !errors.Is(err, ErrNotVault) {
		t.Fatalf("err = %v", err)
	}
	if got := ru.Error(err); got != "не хранилище passh" {
		t.Errorf("ru: %q", got)
	}
	if got := sr.Error(err); got != "nije passh trezor" {
		t.Errorf("sr: %q", got)
	}

	// A truncated file: the sentinel and its detail are both translated.
	_, err = Parse(fx.file[:len(fx.file)/2])
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("err = %v", err)
	}
	if got := ru.Error(err); !strings.HasPrefix(got, "файл обрезан: ") || strings.Contains(got, "truncated") {
		t.Errorf("ru: %q", got)
	}
	if got := sr.Error(err); !strings.HasPrefix(got, "datoteka je odsečena: ") || strings.Contains(got, "truncated") {
		t.Errorf("sr: %q", got)
	}

	// A damaged block: the block number is kept, the reason translated.
	de := &DamagedError{Block: 2, Reason: "bad base64"}
	if got := ru.Error(de); got != "файл повреждён (блок 2): некорректный base64" {
		t.Errorf("ru: %q", got)
	}
	if got := sr.Error(de); got != "datoteka je oštećena (blok 2): neispravan base64" {
		t.Errorf("sr: %q", got)
	}
	if de.Error() != "file is damaged (block 2): bad base64" {
		t.Errorf("en: %q", de.Error())
	}

	// Warnings use the plural forms of each language.
	f, err := Parse(append([]byte("a\nb\nc\nd\ne\n"), append(fx.file, "x\nz\n"...)...))
	if err != nil {
		t.Fatal(err)
	}
	want := map[i18n.Lang][]string{
		i18n.En: {"ignored 5 lines of text before the passh-vault line", "ignored 2 lines of text after the last END line"},
		i18n.Ru: {"проигнорировано до строки passh-vault: 5 строк текста", "проигнорировано после последней строки END: 2 строки текста"},
		i18n.Sr: {"zanemareno pre reda passh-vault: 5 redova teksta", "zanemareno posle poslednjeg reda END: 2 reda teksta"},
	}
	for l, w := range want {
		p := i18n.New(l)
		for i, m := range f.Warnings {
			if got := m.Localize(p); got != w[i] {
				t.Errorf("%v: warning %d = %q, want %q", l, i, got, w[i])
			}
		}
	}
	if got := englishTexts(f.Warnings); got[0] != want[i18n.En][0] {
		t.Errorf("String: %q", got)
	}
}
