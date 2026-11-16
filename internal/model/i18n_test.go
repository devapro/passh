package model

import (
	"testing"
	"time"

	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/paths"
)

// TestErrorsTranslated renders model errors in Russian and Serbian: the
// text is translated, paths, tags and field keys are kept.
func TestErrorsTranslated(t *testing.T) {
	ru, sr := i18n.New(i18n.Ru), i18n.New(i18n.Sr)
	d := NewData()
	err := d.Move(paths.MustParse("work/github"), paths.MustParse("x"), time.Now())
	if got := ru.Error(err); got != "work/github: не найдено" {
		t.Errorf("ru: %q", got)
	}
	if got := sr.Error(err); got != "work/github: nije pronađeno" {
		t.Errorf("sr: %q", got)
	}

	_, err = NormalizeTag("a,b")
	if got := ru.Error(err); got != `некорректный тег "a,b": содержит запятую` {
		t.Errorf("ru: %q", got)
	}

	e := Entry{Fields: []Field{{Key: "pin", Value: "1\n2"}}}
	err = e.NormalizeContent()
	if err.Error() != "invalid entry: field pin must be a single line" {
		t.Errorf("en: %q", err)
	}
	if got := sr.Error(err); got != "neispravna stavka: polje pin mora biti u jednom redu" {
		t.Errorf("sr: %q", got)
	}

	_, err = Decode([]byte(`{"format":"passh-vault-data","version":1,"revision":1}`))
	if got := ru.Error(err); got != "некорректные данные хранилища: поле vault_id отсутствует или некорректно" {
		t.Errorf("ru: %q", got)
	}
	if err.Error() != "invalid vault data: missing or bad vault_id" {
		t.Errorf("en: %q", err)
	}
}
