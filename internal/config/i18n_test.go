package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/devapro/passh/internal/i18n"
)

// problemTexts returns the English text of each problem of ce.
func problemTexts(ce *Error) []string {
	out := make([]string, len(ce.Problems))
	for i, m := range ce.Problems {
		out[i] = m.String()
	}
	return out
}

// TestErrorsTranslated renders config errors in Russian and Serbian: the
// text is translated, and names, values and paths are kept.
func TestErrorsTranslated(t *testing.T) {
	isolate(t)
	ru, sr := i18n.New(i18n.Ru), i18n.New(i18n.Sr)

	_, err := Parse([]byte("vault = \"rel\"\ntypo = 1\n[backup]\nkeep = -2\n"))
	var ce *Error
	if !errors.As(err, &ce) || len(ce.Problems) != 3 {
		t.Fatalf("err = %v, want 3 problems", err)
	}
	ce.Path = "/cfg/config.toml"
	for _, c := range []struct {
		p    i18n.Printer
		want []string
	}{
		{ru, []string{"/cfg/config.toml", `"typo"`, "backup.keep: -2", `"rel"`, "неизвестный ключ", "должно быть 0 или больше"}},
		{sr, []string{"/cfg/config.toml", `"typo"`, "backup.keep: -2", `"rel"`, "nepoznat ključ", "mora biti 0 ili više"}},
	} {
		got := c.p.Error(err)
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%v: %q doesn't contain %q", c.p.Lang(), got, w)
			}
		}
		if strings.Contains(got, "unknown key") || strings.Contains(got, "must be 0 or more") {
			t.Errorf("%v: %q is not translated", c.p.Lang(), got)
		}
	}
	// English stays as it was.
	if got := i18n.New(i18n.En).Error(err); got != err.Error() || !strings.HasPrefix(got, "config /cfg/config.toml:\n  ") {
		t.Errorf("en: %q", got)
	}

	nf := &NotFoundError{Location{Path: "/x/config.toml", Source: SourceEnv}}
	if got := ru.Error(nf); !strings.Contains(got, "/x/config.toml") || !strings.Contains(got, "$PASSH_CONFIG") ||
		!strings.Contains(got, "passh init") || !strings.Contains(got, "нет конфигурационного файла") {
		t.Errorf("ru: %q", got)
	}
	if got := sr.Error(nf); !strings.Contains(got, "/x/config.toml") || !strings.Contains(got, "passh init") ||
		!strings.Contains(got, "nema konfiguracione datoteke") {
		t.Errorf("sr: %q", got)
	}
	if !errors.Is(nf, ErrNoConfig) {
		t.Error("NotFoundError doesn't match ErrNoConfig")
	}

	t.Setenv("HOME", "")
	_, err = HomeDir()
	if got := sr.Error(err); got != "promenljiva $HOME nije postavljena" {
		t.Errorf("sr: %q", got)
	}
}
