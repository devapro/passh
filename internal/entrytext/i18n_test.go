package entrytext

import (
	"testing"

	"github.com/devapro/passh/internal/i18n"
)

// TestErrorsTranslated renders a syntax error in Russian and Serbian: the
// line number and the field name are kept.
func TestErrorsTranslated(t *testing.T) {
	_, err := Parse("pw\nusername: a\nusername: b\n")
	for lang, want := range map[i18n.Lang]string{
		i18n.En: "line 3: username appears twice",
		i18n.Ru: "строка 3: username встречается дважды",
		i18n.Sr: "red 3: username se pojavljuje dvaput",
	} {
		if got := i18n.New(lang).Error(err); got != want {
			t.Errorf("%v: %q, want %q", lang, got, want)
		}
	}
}
