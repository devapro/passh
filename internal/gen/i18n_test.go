package gen

import (
	"testing"

	"github.com/devapro/passh/internal/i18n"
)

// TestErrorsTranslated: generator errors in Russian and Serbian, the
// numbers kept.
func TestErrorsTranslated(t *testing.T) {
	_, err := Generate(Options{Length: MaxLength + 1})
	if got, want := i18n.New(i18n.Ru).Error(err), err.Error(); got == want {
		t.Errorf("ru: not translated: %q", got)
	}
	err = ValidateAlphabet("aba")
	if got := i18n.New(i18n.Sr).Error(err); got != `neispravan skup znakova: 'a' se pojavljuje više puta` {
		t.Errorf("sr: %q", got)
	}
}
