package exec

import (
	"testing"

	"github.com/devapro/passh/internal/i18n"
)

// TestErrorsTranslated: a command line error in Russian and Serbian, the
// command line kept as typed.
func TestErrorsTranslated(t *testing.T) {
	_, err := SplitWords(`vim 'x`)
	if got := i18n.New(i18n.Ru).Error(err); got != `незакрытая одинарная кавычка в "vim 'x"` {
		t.Errorf("ru: %q", got)
	}
	if got := i18n.New(i18n.Sr).Error(err); got != `nezatvoren jednostruki navodnik u "vim 'x"` {
		t.Errorf("sr: %q", got)
	}
}
