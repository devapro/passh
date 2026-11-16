package export

import (
	"testing"

	"github.com/devapro/passh/internal/i18n"
)

// TestErrorsTranslated: export errors in Russian and Serbian; flags and
// format names stay as they are.
func TestErrorsTranslated(t *testing.T) {
	_, err := ParseFormat("xml")
	if got := i18n.New(i18n.Ru).Error(err); got != `неизвестный формат экспорта "xml" (используйте csv, json или bitwarden-json)` {
		t.Errorf("ru: %q", got)
	}
	_, err = ConfirmPlaintext(Options{}, false, false)
	if got := i18n.New(i18n.Sr).Error(err); got != "izvoz kao otvoreni tekst treba potvrditi: bez terminala dodajte --confirm-plaintext (ili ga šifrujte opcijom --age <recipient>)" {
		t.Errorf("sr: %q", got)
	}
}
