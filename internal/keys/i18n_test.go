package keys

import (
	"strings"
	"testing"

	"github.com/devapro/passh/internal/i18n"
)

// TestErrorsTranslated renders the errors of the keys package in Russian
// and Serbian, with the numbers in them kept.
func TestErrorsTranslated(t *testing.T) {
	ru, sr := i18n.New(i18n.Ru), i18n.New(i18n.Sr)
	if got := ru.Error(ErrWrongPassphrase); got != "неверная парольная фраза или повреждён блок ключа" {
		t.Errorf("ru: %q", got)
	}
	if got := sr.Error(ErrKeyMismatch); got != "ključ ne otvara blok podataka: podaci su oštećeni; vratite rezervnu kopiju" {
		t.Errorf("sr: %q", got)
	}
	if got := ru.Error(workFactorError{logN: 22}); got != "блок ключа требует сложность scrypt 2^22, а passh использует 2^18: файл повреждён или создан не passh" {
		t.Errorf("ru: %q", got)
	}

	_, err := ParseRecoveryKey("AGE-SECRET-KEY-1 QPZR")
	if got := ru.Error(err); got != "недействительный ключ восстановления: после AGE-SECRET-KEY-1 должно быть 58 символов, а введено 4; какой-то символ пропущен или лишний" {
		t.Errorf("ru: %q", got)
	}
	if got := sr.Error(err); got != "neispravan ključ za oporavak: posle AGE-SECRET-KEY-1 treba da bude 58 znakova, a uneto je 4; neki znak nedostaje ili je višak" {
		t.Errorf("sr: %q", got)
	}
	_, err = ParseRecoveryKey("AGE-SECRET-KEY-1 QPBR")
	if got := sr.Error(err); !strings.Contains(got, "grupa 1, znak 3:") {
		t.Errorf("sr: %q", got)
	}
}

// TestStrengthTranslated: the weak passphrase warning and its reason in
// each language; English as before.
func TestStrengthTranslated(t *testing.T) {
	s := CheckStrength([]byte("password"))
	if got := s.Message(); got != "weak passphrase: this is a top-10 common password; use 6 or more random words" {
		t.Errorf("en: %q", got)
	}
	if got := s.Localize(i18n.New(i18n.Ru)); got != "слабая парольная фраза: это один из 10 самых распространённых паролей; используйте 6 или больше случайных слов" {
		t.Errorf("ru: %q", got)
	}
	if got := (Strength{Score: 1}).Localize(i18n.New(i18n.Sr)); got != "slaba pristupna fraza; koristite 6 ili više nasumičnih reči" {
		t.Errorf("sr: %q", got)
	}
	if got := (Strength{Score: 4}).Localize(i18n.New(i18n.Ru)); got != "" {
		t.Errorf("strong: %q", got)
	}
}
