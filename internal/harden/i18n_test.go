package harden

import (
	"syscall"
	"testing"

	"github.com/devapro/passh/internal/i18n"
)

func TestErrorsInLanguages(t *testing.T) {
	err := i18n.Errorf("disabling core dumps: %w", syscall.EPERM)
	if err.Error() != "disabling core dumps: operation not permitted" {
		t.Errorf("English %q", err)
	}
	// The operating system's text stays as it is (§3.3).
	if got := i18n.New(i18n.Ru).Error(err); got != "отключение дампов памяти: operation not permitted" {
		t.Errorf("ru %q", got)
	}
	if got := i18n.New(i18n.Sr).Error(err); got != "isključivanje core dump datoteka: operation not permitted" {
		t.Errorf("sr %q", got)
	}
}
