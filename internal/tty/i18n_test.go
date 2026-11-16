package tty

import (
	"errors"
	"strings"
	"syscall"
	"testing"

	"github.com/devapro/passh/internal/i18n"
)

// TestYesNoInLanguages: the hint is translated, the answers of the
// language are accepted, and y/yes/n/no keep working in every language
// (docs/translations.md, "Answers").
func TestYesNoInLanguages(t *testing.T) {
	tests := []struct {
		lang   i18n.Lang
		def    bool
		suffix string
		typed  []string
		want   bool
		err    error
	}{
		{i18n.Ru, false, " [д/Н] ", []string{"д"}, true, nil},
		{i18n.Ru, false, " [д/Н] ", []string{"ДА"}, true, nil},
		{i18n.Ru, true, " [Д/н] ", []string{" нет "}, false, nil},
		{i18n.Ru, true, " [Д/н] ", []string{"н"}, false, nil},
		{i18n.Ru, false, " [д/Н] ", []string{"yes"}, true, nil},
		{i18n.Ru, true, " [Д/н] ", []string{"n"}, false, nil},
		{i18n.Ru, true, " [Д/н] ", []string{""}, true, nil},
		{i18n.Ru, false, " [д/Н] ", []string{"da", "д"}, true, nil}, // Serbian's da is not Russian
		{i18n.Sr, false, " [d/N] ", []string{"da"}, true, nil},
		{i18n.Sr, false, " [d/N] ", []string{"D"}, true, nil},
		{i18n.Sr, true, " [D/n] ", []string{"ne"}, false, nil},
		{i18n.Sr, true, " [D/n] ", []string{"no"}, false, nil},
		{i18n.Sr, false, " [d/N] ", []string{"y"}, true, nil},
		{i18n.Sr, true, " [D/n] ", []string{"да", "нет", "x"}, false, ErrNotConfirmed},
		{i18n.En, false, " [y/N] ", []string{"да", "da", "y"}, true, nil}, // English takes only y/yes/n/no
	}
	for _, tc := range tests {
		t.Run(tc.lang.String()+"/"+strings.Join(tc.typed, ","), func(t *testing.T) {
			tt, c := newTTY(t)
			tt.SetPrinter(i18n.New(tc.lang))
			ch := run(func() (bool, error) { return tt.YesNo("Q?", tc.def) })
			for i, s := range tc.typed {
				if i > 0 {
					c.expect(strings.TrimSuffix(tt.p.T("Please answer y or n.\n"), "\n"))
				}
				c.expect("Q?" + tc.suffix)
				c.send(s + "\n")
			}
			got, err := wait(t, ch)
			if !errors.Is(err, tc.err) || got != tc.want {
				t.Errorf("YesNo = %v, %v; want %v, %v", got, err, tc.want, tc.err)
			}
		})
	}
}

func TestPromptsInRussian(t *testing.T) {
	ru := i18n.New(i18n.Ru)

	// The confirmation phrase stays English; the sentence around it doesn't.
	tt, c := newTTY(t)
	tt.SetPrinter(ru)
	ch := run(func() (struct{}, error) { return struct{}{}, tt.Confirm(PhrasePrintRecoveryKey) })
	c.expect("Для подтверждения введите PRINT RECOVERY KEY: ")
	c.send("ПЕЧАТЬ\n")
	_, err := wait(t, ch)
	if !errors.Is(err, ErrNotConfirmed) {
		t.Fatalf("Confirm = %v", err)
	}
	if got := ru.Error(err); got != "не подтверждено: вы не ввели PRINT RECOVERY KEY" {
		t.Errorf("error %q", got)
	}
	if err.Error() != "not confirmed: you didn't type PRINT RECOVERY KEY" {
		t.Errorf("English error %q", err)
	}

	// A new passphrase: prompts and retries.
	tt, c = newTTY(t)
	tt.SetPrinter(ru)
	pch := run(func() ([]byte, error) { return tt.NewPassphrase(nil) })
	c.expect("Новая парольная фраза: ")
	c.send("\r")
	c.expect("Парольная фраза не может быть пустой.")
	c.expect("Новая парольная фраза: ")
	c.send("один два\r")
	c.expect("Повторите парольную фразу: ")
	c.send("один три\r")
	c.expect("Парольные фразы не совпадают. Попробуйте ещё раз.")
	c.expect("Новая парольная фраза: ")
	c.send("один два\r")
	c.expect("Повторите парольную фразу: ")
	c.send("один два\r")
	got, err := wait(t, pch)
	if err != nil || string(got) != "один два" {
		t.Fatalf("NewPassphrase = %q, %v", got, err)
	}
}

func TestErrorsInLanguages(t *testing.T) {
	sig := &SignalError{Signal: syscall.SIGTERM}
	for _, tc := range []struct {
		err    error
		ru, sr string
	}{
		{sig, "прервано (terminated)", "prekinuto (terminated)"},
		{ErrMismatch, "парольные фразы не совпадают", "pristupne fraze se ne poklapaju"},
		{i18n.Errorf("%w: /dev/tty is not a terminal", ErrNoTerminal), "нет терминала: /dev/tty — не терминал", "nema terminala: /dev/tty nije terminal"},
	} {
		if got := i18n.New(i18n.Ru).Error(tc.err); got != tc.ru {
			t.Errorf("ru %q, want %q", got, tc.ru)
		}
		if got := i18n.New(i18n.Sr).Error(tc.err); got != tc.sr {
			t.Errorf("sr %q, want %q", got, tc.sr)
		}
	}
	if sig.Error() != "interrupted (terminated)" || !errors.Is(sig, ErrInterrupted) {
		t.Errorf("SignalError %q", sig)
	}
}
