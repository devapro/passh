package session

import (
	"testing"

	"github.com/devapro/passh/internal/i18n"
)

func TestReasonInLanguages(t *testing.T) {
	ru, sr := i18n.New(i18n.Ru), i18n.New(i18n.Sr)
	for _, tc := range []struct {
		r          Reason
		en, ru, sr string
	}{
		{ReasonKey, "locked", "заблокировано", "zaključano"},
		{ReasonExit, "locked on exit", "заблокировано при выходе", "zaključano pri izlasku"},
		{ReasonIdle, "locked after inactivity", "заблокировано из-за бездействия", "zaključano zbog neaktivnosti"},
		{ReasonSignal, "locked by a signal", "заблокировано сигналом", "zaključano signalom"},
		{Reason(0), "locked", "заблокировано", "zaključano"},
	} {
		if tc.r.String() != tc.en || tc.r.Localize(ru) != tc.ru || tc.r.Localize(sr) != tc.sr {
			t.Errorf("%d: %q %q %q", tc.r, tc.r.String(), tc.r.Localize(ru), tc.r.Localize(sr))
		}
		// As an argument, a Reason translates itself.
		if got := ru.T("[%s]", tc.r); got != "["+tc.ru+"]" {
			t.Errorf("argument: %q", got)
		}
	}
}
