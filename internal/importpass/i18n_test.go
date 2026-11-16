package importpass

import (
	"testing"

	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/paths"
)

// TestReportTranslated: the reasons and details of skipped files in
// Russian and Serbian, with file names kept; Detail stays English.
func TestReportTranslated(t *testing.T) {
	ru, sr := i18n.New(i18n.Ru), i18n.New(i18n.Sr)
	if got := InvalidPath.Localize(ru); got != "недопустимый путь" {
		t.Errorf("ru: %q", got)
	}
	if got := Conflict.String(); got != "already in the vault" {
		t.Errorf("en: %q", got)
	}

	s := newSkip("b.gpg", DuplicatePath, i18n.Msg("same path as %s", "a.gpg"))
	if s.Detail != "same path as a.gpg" {
		t.Errorf("Detail %q", s.Detail)
	}
	if got := s.LocalizeDetail(sr); got != "ista putanja kao a.gpg" {
		t.Errorf("sr: %q", got)
	}
	s = newSkip("-x.gpg", InvalidPath, i18n.Msg("%v", paths.ErrDashSegment))
	if got := s.LocalizeDetail(ru); got != "сегмент начинается с -" || s.Detail != "a segment starts with -" {
		t.Errorf("ru: %q, Detail %q", got, s.Detail)
	}
	if got := (Skip{Detail: "raw"}).LocalizeDetail(ru); got != "raw" {
		t.Errorf("no message: %q", got)
	}
	if got := (gpgStatus{noSecKey: []string{"A", "B"}}).failure(nil).Localize(ru); got != "нет секретного ключа для ключа с ID A, B" {
		t.Errorf("ru: %q", got)
	}
	if got := sr.Error(ErrNoGPG); got != "gpg nije pronađen: import pass zahteva GnuPG (gpg) za dešifrovanje skladišta pass-a" {
		t.Errorf("sr: %q", got)
	}
}
