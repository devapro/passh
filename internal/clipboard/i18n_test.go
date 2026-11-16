package clipboard

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/i18n"
)

func TestErrorsInLanguages(t *testing.T) {
	_, err := New(config.Clipboard{}, nil)
	err = WithHint(err, "work/git hub", "")
	if !errors.Is(err, ErrNoClipboard) {
		t.Fatalf("New = %v", err)
	}
	const hint = "passh show 'work/git hub' --field password | pbcopy"
	for l, want := range map[i18n.Lang]string{
		i18n.En: "no clipboard: clipboard.osc52 is off and clipboard.command is empty; copy with: " + hint,
		i18n.Ru: "нет буфера обмена: clipboard.osc52 выключен, а clipboard.command пуст; скопируйте так: " + hint,
		i18n.Sr: "nema ostave: clipboard.osc52 je isključen, a clipboard.command je prazan; kopirajte pomoću: " + hint,
	} {
		if got := i18n.New(l).Error(err); got != want {
			t.Errorf("%s: %q, want %q", l, got, want)
		}
	}
	if err.Error() != "no clipboard: clipboard.osc52 is off and clipboard.command is empty; copy with: "+hint {
		t.Errorf("English Error %q", err)
	}
	// The reason, shown on its own as the TUI does.
	var nc *NoClipboardError
	if !errors.As(err, &nc) || i18n.New(i18n.Ru).T(nc.Reason) != "clipboard.osc52 выключен, а clipboard.command пуст" { // i18n:dynamic
		t.Errorf("reason %q", nc.Reason)
	}

	// An interrupted wait: the clipboard was cleared, said in the language.
	c, _ := osc(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = c.CopyAndWait(ctx, "v", time.Hour)
	if !errors.Is(err, ErrInterrupted) || err.Error() != "interrupted (context canceled); the clipboard was cleared" {
		t.Fatalf("CopyAndWait = %v", err)
	}
	if got := i18n.New(i18n.Ru).Error(err); got != "прервано (context canceled); буфер обмена очищен" {
		t.Errorf("ru %q", got)
	}
	if got := i18n.New(i18n.Sr).Error(&ClearError{Err: i18n.Errorf("clipboard command: %w", ErrNoClipboard)}); got != "komanda za ostavu: nema ostave" {
		t.Errorf("sr ClearError %q", got)
	}
}

func TestDescriptionsInLanguages(t *testing.T) {
	c, _ := osc(t)
	ru, sr := i18n.New(i18n.Ru), i18n.New(i18n.Sr)
	if got := ru.T("[%s]", c); got != "[OSC 52 через терминал]" { // the Clipboard as an argument translates itself
		t.Errorf("ru %q", got)
	}
	if c.String() != "OSC 52 through the terminal" || c.Localize(sr) != "OSC 52 preko terminala" {
		t.Errorf("descriptions %q %q", c.String(), c.Localize(sr))
	}
	cmd := &Clipboard{method: MethodCommand, command: []string{"wl-copy", "-n"}}
	if cmd.String() != `command "wl-copy -n"` || cmd.Localize(ru) != `команда "wl-copy -n"` {
		t.Errorf("command %q %q", cmd.String(), cmd.Localize(ru))
	}
	if MethodCommand.Localize(sr) != "komanda za ostavu" || MethodOSC52.Localize(ru) != "OSC 52" || Method(0).String() != "none" || Method(0).Localize(ru) != "нет" {
		t.Error("method names")
	}

	env := map[string]string{"TMUX": "x", "STY": "x", "TERM_PROGRAM": "Apple_Terminal"}
	var got []string
	for _, n := range EnvironmentNotes(func(k string) string { return env[k] }) {
		got = append(got, ru.T(n)) // i18n:dynamic: the notes are marked keys
	}
	if len(got) != 3 || !strings.HasPrefix(got[0], "внутри tmux: для OSC 52 нужно `set -g set-clipboard on`") ||
		!strings.HasPrefix(got[1], "внутри GNU screen") || got[2] != `в Terminal.app нет OSC 52: задайте clipboard.command = ["pbcopy"]` {
		t.Errorf("notes %q", got)
	}
}
