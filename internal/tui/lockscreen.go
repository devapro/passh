package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/editor"
	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/sanitize"
)

// lockScreen asks for the passphrase, or unlocks with the agent (§6.2).
type lockScreen struct {
	pass      editor.LineInput
	msg       string
	msgErr    bool
	busy      bool
	busyText  string
	ask       string // the rollback warning while asking (§4.10)
	agentHint bool   // Enter with an empty passphrase uses the agent or key source
	damaged   bool   // the data block is damaged: msg says so, no passphrase field
}

// The hint bars of the lock screen.
var (
	hintsLockAsk     = []keyHelp{{"y", i18n.Mark("continue")}, {"n", i18n.Mark("stop")}}
	hintsLockBusy    = []keyHelp{{"ctrl+c", i18n.Mark("quit")}}
	hintsLockDamaged = []keyHelp{{"Enter", i18n.Mark("try again")}, {"q", i18n.Mark("quit")}}
	hintsLock        = []keyHelp{{"Enter", i18n.Mark("unlock")}, {"Esc", i18n.Mark("clear")}, {"ctrl+c", i18n.Mark("quit")}}
)

func newLockScreen() lockScreen {
	return lockScreen{pass: editor.NewLineInput("", true)}
}

func (l *lockScreen) setMsg(s string, isErr bool) { l.msg, l.msgErr = s, isErr }

func (m *app) lockKey(msg tea.KeyPressMsg) tea.Cmd {
	k := msg.String()
	l := &m.lk
	if l.ask != "" {
		switch k {
		case "y", "Y":
			l.ask = ""
			return m.answerAsk(true)
		case "n", "N", "esc", "enter":
			l.ask = ""
			return m.answerAsk(false)
		case "ctrl+c":
			return m.quit() // ends the job: the question gets no answer
		}
		return nil
	}
	switch k {
	case "ctrl+c", "ctrl+d":
		return m.quit()
	}
	if l.busy {
		return nil
	}
	if l.damaged {
		switch k {
		case "enter": // try again, e.g. after restoring a backup
			l.damaged = false
			l.setMsg("", false)
			switch {
			case m.d.keySource != nil:
				return m.startUnlock(m.d.keySource, "key")
			case m.d.agent != nil:
				return m.startUnlock(agentSource{m.d.agent}, "agent")
			}
		case "esc", "q":
			return m.quit()
		}
		return nil
	}
	switch k {
	case "enter":
		if l.pass.Empty() {
			switch {
			case m.d.keySource != nil && l.agentHint:
				return m.startUnlock(m.d.keySource, "key")
			case m.d.agent != nil && l.agentHint:
				return m.startUnlock(agentSource{m.d.agent}, "agent")
			}
			l.setMsg(m.d.p.T("Type the passphrase, then Enter."), false)
			return nil
		}
		pass := l.pass.Bytes()
		l.pass.Wipe()
		return m.startUnlock(&onceKey{pass: pass}, "passphrase")
	case "esc":
		if l.pass.Empty() {
			return m.quit()
		}
		l.pass.Wipe()
		return nil
	}
	l.pass.Update(msg)
	return nil
}

func (m *app) lockPaste(s string) {
	if m.lk.busy || m.lk.ask != "" {
		return
	}
	if !m.lk.pass.Paste(s) {
		m.lk.setMsg(m.d.p.T("Paste refused: the passphrase is one line."), true)
	}
}

func (m *app) viewLock() string {
	w := m.w
	l := &m.lk
	var lines []string
	add := func(s string) { lines = append(lines, s) }
	wrap := func(s string, style func(string) string) {
		for _, line := range strings.Split(ansi.Wrap(sanitize.Line(s), max(w-2, 10), ""), "\n") {
			add(" " + style(line))
		}
	}
	plain := func(s string) string { return s }

	p := m.d.p
	add(" " + styleTitle.Render("passh") + styleFaint.Render(" — "+p.T("vault locked")))
	add(" " + styleFaint.Render(sanitize.Line(config.ContractHome(m.d.vaultPath))))
	add("")
	switch {
	case l.ask != "":
		wrap(p.T("Warning: %s", l.ask), fn(styleWarn))
		add("")
		for _, line := range wrapText(p.T("Continue with this copy?"), max(w-6, 10)) {
			add(" " + line)
		}
		lines[len(lines)-1] += " " + styleKey.Render("y") + "/" + styleKey.Render("N")
	case l.busy:
		wrap(l.busyText, fn(styleFaint))
	case l.damaged:
		// The message below says what is wrong and lists the backups.
	default:
		label := " " + p.T("Passphrase") + "  "
		add(label + l.pass.View(max(w-ansi.StringWidth(label)-1, 1), true))
		if l.agentHint {
			add("")
			if m.d.keySource != nil {
				wrap(p.T("Enter with an empty passphrase unlocks with the key passh was given."), fn(styleFaint))
			} else {
				wrap(p.T("An agent is running for this vault: Enter with an empty passphrase unlocks with it."), fn(styleFaint))
			}
		}
	}
	if l.msg != "" {
		add("")
		style := plain
		if l.msgErr {
			style = fn(styleError)
		}
		for line := range strings.SplitSeq(l.msg, "\n") { // e.g. the list of backups
			wrap(line, style)
		}
	}
	add("")
	var hints []keyHelp
	switch {
	case l.ask != "":
		hints = hintsLockAsk
	case l.busy:
		hints = hintsLockBusy
	case l.damaged:
		hints = hintsLockDamaged
	default:
		hints = hintsLock
	}
	for _, line := range wrapItems(hintItems(p, hints), max(w-1, 1)) {
		add(" " + styleFaint.Render(line))
	}
	return fitLines(lines, w, m.h)
}
