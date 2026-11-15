package editor

import (
	"context"
	"errors"
	"fmt"
	"os"

	tea "charm.land/bubbletea/v2"

	"passh/internal/model"
	"passh/internal/tty"
)

// Run shows the form for e on the terminal term (the *os.File of /dev/tty;
// it is both input and output) until the user saves or cancels, and returns
// the edited entry (see Form.Result). Cancelling returns ErrCancelled; a
// cancelled ctx stops the form and returns ctx's error.
//
// The form uses the alternate screen, so nothing it showed, a revealed
// password included, stays in the terminal's scrollback.
func Run(ctx context.Context, term *os.File, e model.Entry, opts FormOptions) (model.Entry, error) {
	if !tty.IsTerminal(term) {
		return model.Entry{}, fmt.Errorf("the entry form needs a terminal: %w", tty.ErrNoTerminal)
	}
	if err := ctx.Err(); err != nil {
		return model.Entry{}, err
	}
	f := NewForm(e, opts)
	p := tea.NewProgram(&runner{f: f}, tea.WithInput(term), tea.WithOutput(term))
	// A cancelled ctx quits the program the normal way. (tea.WithContext
	// kills it instead, which races with Bubble Tea's input reader.)
	finished := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			p.Quit()
		case <-finished:
		}
	}()
	_, err := p.Run()
	close(finished)
	if ctx.Err() != nil {
		return model.Entry{}, ctx.Err()
	}
	if err != nil {
		if errors.Is(err, tea.ErrInterrupted) {
			return model.Entry{}, ErrCancelled
		}
		return model.Entry{}, fmt.Errorf("entry form: %w", err)
	}
	if !f.Done() {
		return model.Entry{}, ErrCancelled // e.g. SIGTERM ended the program
	}
	return f.Result()
}

// runner hosts a Form as a whole Bubble Tea program.
type runner struct{ f *Form }

func (r *runner) Init() tea.Cmd { return r.f.Init() }

func (r *runner) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ws, ok := msg.(tea.WindowSizeMsg); ok {
		r.f.SetSize(ws.Width, ws.Height)
		return r, nil
	}
	_, cmd := r.f.Update(msg)
	if r.f.Done() {
		return r, tea.Quit
	}
	return r, cmd
}

func (r *runner) View() tea.View {
	v := tea.NewView(r.f.View())
	v.AltScreen = true
	return v
}
