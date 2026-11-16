package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/devapro/passh/internal/gen"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/tty"
)

// promptAttempts is how often an invalid answer is asked again.
const promptAttempts = 3

func (a *app) cmdAdd() *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:   "add <path>",
		Short: "Add an entry interactively: password (or generate), username, url, tags, notes",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			p, err := paths.Parse(args[0])
			if err != nil {
				return err
			}
			t, err := a.needTTY("passh add")
			if err != nil {
				return err
			}
			v, err := a.unlock(ctx)
			if err != nil {
				return err
			}
			defer v.Close()
			if _, exists := v.Get(p); exists && !force {
				return fmt.Errorf("%s already exists: use --force to replace it", p)
			}
			e, generated, err := askEntry(ctx, t)
			if err != nil {
				return err
			}
			e.Path = p
			if _, err := v.AddContext(ctx, e, force); err != nil {
				return err
			}
			if generated {
				a.statusf("Generated a %d-character password.", gen.DefaultLength)
			}
			a.statusf("Saved %s.", line(p.String()))
			return nil
		},
	}
	c.Flags().BoolVarP(&force, "force", "f", false, "replace an existing entry")
	return c
}

// askEntry asks for the values of a new entry on the terminal. An empty
// password generates one (gen defaults). ctx ends the prompts.
func askEntry(ctx context.Context, t *tty.TTY) (e model.Entry, generated bool, err error) {
	pw, err := askPassword(ctx, t)
	if err != nil {
		return e, false, err
	}
	if pw == "" {
		if pw, err = gen.Generate(gen.Options{}); err != nil {
			return e, false, err
		}
		generated = true
	}
	e.Password = pw
	if e.Username, err = t.ReadLineContext(ctx, "Username: "); err != nil && !errors.Is(err, io.EOF) {
		return e, false, err
	}
	if e.URL, err = t.ReadLineContext(ctx, "URL: "); err != nil && !errors.Is(err, io.EOF) {
		return e, false, err
	}
	for i := 0; ; i++ {
		s, err := t.ReadLineContext(ctx, "Tags (comma-separated): ")
		if err != nil && !errors.Is(err, io.EOF) {
			return e, false, err
		}
		tags, err := model.ParseTagList(s)
		if err == nil {
			e.Tags = tags
			break
		}
		if i == promptAttempts-1 {
			return e, false, err
		}
		termf(t, "%v\n", err)
	}
	termf(t, "Notes (end with an empty line):\n")
	var notes []string
	for {
		l, err := t.ReadLineContext(ctx, "")
		if errors.Is(err, io.EOF) || (err == nil && l == "") {
			break
		}
		if err != nil {
			return e, false, err
		}
		notes = append(notes, l)
	}
	e.Notes = strings.Join(notes, "\n")
	return e, generated, nil
}

// askPassword reads the password twice with echo off. An empty first
// answer means "generate one". Ctrl-C and signals return the prompt's error
// unchanged (tty.ErrInterrupted, *tty.SignalError).
func askPassword(ctx context.Context, t *tty.TTY) (string, error) {
	// Both prompts in one stay in raw mode: a pasted repetition is never
	// echoed between them.
	p, err := t.ReadPairContext(ctx, tty.Pair{
		First:    "Password (empty to generate): ",
		Repeat:   "Repeat password: ",
		Mismatch: "Passwords don't match. Try again.",
		Attempts: promptAttempts,
	})
	if errors.Is(err, tty.ErrMismatch) {
		return "", errors.New("passwords don't match")
	}
	if err != nil {
		return "", err
	}
	s := string(p) // the entry model holds strings (SEC-1)
	tty.Wipe(p)
	return s, nil
}

func (a *app) cmdGenerate() *cobra.Command {
	var (
		symbols bool
		force   bool
	)
	c := &cobra.Command{
		Use:   "generate <path> [len]",
		Short: "Generate and store a password",
		Long: "Generate a random password (default 24 letters and digits) and store it.\n\n" +
			"A new path makes a new entry. For an existing entry, --force replaces its\n" +
			"password and keeps its other values (username, url, tags, fields, notes).\n" +
			"The password is not printed; show it with `passh show <path> --field password`.",
		Args: rangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := paths.Parse(args[0])
			if err != nil {
				return err
			}
			opts := gen.Options{Symbols: symbols}
			if len(args) == 2 {
				n, err := strconv.Atoi(args[1])
				if err != nil || n < 1 || n > gen.MaxLength {
					return usagef("length %q: give a number from 1 to %d", args[1], gen.MaxLength)
				}
				opts.Length = n
			}
			ctx := cmd.Context()
			v, err := a.unlock(ctx)
			if err != nil {
				return err
			}
			defer v.Close()
			e, exists := v.Get(p)
			if exists && !force {
				return fmt.Errorf("%s already exists: use --force to replace its password (its other values are kept)", p)
			}
			pw, err := gen.Generate(opts)
			if err != nil {
				return err
			}
			if exists {
				e.Password = pw
				if _, err := v.UpdateContext(ctx, e); err != nil {
					return err
				}
			} else if _, err := v.AddContext(ctx, model.Entry{Path: p, Password: pw}, false); err != nil {
				return err
			}
			length := opts.Length
			if length == 0 {
				length = gen.DefaultLength
			}
			bits, _ := gen.Bits(opts)
			kind := "letters and digits"
			if symbols {
				kind = "letters, digits and symbols"
			}
			verb := "Stored"
			if exists {
				verb = "Replaced the password of"
			}
			a.statusf("%s %s: a new %d-character password (%s, %d bits).\nShow it with: passh show %s --field password",
				verb, line(p.String()), length, kind, int(math.Floor(bits)), shellQuote(p.String()))
			return nil
		},
	}
	c.Flags().BoolVar(&symbols, "symbols", false, "also use punctuation characters")
	c.Flags().BoolVarP(&force, "force", "f", false, "replace the password of an existing entry")
	return c
}

// shellQuote quotes s for a command line the user may copy: as is when it
// is plain, else in single quotes. The result is escaped for the terminal.
func shellQuote(s string) string {
	plain := s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-+@:,=", r))
	}) < 0
	if plain {
		return line(s)
	}
	return line("'" + strings.ReplaceAll(s, "'", `'\''`) + "'")
}

func (a *app) cmdMv() *cobra.Command {
	return &cobra.Command{
		Use:   "mv <src> <dst>",
		Short: "Move or rename an entry or a folder",
		Long: "Move or rename an entry. A destination ending in / moves the entry into that\n" +
			"folder, keeping its name. If <src> is a folder, every entry in it moves, in\n" +
			"one save; nothing moves if any destination is taken.",
		Args: exactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			src, err := paths.Parse(args[0])
			if err != nil {
				return err
			}
			into := strings.HasSuffix(args[1], "/")
			dstText := strings.TrimSuffix(args[1], "/")
			if into {
				dstText += "/" + src.Name()
			}
			dst, err := paths.Parse(dstText)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			v, err := a.unlock(ctx)
			if err != nil {
				return err
			}
			defer v.Close()
			if _, ok := v.Get(src); ok {
				if err := v.MoveContext(ctx, src, dst); err != nil {
					return err
				}
				a.statusf("Moved %s to %s.", line(src.String()), line(dst.String()))
				return nil
			}
			list := v.Snapshot().ListFolder(src)
			if len(list) == 0 {
				return fmt.Errorf("%s: %w", src, model.ErrNotFound)
			}
			if dst.HasPrefix(src) {
				return fmt.Errorf("can't move the folder %s into itself", src)
			}
			err = v.ApplyContext(ctx, func(d *model.Data, now time.Time) (bool, error) {
				for _, e := range list {
					to, err := paths.Parse(dst.String() + strings.TrimPrefix(e.Path.String(), src.String()))
					if err != nil {
						return false, err
					}
					if err := d.Move(e.Path, to, now); err != nil {
						return false, err
					}
				}
				return true, nil
			})
			if err != nil {
				return err
			}
			a.statusf("Moved the folder %s/ to %s/ (%s).", line(src.String()), line(dst.String()), plural(len(list), "entry", "entries"))
			return nil
		},
	}
}

func (a *app) cmdRm() *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:   "rm <path>",
		Short: "Delete an entry (asks for confirmation)",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := paths.Parse(args[0])
			if err != nil {
				return err
			}
			var t *tty.TTY
			if !force {
				if t, err = a.tty(); err != nil {
					return errors.New("passh rm asks for confirmation on a terminal: run it in one, or add --force")
				}
			}
			ctx := cmd.Context()
			v, err := a.unlock(ctx)
			if err != nil {
				return err
			}
			defer v.Close()
			if _, ok := v.Get(p); !ok {
				return notFound(v, p)
			}
			if !force {
				ok, err := t.YesNoContext(ctx, fmt.Sprintf("Delete %s?", line(p.String())), false)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("not deleted")
				}
			}
			if err := v.RemoveContext(ctx, p); err != nil {
				return err
			}
			a.statusf("Deleted %s.", line(p.String()))
			return nil
		},
	}
	c.Flags().BoolVarP(&force, "force", "f", false, "don't ask for confirmation")
	return c
}

func (a *app) cmdTag() *cobra.Command {
	var add, remove []string
	c := &cobra.Command{
		Use:   "tag <path> --add a --remove b",
		Short: "Add and remove tags of an entry",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(add) == 0 && len(remove) == 0 {
				return usagef("give --add and/or --remove")
			}
			p, err := paths.Parse(args[0])
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			v, err := a.unlock(ctx)
			if err != nil {
				return err
			}
			defer v.Close()
			if _, ok := v.Get(p); !ok {
				return notFound(v, p)
			}
			e, changed, err := v.EditTagsContext(ctx, p, add, remove)
			if err != nil {
				return err
			}
			tags := "no tags"
			if len(e.Tags) > 0 {
				tags = "tags " + line(strings.Join(e.Tags, ", "))
			}
			if !changed {
				tags += " (unchanged)"
			}
			a.statusf("%s: %s", line(p.String()), tags)
			return nil
		},
	}
	c.Flags().StringSliceVar(&add, "add", nil, "tag to add (repeat, or separate with commas)")
	c.Flags().StringSliceVar(&remove, "remove", nil, "tag to remove (repeat, or separate with commas)")
	return c
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
