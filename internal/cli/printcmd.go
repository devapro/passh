package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/export"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/print"
	"github.com/devapro/passh/internal/printweb"
	"github.com/devapro/passh/internal/tty"
)

// output is where a plaintext document goes (§7.1, §7.2): a new file (-o)
// or stdout, never a terminal.
type output struct {
	path string // "" means stdout
}

// prepareOutput checks the destination before anything is unlocked: -o
// must not exist; without -o, stdout must not be a terminal. what names
// the data in the refusal ("export data", "the sheet").
func (a *app) prepareOutput(o, what string) (output, error) {
	if o == "" {
		if tty.IsTerminal(a.stdout) {
			return output{}, fmt.Errorf("refusing to write %s to a terminal: add -o file or redirect stdout", what)
		}
		return output{}, nil
	}
	p, err := config.ExpandPath(o)
	if err != nil {
		return output{}, err
	}
	if _, err := os.Lstat(p); err == nil {
		return output{}, fmt.Errorf("%s already exists; passh doesn't overwrite files", config.ContractHome(p))
	}
	return output{path: p}, nil
}

// write writes data to the destination and returns its name for messages.
// A new file gets mode 0600; if it isn't on tmpfs and holds plaintext,
// passh warns (§7.1).
func (a *app) write(out output, data []byte, plaintext bool) (string, error) {
	if out.path == "" {
		_, err := a.stdout.Write(data)
		return "stdout", err
	}
	if err := writeNewFile(out.path, data); err != nil {
		return "", err
	}
	dest := displayPath(out.path)
	if plaintext && !onTmpfs(filepath.Dir(out.path)) {
		a.warnf("%s isn't on tmpfs: the plaintext is on persistent disk. Delete it when you're done", dest)
	}
	return dest, nil
}

// docFormat is the format of a printed sheet.
type docFormat string

const (
	formatPDF docFormat = "pdf"
	formatTXT docFormat = "txt"
)

func parseDocFormat(s string) (docFormat, error) {
	switch f := docFormat(strings.ToLower(s)); f {
	case formatPDF, formatTXT:
		return f, nil
	}
	return "", usagef("--format %q: use pdf or txt", s)
}

// render lays out doc as PDF or text.
func render(doc print.Document, f docFormat, paper print.PaperSize) ([]byte, error) {
	var buf bytes.Buffer
	var err error
	if f == formatTXT {
		err = print.WriteTXT(&buf, doc)
	} else {
		err = print.WritePDF(&buf, doc, paper)
	}
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// printFlags are the output flags shared by print and recovery-key print.
type printFlags struct {
	format string
	paper  string
	out    string
	web    bool
}

func (pf *printFlags) register(c *cobra.Command) {
	c.Flags().StringVar(&pf.format, "format", "pdf", "pdf or txt")
	c.Flags().StringVar(&pf.paper, "paper", "a4", "PDF paper size: a4 or letter")
	c.Flags().StringVarP(&pf.out, "output", "o", "", "write to this new file (mode 0600) instead of stdout")
	c.Flags().BoolVar(&pf.web, "web", false, "show the sheet on the one-shot print page (§7.4) instead")
}

// parse checks the flags: the format and paper size, and that --web isn't
// combined with file options.
func (pf *printFlags) parse(c *cobra.Command) (docFormat, print.PaperSize, error) {
	if pf.web {
		for _, f := range []string{"format", "paper", "output"} {
			if c.Flags().Changed(f) {
				return "", 0, usagef("--%s can't be used with --web", f)
			}
		}
	}
	f, err := parseDocFormat(pf.format)
	if err != nil {
		return "", 0, err
	}
	paper, err := print.ParsePaperSize(pf.paper)
	if err != nil {
		return "", 0, usageErr(err)
	}
	return f, paper, nil
}

func (a *app) cmdPrint() *cobra.Command {
	var (
		pf      printFlags
		folder  string
		tags    []string
		fields  string
		confirm bool
	)
	c := &cobra.Command{
		Use:   "print [--tag t] [--folder f] [--fields password,username,url] [--format pdf|txt] [-o file]",
		Short: "Print a password sheet (PDF or text), or show it on the print page (--web)",
		Long: "Lay out the chosen entries as a password sheet, grouped by folder, with the\n" +
			"chosen fields (default password,username,url; also tags, notes, fields, or a\n" +
			"custom field's key). Ambiguous characters are marked.\n\n" +
			"The sheet is plaintext: it is never written to a terminal, and it needs\n" +
			"confirmation as a plaintext export does (type EXPORT PLAINTEXT, or\n" +
			"--confirm-plaintext without a terminal). Print it, then delete the file.\n\n" +
			"--web shows it on the one-shot print page instead (print_web.enabled; needs a\n" +
			"terminal and typing PRINT).",
		Args: noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			f, paper, err := pf.parse(cmd)
			if err != nil {
				return err
			}
			if pf.web && confirm {
				return usagef("--confirm-plaintext can't be used with --web: the print page needs a terminal")
			}
			opts := print.Options{}
			if folder != "" {
				if opts.Folder, err = paths.ParseFolder(folder); err != nil {
					return err
				}
			}
			for _, t := range tags {
				n, err := model.NormalizeTag(t)
				if err != nil {
					return err
				}
				opts.Tags = append(opts.Tags, n)
			}
			if opts.Fields, err = print.ParseFields(fields); err != nil {
				return usageErr(err)
			}
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}

			var out output
			if pf.web {
				t, err := a.webPrelude(cfg, tty.PhrasePrint)
				if err != nil {
					return err
				}
				sheet, err := a.passwordSheet(ctx, opts)
				if err != nil {
					return err
				}
				return a.servePrintPage(ctx, t, cfg, sheet)
			}
			if out, err = a.prepareOutput(pf.out, "the sheet"); err != nil {
				return err
			}
			// The same confirmation as a plaintext export (§7.2, §7.1).
			t, terr := a.tty()
			prompt, err := export.ConfirmPlaintext(export.Options{}, terr == nil, confirm)
			if err != nil {
				return errors.New("printing needs confirmation: without a terminal, add --confirm-plaintext")
			}
			if prompt {
				t.Printf("The sheet holds your passwords unencrypted.\n")
				if err := t.Confirm(tty.PhraseExportPlaintext); err != nil {
					return err
				}
			}
			sheet, err := a.passwordSheet(ctx, opts)
			if err != nil {
				return err
			}
			data, err := render(sheet, f, paper)
			if err != nil {
				return err
			}
			defer clear(data)
			dest, err := a.write(out, data, true)
			if err != nil {
				return err
			}
			a.notef("printed %s (%s) to %s; print it, then delete the file", plural(sheet.Len(), "entry", "entries"), f, dest)
			return nil
		},
	}
	pf.register(c)
	c.Flags().StringSliceVar(&tags, "tag", nil, "only entries with this tag (repeat for several: all must match)")
	c.Flags().StringVar(&folder, "folder", "", "only entries in this folder")
	c.Flags().StringVar(&fields, "fields", "", "fields to print, comma-separated (default password,username,url)")
	c.Flags().BoolVar(&confirm, "confirm-plaintext", false, "confirm a plaintext sheet when there is no terminal")
	return c
}

// passwordSheet unlocks the vault and lays out the sheet; the vault is
// closed again before the sheet is written or served.
func (a *app) passwordSheet(ctx context.Context, opts print.Options) (*print.Sheet, error) {
	v, err := a.unlock(ctx)
	if err != nil {
		return nil, err
	}
	defer v.Close()
	return print.NewSheet(v.Entries(), opts)
}

// webPrelude checks what the print page needs before anything is
// unlocked: print_web.enabled, a terminal, and the confirmation phrase.
func (a *app) webPrelude(cfg *config.Config, phrase string) (*tty.TTY, error) {
	if !cfg.PrintWeb.Enabled {
		return nil, printweb.ErrDisabled
	}
	t, err := a.needTTY("the print page")
	if err != nil {
		return nil, err
	}
	if err := t.Confirm(phrase); err != nil {
		return nil, err
	}
	return t, nil
}

func (a *app) cmdRecoveryKey() *cobra.Command {
	c := &cobra.Command{
		Use:   "recovery-key",
		Short: "The paper recovery key",
		Args:  noArgs(),
		RunE: func(*cobra.Command, []string) error {
			return usagef("say what to do, e.g. `passh recovery-key print`")
		},
	}
	var pf printFlags
	p := &cobra.Command{
		Use:   "print [--format pdf|txt] [-o file] [--web]",
		Short: "Print the paper recovery key (needs a terminal and typing PRINT RECOVERY KEY)",
		Long: "Print the paper recovery key: the vault key in groups of four characters and\n" +
			"as a QR code, the vault_id, the print date, a warning and the manual recovery\n" +
			"steps. Whoever has the sheet and a copy of the vault can read everything: keep\n" +
			"it offline, and print a new one after `passh rekey`.\n\n" +
			"It needs a terminal and typing PRINT RECOVERY KEY. The sheet is never written\n" +
			"to a terminal: use -o file (mode 0600) or redirect stdout, print it, then delete\n" +
			"the file. --web shows it on the one-shot print page instead.",
		Args: noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			f, paper, err := pf.parse(cmd)
			if err != nil {
				return err
			}
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			var out output
			var t *tty.TTY
			if pf.web {
				if t, err = a.webPrelude(cfg, tty.PhrasePrintRecoveryKey); err != nil {
					return err
				}
			} else {
				if out, err = a.prepareOutput(pf.out, "the recovery key"); err != nil {
					return err
				}
				if t, err = a.needTTY("passh recovery-key print"); err != nil {
					return err
				}
				if err := t.Confirm(tty.PhrasePrintRecoveryKey); err != nil {
					return err
				}
			}
			sheet, err := a.recoverySheet(ctx)
			if err != nil {
				return err
			}
			if pf.web {
				return a.servePrintPage(ctx, t, cfg, sheet)
			}
			dest, err := a.writeRecoverySheet(out, sheet, f, paper)
			if err != nil {
				return err
			}
			a.printf("Wrote the paper recovery key to %s.\n", dest)
			return nil
		},
	}
	pf.register(p)
	c.AddCommand(p)
	return c
}

// recoverySheet unlocks the vault (the usual key chain) and makes the
// sheet for its key.
func (a *app) recoverySheet(ctx context.Context) (*print.RecoverySheet, error) {
	v, err := a.unlock(ctx)
	if err != nil {
		return nil, err
	}
	defer v.Close()
	return print.NewRecoverySheet(v.Key(), v.Info().VaultID, time.Now())
}

// writeRecoverySheet renders and writes the sheet.
func (a *app) writeRecoverySheet(out output, sheet *print.RecoverySheet, f docFormat, paper print.PaperSize) (string, error) {
	data, err := render(sheet, f, paper)
	if err != nil {
		return "", err
	}
	defer clear(data)
	dest, err := a.write(out, data, true)
	if err != nil {
		return "", err
	}
	if out.path != "" {
		a.notef("print it, keep the sheet offline, then delete the file: rm %s", shellQuote(out.path))
	}
	return dest, nil
}

// offerRecoverySheet is `passh init`'s offer to print the recovery key
// (§5.4): a sheet written to a file the user picks (PDF, or text for a
// .txt name), after typing PRINT RECOVERY KEY.
func (a *app) offerRecoverySheet(t *tty.TTY, key *age.X25519Identity, vaultID string) error {
	ok, err := t.YesNo("Print the recovery key now?", true)
	if err != nil || !ok {
		a.printf("%s\n", recoverySheetHint)
		return nil
	}
	def := defaultSheetPath()
	var out output
	for i := 0; ; i++ {
		ans, err := t.ReadLine(fmt.Sprintf("Write the sheet (PDF; .txt for text) to [%s]: ", displayPath(def)))
		if err != nil {
			return err
		}
		if strings.TrimSpace(ans) == "" {
			ans = def
		}
		if out, err = a.prepareOutput(ans, "the recovery key"); err == nil && out.path != "" {
			break
		}
		if i == promptAttempts-1 {
			return err
		}
		t.Printf("%v\n", err)
	}
	if err := t.Confirm(tty.PhrasePrintRecoveryKey); err != nil {
		return err
	}
	sheet, err := print.NewRecoverySheet(key, vaultID, time.Now())
	if err != nil {
		return err
	}
	f := formatPDF
	if strings.EqualFold(filepath.Ext(out.path), ".txt") {
		f = formatTXT
	}
	dest, err := a.writeRecoverySheet(out, sheet, f, print.A4)
	if err != nil {
		return err
	}
	a.printf("Wrote the paper recovery key to %s.\n", dest)
	return nil
}

// defaultSheetPath proposes where init writes the recovery sheet: on
// tmpfs if there is one (/dev/shm), else in the home folder.
func defaultSheetPath() string {
	if onTmpfs("/dev/shm") {
		return "/dev/shm/passh-recovery.pdf"
	}
	if home, err := config.HomeDir(); err == nil {
		return filepath.Join(home, "passh-recovery.pdf")
	}
	return "passh-recovery.pdf"
}

// servePrintPage runs the print page dialog (§7.4) on the terminal t: the
// URLs with QR codes, the certificate fingerprint and a countdown; c copies
// the URL, Esc (or q, or Ctrl-C) stops. SIGINT, SIGHUP and SIGTERM stop the
// server too. It reports how the page ended.
func (a *app) servePrintPage(ctx context.Context, t *tty.TTY, cfg *config.Config, doc print.Document) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)
	defer signal.Stop(sigs)
	go func() {
		select {
		case <-sigs:
			cancel()
		case <-ctx.Done():
		}
	}()

	srv, err := printweb.Start(ctx, printweb.Options{Settings: cfg.PrintWeb, Doc: doc})
	if err != nil {
		return err
	}
	var b strings.Builder
	if srv.CertNotice != "" {
		b.WriteString(line(srv.CertNotice) + "\n")
	}
	for _, s := range srv.Skipped {
		b.WriteString("not used: " + line(s) + "\n")
	}
	for _, u := range srv.URLs {
		if qr, err := printweb.TerminalQR(u); err == nil {
			b.WriteString(qr)
		}
		b.WriteString(u + "\n\n")
	}
	b.WriteString("certificate SHA-256  " + srv.Fingerprint + "\n")
	b.WriteString("Compare it with the fingerprint your browser shows before you accept the certificate.\n")
	b.WriteString("c copies the URL · Esc stops\n")
	t.Printf("%s", b.String())

	res := a.printPageKeys(ctx, t, cfg, srv)
	if res.Outcome == printweb.Served {
		a.printf("Done: %s.\n", res)
		return nil
	}
	return errors.New(res.String())
}

// printPageKeys shows the countdown and handles keys until the server
// stops. The terminal is in raw mode meanwhile and restored afterwards.
func (a *app) printPageKeys(ctx context.Context, t *tty.TTY, cfg *config.Config, srv *printweb.Server) printweb.Result {
	f := t.File()
	fd := int(f.Fd())
	if old, err := term.MakeRaw(fd); err == nil {
		defer func() { _ = term.Restore(fd, old) }()
	}
	keys := make(chan byte, 16)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		var k [1]byte
		for {
			n, err := f.Read(k[:])
			if n == 1 {
				select {
				case keys <- k[0]:
				default:
				}
			}
			if err != nil {
				return
			}
		}
	}()
	defer func() {
		// Unblock the reader, so it doesn't eat input after the dialog.
		if f.SetReadDeadline(time.Now()) == nil {
			select {
			case <-readerDone:
			case <-time.After(time.Second):
			}
			_ = f.SetReadDeadline(time.Time{})
		}
	}()

	status := func(msg string) {
		left := max(time.Until(srv.Expires).Round(time.Second), 0)
		t.Printf("\r\x1b[K%sstops after one load or in %d:%02d", msg, int(left/time.Minute), int(left%time.Minute/time.Second))
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var copied string
	cb, cbErr := a.clipboard(cfg)
	if cb != nil {
		defer func() {
			cctx, ccancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer ccancel()
			_ = cb.ClearPending(cctx)
		}()
	}
	status("")
	for {
		select {
		case <-srv.Done():
			t.Printf("\r\x1b[K")
			return srv.Wait()
		case <-tick.C:
			status(copied)
		case k := <-keys:
			switch k {
			case 'c', 'C':
				switch {
				case cbErr != nil:
					copied = "no clipboard · "
				default:
					if _, err := cb.CopyFor(ctx, srv.URLs[0], cfg.Clipboard.ClearAfter); err != nil {
						copied = "copy failed · "
					} else {
						copied = "URL copied · "
					}
				}
				status(copied)
			case 0x1b, 'q', 'Q', 0x03:
				srv.Stop()
			}
		}
	}
}
