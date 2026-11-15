// Package export writes vault entries in formats other tools read (spec
// §7.1, §7.3): json (the vault's own data format), csv and bitwarden-json.
//
// Everything here is a pure function: entries and vault metadata in, bytes
// out to an io.Writer. The output is built in memory first, so on an error
// nothing is written. Prompts, the "never to a terminal" check and creating
// the output file belong to the CLI; ConfirmPlaintext tells it which
// confirmation a plaintext export needs.
//
// With a recipient (--age), the output is encrypted to an age X25519
// (age1…) or hybrid post-quantum (age1pq1…) public key and written with
// age's ASCII armor ("-----BEGIN AGE ENCRYPTED FILE-----"), like the vault
// blocks: it survives copy and paste and e-mail bodies, and `age -d` reads
// it as is.
package export

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"

	"passh/internal/model"
	"passh/internal/paths"
)

// Format is an export format.
type Format string

// The export formats (§7.1).
const (
	FormatCSV       Format = "csv"
	FormatJSON      Format = "json"
	FormatBitwarden Format = "bitwarden-json"
)

// Formats lists the format names, for help texts and completion.
func Formats() []string {
	return []string{string(FormatCSV), string(FormatJSON), string(FormatBitwarden)}
}

// ParseFormat checks a --format value.
func ParseFormat(s string) (Format, error) {
	switch f := Format(s); f {
	case FormatCSV, FormatJSON, FormatBitwarden:
		return f, nil
	}
	return "", fmt.Errorf("unknown export format %q (use csv, json or bitwarden-json)", s)
}

// Filter selects the entries to export (--tag, --folder).
type Filter struct {
	// Folder keeps the entries inside this folder, at any depth. The test
	// is segment-aware: "work" holds "work/x", not "workshop/x". The zero
	// Path keeps every folder.
	Folder paths.Path
	// Tags keeps the entries that have every one of these tags (AND).
	Tags []string
}

// ParseFilter validates --folder (empty means every folder) and --tag
// values (repeatable; all must match).
func ParseFilter(folder string, tags []string) (Filter, error) {
	var f Filter
	if folder != "" {
		p, err := paths.ParseFolder(folder)
		if err != nil {
			return Filter{}, err
		}
		f.Folder = p
	}
	for _, t := range tags {
		n, err := model.NormalizeTag(t)
		if err != nil {
			return Filter{}, err
		}
		f.Tags = append(f.Tags, n)
	}
	return f, nil
}

// Select returns copies of d's entries that pass f, sorted by path.
func (f Filter) Select(d *model.Data) []model.Entry {
	return d.Filter(f.Folder, f.Tags)
}

// Options describe one export.
type Options struct {
	Format Format
	Filter Filter
	// SpreadsheetSafe prefixes "'" to CSV cells starting with = + - @,
	// tab or CR. Only for FormatCSV.
	SpreadsheetSafe bool
	// Recipient, if set, encrypts the output to this age public key
	// (--age). Empty means plaintext.
	Recipient string
	// Now is the export time (json's "exported_at"); zero means time.Now().
	Now time.Time
}

// Plaintext reports whether the export is written unencrypted and so needs
// the user's confirmation (§7.1).
func (o Options) Plaintext() bool { return o.Recipient == "" }

var (
	// ErrNotConfirmed: a plaintext export without a terminal and without
	// --confirm-plaintext (§7.1, §13.2 test 5).
	ErrNotConfirmed = errors.New("a plaintext export needs confirmation: without a terminal, add --confirm-plaintext (or encrypt it with --age <recipient>)")
	// ErrAgeAndConfirm: --age and --confirm-plaintext together.
	ErrAgeAndConfirm = errors.New("--age and --confirm-plaintext can't be used together")
	// ErrSpreadsheetSafe: --spreadsheet-safe with a format other than csv.
	ErrSpreadsheetSafe = errors.New("--spreadsheet-safe applies only to --format csv")
)

// ConfirmPlaintext decides how the CLI confirms an export (§7.1). It
// returns prompt = true when the user must type tty.PhraseExportPlaintext
// on the terminal. An encrypted export needs nothing. A plaintext export
// with a terminal is always confirmed there, even with --confirm-plaintext:
// the flag stands in for the prompt only when there is no terminal, and
// without both it fails with ErrNotConfirmed.
func ConfirmPlaintext(o Options, haveTerminal, confirmFlag bool) (prompt bool, err error) {
	switch {
	case !o.Plaintext() && confirmFlag:
		return false, ErrAgeAndConfirm
	case !o.Plaintext():
		return false, nil
	case haveTerminal:
		return true, nil
	case confirmFlag:
		return false, nil
	}
	return false, ErrNotConfirmed
}

// Summary describes a finished export, for the CLI's message.
type Summary struct {
	Entries   int  // entries written
	Encrypted bool // the output is age-encrypted
	// OmittedFields counts the custom fields (otp included) a CSV export
	// has no column for. Other formats keep every field.
	OmittedFields int
}

// Export writes the entries of d that pass o.Filter to w, in o.Format,
// encrypted if o.Recipient is set. Options are checked before anything is
// written, and nothing is written on an error.
func Export(w io.Writer, d *model.Data, o Options) (Summary, error) {
	if _, err := ParseFormat(string(o.Format)); err != nil {
		return Summary{}, err
	}
	if o.SpreadsheetSafe && o.Format != FormatCSV {
		return Summary{}, ErrSpreadsheetSafe
	}
	var rcpt age.Recipient
	if !o.Plaintext() {
		r, err := ParseRecipient(o.Recipient)
		if err != nil {
			return Summary{}, err
		}
		rcpt = r
	}
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}

	entries := o.Filter.Select(d)
	sum := Summary{Entries: len(entries), Encrypted: rcpt != nil}
	var buf bytes.Buffer
	defer func() { b := buf.Bytes(); clear(b[:cap(b)]) }() // best effort
	var err error
	switch o.Format {
	case FormatJSON:
		err = WriteJSON(&buf, d, entries, now)
	case FormatCSV:
		err = WriteCSV(&buf, entries, o.SpreadsheetSafe)
		for _, e := range entries {
			sum.OmittedFields += len(e.Fields)
		}
	case FormatBitwarden:
		err = WriteBitwarden(&buf, d.VaultID, entries)
	}
	if err != nil {
		return Summary{}, err
	}
	if rcpt != nil {
		err = Encrypt(w, rcpt, buf.Bytes())
	} else {
		_, err = w.Write(buf.Bytes())
	}
	if err != nil {
		return Summary{}, err
	}
	return sum, nil
}

// WriteJSON writes the json format (§7.3): the data format of §4.2 with
// d's header and unknown keys, "exported_at" added, the given entries, and
// no "deleted".
func WriteJSON(w io.Writer, d *model.Data, entries []model.Entry, exportedAt time.Time) error {
	b, err := d.EncodeExport(entries, exportedAt)
	if err != nil {
		return err
	}
	defer clear(b)
	_, err = w.Write(b)
	return err
}

// ParseRecipient parses an --age value: an X25519 recipient (age1…) or a
// hybrid post-quantum one (age1pq1…). Anything else is an error that
// doesn't repeat the value unless it looks like a recipient, so a secret
// key pasted by mistake isn't echoed.
func ParseRecipient(s string) (age.Recipient, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "age1pq1"):
		r, err := age.ParseHybridRecipient(s)
		if err != nil {
			return nil, fmt.Errorf("--age: invalid age recipient %q: %v", s, err)
		}
		return r, nil
	case strings.HasPrefix(s, "age1"):
		r, err := age.ParseX25519Recipient(s)
		if err != nil {
			return nil, fmt.Errorf("--age: invalid age recipient %q: %v", s, err)
		}
		return r, nil
	case strings.HasPrefix(strings.ToUpper(s), "AGE-SECRET-KEY-"):
		return nil, errors.New("--age: this is an age secret key; give its public recipient (age1…), as printed by age-keygen -y")
	case s == "":
		return nil, errors.New("--age: the recipient is empty; give an age public key (age1…)")
	}
	return nil, errors.New("--age: not an age recipient; give an age public key (age1…)")
}

// Encrypt writes plaintext to w encrypted to r, in age's ASCII armor. The
// ciphertext is built in memory and written with one Write.
func Encrypt(w io.Writer, r age.Recipient, plaintext []byte) error {
	var out bytes.Buffer
	aw := armor.NewWriter(&out)
	ew, err := age.Encrypt(aw, r)
	if err != nil {
		return fmt.Errorf("age: %w", err)
	}
	if _, err := ew.Write(plaintext); err != nil {
		return fmt.Errorf("age: %w", err)
	}
	if err := ew.Close(); err != nil {
		return fmt.Errorf("age: %w", err)
	}
	if err := aw.Close(); err != nil {
		return fmt.Errorf("age: %w", err)
	}
	_, err = w.Write(out.Bytes())
	return err
}
