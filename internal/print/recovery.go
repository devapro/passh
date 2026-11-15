package print

import (
	"errors"
	"slices"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/sanitize"
)

// RecoverySheet is the paper recovery key (§5.4): the vault key in groups of
// four characters and as a QR code, the vault_id, the print date, a warning
// and the manual recovery steps of §8.
//
// It never holds or prints the key's public recipient (age1…, S9).
type RecoverySheet struct {
	key     string   // the bare key, AGE-SECRET-KEY-1…
	lines   []string // keys.FormatRecoveryKey, one line each
	vaultID string
	date    time.Time
}

// recoveryCommands are the manual recovery commands of §8, exactly as the
// spec gives them. Never written; RecoveryCommandList hands out copies.
var recoveryCommands = []string{
	`tr -d '\r' < vault.passh | awk '/BEGIN AGE ENCRYPTED FILE/{n++} n==1{print} n==1 && /END AGE ENCRYPTED FILE/{exit}' > key.age`,
	`tr -d '\r' < vault.passh | awk '/BEGIN AGE ENCRYPTED FILE/{n++} n==2{print} n==2 && /END AGE ENCRYPTED FILE/{exit}' > data.age`,
	`age -d -o /dev/shm/key.txt key.age                            # asks for the passphrase`,
	`age -d -i /dev/shm/key.txt -o /dev/shm/vault.json data.age`,
	`rm /dev/shm/key.txt`,
}

// RecoveryCommandList returns the manual recovery commands of §8 that the
// recovery sheet prints, exactly as the spec gives them. Each call returns
// a new slice (API-7).
func RecoveryCommandList() []string { return slices.Clone(recoveryCommands) }

// RecoveryCommands is a copy of RecoveryCommandList, kept for existing
// callers. This package never reads it, so changing it changes nothing
// here; new code calls RecoveryCommandList.
var RecoveryCommands = RecoveryCommandList()

// NewRecoverySheet makes the recovery sheet for the vault key id of the
// vault vaultID. A zero date means now.
func NewRecoverySheet(id *age.X25519Identity, vaultID string, date time.Time) (*RecoverySheet, error) {
	if id == nil {
		return nil, errors.New("recovery sheet: no vault key")
	}
	if vaultID == "" {
		return nil, errors.New("recovery sheet: no vault_id")
	}
	if date.IsZero() {
		date = time.Now()
	}
	return &RecoverySheet{
		key:     id.String(),
		lines:   strings.Split(keys.FormatRecoveryKey(id), "\n"),
		vaultID: vaultID,
		date:    date,
	}, nil
}

// Title implements Document.
func (r *RecoverySheet) Title() string { return "passh paper recovery key" }

// Date implements Document.
func (r *RecoverySheet) Date() time.Time { return r.date }

// Legend implements Document. The recovery sheet has no marks to explain.
func (r *RecoverySheet) Legend() []string { return nil }

// Blocks implements Document.
func (r *RecoverySheet) Blocks() []Block { return r.blocks(targetWeb) }

func (r *RecoverySheet) blocks(t target) []Block {
	head := Block{Rows: []Row{
		{Kind: RowTitle, Text: r.Title()},
		{Kind: RowMeta, Text: "vault_id " + t.text(sanitize.Line(r.vaultID))},
		{Kind: RowMeta, Text: "printed " + FormatDate(r.date)},
		{Kind: RowSpace},
	}}
	head.Rows = append(head.Rows, t.proseRows(RowWarning,
		"Whoever has this sheet and a copy of the vault can read everything in the vault.")...)
	head.Rows = append(head.Rows, t.proseRows(RowText,
		"Keep it offline, like cash. If it may have been seen, copied or lost, run `passh rekey` "+
			"and print a new sheet: the old key then no longer opens new versions of the vault "+
			"(copies made before still open with it).")...)

	key := Block{Rows: []Row{{Kind: RowSpace}, {Kind: RowHeading, Text: "Vault key"}}}
	for _, l := range r.lines {
		key.Rows = append(key.Rows, Row{Kind: RowKey, Text: l})
	}
	key.Rows = append(key.Rows, Row{Kind: RowSpace})
	key.Rows = append(key.Rows, t.proseRows(RowText,
		"After AGE-SECRET-KEY-1 the key never has the letters B, I or O or the digit 1: "+
			"0 is always the digit zero.")...)
	if t == targetTXT {
		key.Rows = append(key.Rows, t.proseRows(RowText,
			"The PDF and the print page also show the key as a QR code.")...)
	} else {
		key.Rows = append(key.Rows, Row{Kind: RowQR, Text: r.key})
	}

	forgot := Block{Rows: []Row{{Kind: RowSpace}, {Kind: RowHeading, Text: "Forgotten passphrase"}}}
	forgot.Rows = append(forgot.Rows, t.proseRows(RowText,
		"Run `passh recover` and type the key above. Spaces, line breaks and letter case are "+
			"ignored, and the key's checksum catches typos. passh then asks for a new passphrase.")...)

	manual := Block{Rows: []Row{{Kind: RowSpace}, {Kind: RowHeading, Text: "Without passh"}}}
	manual.Rows = append(manual.Rows, t.proseRows(RowText,
		"On any machine with age (https://age-encryption.org) v1.0 or later, where vault.passh "+
			"is a copy of the vault file:")...)
	manual.Rows = append(manual.Rows, Row{Kind: RowSpace})
	for _, c := range recoveryCommands {
		manual.Rows = append(manual.Rows, Row{Kind: RowCode, Text: c})
	}
	for _, p := range []string{
		"With this key instead of the passphrase: write it to /dev/shm/key.txt as one line, " +
			"without spaces, in capital letters as printed (AGE-SECRET-KEY-1 and then the groups), " +
			"instead of running the first and third commands. The other commands stay the same.",
		"vault.json is plaintext. Keep it on tmpfs (/dev/shm on Linux) and delete it when done.",
		"If a mail client or editor re-wrapped the lines, age may reject the blocks. passh still " +
			"opens such a file, and `passh backup` writes it back in canonical form.",
	} {
		manual.Rows = append(manual.Rows, Row{Kind: RowSpace})
		manual.Rows = append(manual.Rows, t.bulletRows(p)...)
	}
	return []Block{head, key, forgot, manual}
}

// bulletRows wraps a bullet point, continuation lines indented.
func (t target) bulletRows(text string) []Row {
	lines := t.wrapProse(text, Columns-2)
	rows := make([]Row, len(lines))
	for i, l := range lines {
		prefix := "  "
		if i == 0 {
			prefix = "• "
		}
		rows[i] = Row{Kind: RowText, Text: prefix + l}
	}
	return rows
}
