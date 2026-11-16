// Package print lays out the printed sheets of §7.2 and §5.4 and writes them
// as plain text. The print page (internal/printweb) renders the same layout
// as HTML, with the recovery key's QR code; a browser can print it, or save
// it as PDF. passh writes no PDF itself.
//
// There are two documents:
//
//   - Sheet, the password sheet: chosen entries, grouped by folder, with the
//     chosen fields (NewSheet);
//   - RecoverySheet, the paper recovery key (NewRecoverySheet).
//
// Both are a Document, written in the language of the i18n.Printer they
// were made with (Options.Printer, NewRecoverySheet). A Document is laid out as Blocks of Rows on a grid of
// Columns monospaced columns; WriteTXT and the print page draw those rows,
// so both show the same content in the same order.
//
// Every value from the vault goes through internal/sanitize (S4) while it is
// laid out. On top of that, characters that would be invisible or
// misleading on paper (zero-width and other format characters, spaces other
// than U+0020, private-use characters) are written as \uXXXX. No character
// is ever dropped: long values wrap onto continuation lines that start with
// "→".
//
// Ambiguous characters are marked on a line of codes directly under the
// value: D under the digits 0 and 1, U under the capital letters O and I, L
// under the small letter l, and S under a space (in single-line values,
// where a space would otherwise be invisible). The legend is in the footer
// of every page.
package print

import (
	"time"

	"github.com/devapro/passh/internal/i18n"
)

// Columns is the width of the layout in monospaced columns: the text
// sheet's line length, which fits A4 and Letter.
const Columns = 80

// Confidential is printed in the header of every page.
const Confidential = "CONFIDENTIAL"

// DateLayout is how the print date is written.
const DateLayout = "2006-01-02 15:04"

// FormatDate writes t as the print date ("2026-11-15 14:03").
func FormatDate(t time.Time) string { return t.Format(DateLayout) }

// Document is a sheet to print: a Sheet or a RecoverySheet.
type Document interface {
	// Title names the document, e.g. "passh password sheet". It holds no
	// vault data.
	Title() string
	// Date is the print date.
	Date() time.Time
	// Legend is the explanation printed in the footer of every page (the
	// ambiguity marks), one line each. It may be empty.
	Legend() []string
	// Blocks returns the layout for the print page (HTML): no character is
	// replaced for lack of a glyph, and RowQR rows are included.
	Blocks() []Block

	blocks(t target) []Block
	// printer is the language the document is written in (§3.3).
	printer() i18n.Printer
}

// RowKind tells how a row is drawn.
type RowKind int

// Row kinds.
const (
	// RowTitle is the document's title.
	RowTitle RowKind = iota + 1
	// RowMeta is a small line under the title: date, selection, vault_id.
	RowMeta
	// RowFolder is a folder heading (password sheet).
	RowFolder
	// RowEntry is an entry's name (password sheet).
	RowEntry
	// RowValue is one line of a value: Prefix holds the indentation and the
	// label column (the label, blank, or the continuation arrow), Text the
	// value, Marks the ambiguity codes.
	RowValue
	// RowHeading is a section heading (recovery sheet).
	RowHeading
	// RowText is a line of prose, already wrapped to Columns.
	RowText
	// RowWarning is a line of warning prose, already wrapped.
	RowWarning
	// RowKey is a line of the recovery key, printed large.
	RowKey
	// RowCode is a command line, exact and never wrapped. It may be longer
	// than Columns; the page prints it smaller.
	RowCode
	// RowQR is a QR code of Text. Plain text has none.
	RowQR
	// RowSpace is vertical space between blocks.
	RowSpace
)

// Row is one line of the layout.
type Row struct {
	Kind RowKind
	// Prefix is drawn before Text in the label style (RowValue only). Its
	// width in columns is always ValuePrefixWidth.
	Prefix string
	// Text is the line's content, already escaped (S4).
	Text string
	// Marks holds the ambiguity codes (D, U, L, S) aligned column by column
	// with Prefix+Text, so it starts with blanks; it is "" when the line has
	// nothing to mark. RowValue only.
	Marks string
}

// Block is a group of rows kept on one page when possible: an entry, a
// heading, a section.
type Block struct {
	Rows []Row
	// KeepWithNext asks for the block to stay on the same page as the start
	// of the next block (headings).
	KeepWithNext bool
}

// Layout constants for value rows.
const (
	// ValueIndent is the indentation of value rows under an entry name.
	ValueIndent = 2
	// LabelWidth is the label column after the indentation: up to
	// LabelWidth-1 columns of label, then a space.
	LabelWidth = 10
	// ValuePrefixWidth is the width of Row.Prefix in RowValue rows.
	ValuePrefixWidth = ValueIndent + LabelWidth
	// ValueWidth is the width of the value column.
	ValueWidth = Columns - ValuePrefixWidth
)

// Continuation starts the label column of a line that continues the value
// on the line above (the value was wrapped, nothing was added or lost).
const Continuation = "→"

// target is the output a layout is made for.
type target int

const (
	// targetWeb: the print page. Every character is shown; East Asian wide
	// characters take two columns.
	targetWeb target = iota
	// targetTXT: like targetWeb, without the QR code.
	targetTXT
)
