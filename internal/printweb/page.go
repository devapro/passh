package printweb

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"

	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/print"
)

// pageCSS is the page's only style, inline in one <style> element; its hash
// is in the Content-Security-Policy. It has no comments: html/template
// removes CSS comments from template text, which would change the hash.
const pageCSS = `
@page { size: auto; margin: 12mm 15mm; }
html { background: #fff; color: #000; color-scheme: light; }
body { margin: 0; padding: 12px; font-family: ui-monospace, "DejaVu Sans Mono", "Liberation Mono", Menlo, Consolas, monospace; font-size: 10pt; line-height: 1.3; }
.tip { font-family: system-ui, sans-serif; background: #ffe; border: 1px solid #cc9; padding: 8px 12px; margin: 0 0 12px; }
.wrap { overflow-x: auto; }
table.sheet { border-collapse: collapse; width: 100%; }
table.sheet td { padding: 0; vertical-align: top; }
.hd { display: flex; justify-content: space-between; gap: 2ch; font-size: 8.5pt; border-bottom: 1.5px solid #000; padding-bottom: 2pt; margin-bottom: 8pt; }
.ft { font-size: 7pt; color: #333; border-top: 1px solid #000; padding-top: 2pt; margin-top: 8pt; }
.nb { break-inside: avoid; page-break-inside: avoid; }
.keep { break-after: avoid; page-break-after: avoid; }
.r { white-space: pre; min-height: 1.3em; }
.r.sp { min-height: 0; height: 0.6em; }
.title { font-size: 14pt; font-weight: bold; }
.meta { font-size: 9pt; color: #444; }
.folder, .heading { font-size: 11pt; font-weight: bold; border-bottom: 1px solid #777; margin-bottom: 3pt; }
.entry, .warning, .key { font-weight: bold; }
.key { font-size: 16pt; }
.code { font-size: 6.5pt; }
.lb { color: #666; }
.mk { white-space: pre; line-height: 1; margin-bottom: 2pt; }
.mk b { display: inline-block; width: 1.4286ch; font-size: 7pt; text-align: center; color: #444; }
.qr { margin: 4pt 0; }
.qr svg { width: 38mm; height: 38mm; display: block; }
@media print {
  body { padding: 0; }
  .tip { display: none; }
  .wrap { overflow: visible; }
}
`

var (
	styleHash = func() string {
		sum := sha256.Sum256([]byte(pageCSS))
		return base64.StdEncoding.EncodeToString(sum[:])
	}()
	// contentSecurityPolicy blocks scripts and every outgoing request
	// (§7.4); the only style allowed is pageCSS.
	contentSecurityPolicy = "default-src 'none'; style-src 'sha256-" + styleHash +
		"'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

// setHeaders sets the response headers of §7.4, on every response.
func setHeaders(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", contentSecurityPolicy)
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
}

const pageHTML = `<!DOCTYPE html>
<html lang="{{.Lang}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<title>{{.Confidential}} · {{.Title}}</title>
<style>` + pageCSS + `</style>
</head>
<body>
<p class="tip">{{.Tip}}</p>
<div class="wrap">
<table class="sheet">
<thead><tr><td><div class="hd"><span><b>{{.Confidential}}</b> · {{.Title}}</span><span>{{.Date}}</span></div></td></tr></thead>
<tfoot><tr><td><div class="ft">{{range .Legend}}<div>{{.}}</div>{{end}}</div></td></tr></tfoot>
<tbody><tr><td>
{{range .Blocks}}<div class="blk{{if .Whole}} nb{{end}}{{if .Keep}} keep{{end}}">
{{range .Rows}}{{if .QR}}<div class="qr">{{.QR}}</div>
{{else}}<div class="r {{.Class}}">{{if .Prefix}}<span class="lb">{{.Prefix}}</span>{{end}}{{.Text}}</div>
{{if .Marks}}<div class="mk">{{.Marks}}</div>
{{end}}{{end}}{{end}}</div>
{{end}}</td></tr></tbody>
</table>
</div>
</body>
</html>
`

var pageTmpl = template.Must(template.New("page").Parse(pageHTML))

type pageData struct {
	Lang         string // the BCP 47 tag of the page's language
	Confidential string
	Title        string
	Tip          template.HTML // escaped with HTMLEscapeString: "+" stays as it is
	Date         string
	Legend       []string
	Blocks       []blockData
}

// htmlLang is the lang attribute of the page in p's language: Serbian is
// written in Latin script (§3.3).
func htmlLang(p i18n.Printer) string {
	switch p.Lang() {
	case i18n.Ru:
		return "ru"
	case i18n.Sr:
		return "sr-Latn"
	}
	return "en"
}

type blockData struct {
	Keep  bool // keep with the next block (a heading)
	Whole bool // don't split across pages
	Rows  []rowData
}

// maxWholeRows: blocks up to this many rows (an entry) are kept on one
// page; longer ones (long notes, the recovery steps) may be split.
const maxWholeRows = 16

type rowData struct {
	Class  string
	Prefix string
	Text   string
	Marks  template.HTML // built by marksHTML from known characters only
	QR     template.HTML // built by qrSVG from a bitmap
}

var rowClass = map[print.RowKind]string{
	print.RowTitle:   "title",
	print.RowMeta:    "meta",
	print.RowFolder:  "folder",
	print.RowEntry:   "entry",
	print.RowValue:   "value",
	print.RowHeading: "heading",
	print.RowText:    "text",
	print.RowWarning: "warning",
	print.RowKey:     "key",
	print.RowCode:    "code",
	print.RowSpace:   "sp",
}

// renderPage writes the page for doc to w, as it is laid out. Every value
// was escaped for S4 by the layout; html/template escapes it for HTML. The
// page's own text is in p's language; doc is in its own (the same, as
// passh makes them).
func renderPage(w io.Writer, doc print.Document, p i18n.Printer) error {
	data := pageData{
		Lang:         htmlLang(p),
		Confidential: p.T(print.Confidential),
		Title:        doc.Title(),
		Tip: template.HTML(template.HTMLEscapeString(p.T("Print with Ctrl+P (Cmd+P on a Mac), then close this tab. This page was served once " + //nolint:gosec // G203: escaped with HTMLEscapeString
			"and is gone from passh; the browser may still keep it in its session history."))),
		Date:   p.T("printed %s", print.FormatDate(doc.Date())),
		Legend: doc.Legend(),
	}
	for _, b := range doc.Blocks() {
		bd := blockData{Keep: b.KeepWithNext, Whole: len(b.Rows) <= maxWholeRows}
		for _, r := range b.Rows {
			rd := rowData{Class: rowClass[r.Kind], Prefix: r.Prefix, Text: r.Text, Marks: marksHTML(r.Marks)}
			if r.Kind == print.RowQR {
				svg, err := qrSVG(r.Text, p.T("QR code of the vault key"))
				if err != nil {
					return err
				}
				rd = rowData{QR: svg}
			}
			bd.Rows = append(bd.Rows, rd)
		}
		data.Blocks = append(data.Blocks, bd)
	}
	return pageTmpl.Execute(w, data)
}

// marksHTML renders a marks line: each code letter in a <b> one column
// wide (a smaller letter, centered under its character), blanks as they
// are. Anything else is escaped.
func marksHTML(marks string) template.HTML {
	if marks == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range marks {
		switch r {
		case 'D', 'U', 'L', 'S':
			b.WriteString("<b>")
			b.WriteRune(r)
			b.WriteString("</b>")
		case ' ':
			b.WriteByte(' ')
		default:
			b.WriteString(template.HTMLEscapeString(string(r)))
		}
	}
	return template.HTML(b.String()) //nolint:gosec // G203: only <b>, the runes D, U, L, S, spaces and runes escaped with HTMLEscapeString
}

// qrSVG draws the QR code of text as inline SVG: no image, no external
// resource. label is its accessible name, escaped here.
func qrSVG(text, label string) (template.HTML, error) {
	bm, err := print.QRBitmap(text)
	if err != nil {
		return "", err
	}
	n := len(bm)
	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" role="img" aria-label="%s" shape-rendering="crispEdges">`, n, n, template.HTMLEscapeString(label))
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n)
	for y, row := range bm {
		for x := 0; x < len(row); {
			if !row[x] {
				x++
				continue
			}
			end := x
			for end < len(row) && row[end] {
				end++
			}
			fmt.Fprintf(&b, "M%d %dh%dv1h-%dz", x, y, end-x, end-x)
			x = end
		}
	}
	b.WriteString(`"/></svg>`)
	return template.HTML(b.String()), nil //nolint:gosec // G203: built from integers, constant strings and the label escaped with HTMLEscapeString
}
