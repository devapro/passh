package print

import (
	"fmt"
	"io"
	"math"
	"strconv"
	"unicode/utf8"

	"github.com/go-pdf/fpdf"
)

// compress is false in tests, so that they can read the page content.
var compress = true

const (
	fontFamily = "gomono"

	ptToMM = 25.4 / 72
	// advance is Go Mono's advance width in em (1229/2048), the same for
	// every glyph.
	advance = 1229.0 / 2048

	marginX      = 15.0 // mm, left and right
	marginTop    = 12.0
	marginBottom = 12.0
	headerHeight = 9.0 // header line and rule, before the body
	legendLine   = 3.4 // height of a footer line

	bodySize   = 10.0 // pt; Columns of it fit A4 and Letter
	markSize   = 7.0
	headerSize = 8.5
	legendSize = 7.0
	qrSize     = 38.0 // mm
)

// charWidth returns the width in mm of one Go Mono character at size pt.
func charWidth(size float64) float64 { return size * advance * ptToMM }

// pdfDoc draws one document.
type pdfDoc struct {
	f        *fpdf.Fpdf
	pageW    float64
	pageH    float64
	codeSize float64
}

// WritePDF writes doc as a PDF on paper of the given size. The only font is
// the embedded Go Mono.
func WritePDF(w io.Writer, doc Document, size PaperSize) error {
	sizeName := "A4"
	if size == Letter {
		sizeName = "Letter"
	}
	f := fpdf.NewCustom(&fpdf.InitType{OrientationStr: "P", UnitStr: "mm", SizeStr: sizeName})
	f.SetCompression(compress)
	f.SetCreationDate(doc.Date())
	f.SetModificationDate(doc.Date())
	f.SetTitle(doc.Title()+" ("+Confidential+")", true)
	f.SetCreator("passh", false)
	f.SetProducer("passh", false)
	f.AddUTF8FontFromBytes(fontFamily, "", fontRegular)
	f.AddUTF8FontFromBytes(fontFamily, "B", fontBold)
	f.SetAutoPageBreak(false, 0)
	f.SetMargins(marginX, marginTop, marginX)
	f.SetCellMargin(0)

	p := &pdfDoc{f: f}
	p.pageW, p.pageH = f.GetPageSize()
	blocks := doc.blocks(targetPDF)
	p.codeSize = p.fitCode(blocks)

	legend := doc.Legend()
	bodyTop := marginTop + headerHeight
	footerTop := p.pageH - marginBottom - 2 - legendLine*float64(len(legend))
	pages := paginate(blocks, footerTop-1-bodyTop, p.height)
	for i, rows := range pages {
		f.AddPage()
		p.header(doc, i+1, len(pages))
		p.footer(legend, footerTop)
		y := bodyTop
		for _, r := range rows {
			if err := p.draw(r, y); err != nil {
				return err
			}
			y += p.height(r)
		}
	}
	if err := f.Error(); err != nil {
		return fmt.Errorf("PDF: %w", err)
	}
	if err := f.Output(w); err != nil {
		return fmt.Errorf("PDF: %w", err)
	}
	return nil
}

// fitCode returns the font size at which the longest command fits the page
// width, at most 8 pt.
func (p *pdfDoc) fitCode(blocks []Block) float64 {
	longest := 0
	for _, b := range blocks {
		for _, r := range b.Rows {
			if r.Kind == RowCode {
				longest = max(longest, utf8.RuneCountInString(r.Text))
			}
		}
	}
	if longest == 0 {
		return 8
	}
	fit := (p.pageW - 2*marginX) / (float64(longest) * charWidth(1))
	return min(8, math.Floor(fit*10)/10)
}

// height returns the height of a row in mm.
func (p *pdfDoc) height(r Row) float64 {
	switch r.Kind {
	case RowTitle:
		return 9
	case RowMeta:
		return 4.4
	case RowFolder, RowHeading:
		return 7.5
	case RowEntry:
		return 5.4
	case RowValue:
		if r.Marks != "" {
			return 4.5 + 2.9
		}
		return 4.5
	case RowText:
		return 4.5
	case RowWarning:
		return 5
	case RowKey:
		return 7.5
	case RowCode:
		return max(3, p.codeSize*ptToMM*1.4)
	case RowQR:
		return qrSize + 2
	case RowSpace:
		return 2.5
	}
	return 4.5
}

func (p *pdfDoc) text(x, y, h float64, style string, size float64, gray int, s string) {
	p.f.SetFont(fontFamily, style, size)
	p.f.SetTextColor(gray, gray, gray)
	p.f.SetXY(x, y)
	p.f.CellFormat(0, h, s, "", 0, "L", false, 0, "")
}

func (p *pdfDoc) header(doc Document, page, pages int) {
	f := p.f
	y := marginTop
	p.text(marginX, y, 5, "B", headerSize, 0, Confidential)
	x := marginX + charWidth(headerSize)*float64(len(Confidential))
	p.text(x, y, 5, "", headerSize, 0, " · "+doc.Title())
	right := FormatDate(doc.Date()) + " · page " + strconv.Itoa(page) + " of " + strconv.Itoa(pages)
	f.SetFont(fontFamily, "", headerSize)
	f.SetXY(p.pageW-marginX-f.GetStringWidth(right), y)
	f.CellFormat(0, 5, right, "", 0, "L", false, 0, "")
	f.SetDrawColor(0, 0, 0)
	f.SetLineWidth(0.3)
	f.Line(marginX, y+6, p.pageW-marginX, y+6)
}

func (p *pdfDoc) footer(legend []string, top float64) {
	f := p.f
	f.SetDrawColor(0, 0, 0)
	f.SetLineWidth(0.2)
	f.Line(marginX, top+1, p.pageW-marginX, top+1)
	for i, l := range legend {
		p.text(marginX, top+2+legendLine*float64(i), legendLine, "", legendSize, 60, l)
	}
}

func (p *pdfDoc) draw(r Row, y float64) error {
	h := p.height(r)
	switch r.Kind {
	case RowTitle:
		p.text(marginX, y, h, "B", 14, 0, r.Text)
	case RowMeta:
		p.text(marginX, y, h, "", 9, 60, r.Text)
	case RowFolder, RowHeading:
		p.text(marginX, y, h-1.5, "B", 11, 0, r.Text)
		p.f.SetDrawColor(120, 120, 120)
		p.f.SetLineWidth(0.2)
		p.f.Line(marginX, y+h-1, p.pageW-marginX, y+h-1)
	case RowEntry:
		p.text(marginX, y, h, "B", bodySize, 0, r.Text)
	case RowValue:
		p.value(r, y)
	case RowText:
		p.text(marginX, y, h, "", bodySize, 0, r.Text)
	case RowWarning:
		p.text(marginX, y, h, "B", bodySize, 0, r.Text)
	case RowKey:
		p.text(marginX, y, h, "B", 16, 0, r.Text)
	case RowCode:
		p.text(marginX, y, h, "", p.codeSize, 0, r.Text)
	case RowQR:
		return p.qr(r.Text, y+1)
	}
	return nil
}

// value draws a value line: the label column in gray, the value in black,
// and the ambiguity codes under their characters.
func (p *pdfDoc) value(r Row, y float64) {
	const lineH = 4.5
	cw := charWidth(bodySize)
	p.text(marginX, y, lineH, "", bodySize, 110, r.Prefix)
	if r.Text != "" {
		x := marginX + cw*float64(utf8.RuneCountInString(r.Prefix))
		p.text(x, y, lineH, "", bodySize, 0, r.Text)
	}
	if r.Marks == "" {
		return
	}
	mw := charWidth(markSize)
	for i := 0; i < len(r.Marks); i++ {
		if c := r.Marks[i]; c != ' ' {
			x := marginX + cw*float64(i) + (cw-mw)/2
			p.text(x, y+lineH-0.8, 3, "B", markSize, 70, string(c))
		}
	}
}

// qr draws the QR code of text, dark modules in runs.
func (p *pdfDoc) qr(text string, y float64) error {
	bm, err := QRBitmap(text)
	if err != nil {
		return err
	}
	m := qrSize / float64(len(bm))
	p.f.SetFillColor(0, 0, 0)
	for row, bits := range bm {
		for x := 0; x < len(bits); {
			if !bits[x] {
				x++
				continue
			}
			end := x
			for end < len(bits) && bits[end] {
				end++
			}
			// A hair of overlap avoids hairline gaps between modules.
			p.f.Rect(marginX+float64(x)*m, y+float64(row)*m, float64(end-x)*m+0.02, m+0.02, "F")
			x = end
		}
	}
	return nil
}
