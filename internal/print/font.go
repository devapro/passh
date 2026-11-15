package print

import (
	"sync"

	"golang.org/x/image/font/gofont/gomono"
	"golang.org/x/image/font/gofont/gomonobold"
	"golang.org/x/image/font/sfnt"
)

// The PDF embeds Go Mono (regular and bold) as its only font: a monospaced
// UTF-8 font with Latin, Greek and Cyrillic. Both styles cover the same
// characters, all with the same advance.

var (
	fontRegular = gomono.TTF
	fontBold    = gomonobold.TTF
)

// glyphs is the set of characters Go Mono can draw, read from its cmap.
var glyphs = sync.OnceValue(func() map[rune]bool {
	f, err := sfnt.Parse(fontRegular)
	if err != nil {
		panic("print: embedded Go Mono font: " + err.Error())
	}
	var buf sfnt.Buffer
	m := make(map[rune]bool, 1024)
	for r := rune(0x20); r <= 0xffff; r++ {
		if g, err := f.GlyphIndex(&buf, r); err == nil && g != 0 {
			m[r] = true
		}
	}
	return m
})

// hasGlyph reports whether the PDF font can draw r.
func hasGlyph(r rune) bool { return glyphs()[r] }
