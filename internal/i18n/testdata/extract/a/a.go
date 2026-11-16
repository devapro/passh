// Package a holds one call of each kind the extractor must find
// (TestExtractor). It is parsed, never compiled.
package a

import (
	"fmt"

	"example.com/m/b"
	tr "example.com/m/internal/i18n"
)

const greeting = "Hello, %s."

const joined = "part one, " + "part two"

var errSentinel = tr.NewError("a sentinel")

// X is anything with a Printer.
type X struct{ p tr.Printer }

// say prints a translated message.
//
// i18n:wrapper
func (x *X) say(format string, args ...any) { x.p.T(format, args...) }

func (x *X) f(v string, n int) {
	x.p.T(greeting, v)
	x.p.T(joined)
	x.p.T(b.Shared)
	x.p.TC("menu", "Open")
	x.p.N(n, "%d file", "%d files", n)
	_ = tr.Errorf("reading %s: %w", v, errSentinel)
	_ = tr.Msg("deferred %d", n)
	_ = tr.Mark("marked")
	x.say("Said %s.", v)
	b.Warnf("warned %d", n)
	x.p.T("%s: %v", v, errSentinel)
	x.p.T(v) // i18n:dynamic
	// i18n:dynamic
	x.p.T(v)
	_ = fmt.Errorf("not ours %s", v)
	_ = x.p.T(v)
	x.p.T("two %s %d", v)
	x.p.T("100% plain")
	_ = tr.NewError("bad %d")
	x.p.T("spread %s %d", []any{v, n}...)
}
