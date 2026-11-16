// Package i18n translates what passh writes for people (spec §3.3
// `language`): messages, prompts, errors, help texts, the TUI and the
// printed sheets, in English (en, the default), Russian (ru) and Serbian
// in Latin script (sr).
//
// The package is a leaf (standard library only) that every passh package
// may import. It has no mutable state (API-4, API-5): the language is a
// value, a [Printer], passed down from internal/cli; the catalogs are
// read-only tables built from Go map literals. docs/translations.md is the
// guide for adding and translating messages.
//
// # Messages
//
// The English text is the key, gettext style. A [Printer] looks it up in
// the catalog of its language and falls back to English; with arguments
// the result is formatted with [fmt.Sprintf]. Translators may reorder
// arguments with indexed verbs (%[2]s … %[1]d). Arguments that are errors
// are rendered with [Printer.Error] and arguments that implement
// [Localizer] with their Localize method, so they are translated too.
// A message called without arguments is plain text, never a format.
//
//	p.T("Saved %s.", path)                        // a sentence
//	p.TC("menu", "Open")                          // one English text, two translations
//	p.N(n, "%d entry", "%d entries", n)           // plural forms
//	i18n.Msg("the backup %s was skipped", name)   // a deferred message (core packages)
//	i18n.Mark("no clipboard is configured")       // a key kept in a string, translated later
//
// The same English text has the same translation everywhere. When one
// English text needs two translations, give one of the calls a context
// with [Printer.TC].
//
// # Errors
//
// Packages without a Printer (vault, keys, config, …) make translatable
// errors: [NewError] for sentinels (errors.Is works by identity, as with
// errors.New) and [Errorf], a drop-in for fmt.Errorf with the same %w
// wrapping, Unwrap and errors.Is/As behaviour. Their Error method returns
// the English text. [Printer.Error] renders any error in the language: a
// [Localizer] renders itself (typed errors with fields write a Localize
// method), the errors of this package translate their format and render
// their arguments recursively, a plain error whose whole text is a catalog
// key is translated, and anything else (operating system and library
// errors) stays as it is.
//
// # Plurals
//
// [Printer.N] picks the form by the CLDR rules for integers: English has
// one (n = 1) and other; Russian and Serbian have one (n%10 = 1 and n%100
// ≠ 11), few (n%10 in 2..4 and n%100 not in 12..14) and many/other. The
// catalogs store three forms for ru and sr.
//
// # Catalogs
//
// Each language has one file per area, so translators of different areas
// never edit the same file: ru_core.go, ru_ui.go, ru_cli.go, ru_tui.go and
// the same for sr (the areas are listed in docs/translations.md). A key in
// two area files must have the same translation in both.
//
// # How the tests find messages
//
// The tests of this package parse every non-test .go file under internal/
// and cmd/ (go/ast, no type checking) and collect the messages of these
// calls:
//
//   - x.T(msg, …), x.TC(context, msg, …) and x.N(n, one, other, …): any
//     method call with these names, so never give another method one of
//     these names;
//   - i18n.NewError(msg), i18n.Errorf(format, …), i18n.Msg(format, …) and
//     i18n.Mark(msg), qualified by the name the file imports this package
//     under (no dot import);
//   - calls of wrappers: a function or method whose doc comment has a line
//     "i18n:wrapper" passes its parameter named format or msg on as a
//     message, so its callers' literals are messages too (statusf-style
//     helpers). Calls are matched by the wrapper's name.
//
// The message must be a string constant: a literal, a concatenation, or a
// constant of the same package or another passh package. A call with
// another expression fails the tests, unless a comment containing
// "i18n:dynamic" is on the same line or the line above (for strings that
// were marked with [Mark] where they were written, or a wrapper passing its
// own parameter on, which needs no comment). Messages without any letter
// ("%s: %v") are not keys. The tests then require a ru and a sr
// translation for every message, no catalog entry that no call uses, the
// same format verbs (for the same arguments) in every translation, and as
// many arguments as the English format uses at every call.
package i18n

import (
	"fmt"
	"strings"
)

// Lang is a language passh speaks. The zero value is English.
type Lang uint8

// The languages of §3.3.
const (
	// En is English, the default.
	En Lang = iota
	// Ru is Russian.
	Ru
	// Sr is Serbian in Latin script (ekavian).
	Sr
	numLangs
)

// langNames are the config values, indexed by Lang.
var langNames = [numLangs]string{En: "en", Ru: "ru", Sr: "sr"}

// Langs returns every language, English first.
func Langs() []Lang { return []Lang{En, Ru, Sr} }

// Parse returns the language of a `language` config value: exactly "en",
// "ru" or "sr". Anything else is an error naming the allowed values.
func Parse(s string) (Lang, error) {
	for l, name := range langNames {
		if s == name {
			return Lang(l), nil
		}
	}
	// The language is unknown here, so this message is never translated:
	// a config file with it doesn't load, and passh speaks English.
	return En, fmt.Errorf("%q is not one of %s", s, quotedNames())
}

// quotedNames is `"en", "ru" or "sr"`.
func quotedNames() string {
	q := make([]string, len(langNames))
	for i, n := range langNames {
		q[i] = fmt.Sprintf("%q", n)
	}
	return strings.Join(q[:len(q)-1], ", ") + " or " + q[len(q)-1]
}

// String returns the config value: "en", "ru" or "sr".
func (l Lang) String() string {
	if l < numLangs {
		return langNames[l]
	}
	return fmt.Sprintf("Lang(%d)", uint8(l))
}

// Printer renders messages in one language. It is a small value: copy it
// freely and pass it down. The zero value prints English. A Printer is safe
// for concurrent use.
type Printer struct {
	lang Lang
}

// New returns a Printer for l; an unknown l prints English.
func New(l Lang) Printer {
	if l >= numLangs {
		l = En
	}
	return Printer{lang: l}
}

// Lang returns the Printer's language.
func (p Printer) Lang() Lang { return p.lang }

// T returns msg in p's language, formatted with args when there are any.
// Without args msg is plain text: a % in it is printed as is.
func (p Printer) T(msg string, args ...any) string {
	return p.sprintf(p.lookup(msg), args)
}

// TC is T for an English text that needs a different translation in this
// place (context names the place, e.g. "menu"). Without a translation for
// the context it falls back to the English msg, not to msg's translation
// without context.
func (p Printer) TC(context, msg string, args ...any) string {
	if t, ok := p.catalog().msgs[contextKey(context, msg)]; ok {
		return p.sprintf(t, args)
	}
	return p.sprintf(msg, args)
}

// N returns the plural form for n of the message whose English forms are
// one and other, formatted with args (pass n again if the text shows it:
// p.N(n, "%d entry", "%d entries", n)). Every form must use the same
// arguments.
func (p Printer) N(n int, one, other string, args ...any) string {
	if forms, ok := p.catalog().plurals[pluralKey{one, other}]; ok {
		return p.sprintf(forms[pluralForm(p.lang, n)], args)
	}
	if n == 1 || n == -1 {
		return p.sprintf(one, args)
	}
	return p.sprintf(other, args)
}

// Plural forms, the index into a ru or sr catalog entry.
const (
	formOne = iota
	formFew
	formMany
)

// pluralForm returns the CLDR plural form of the integer n in l: formOne or
// formMany (other) in English; formOne, formFew or formMany in Russian and
// Serbian.
func pluralForm(l Lang, n int) int {
	if n < 0 {
		n = -n
	}
	if l == En {
		if n == 1 {
			return formOne
		}
		return formMany
	}
	mod10, mod100 := n%10, n%100
	switch {
	case mod10 == 1 && mod100 != 11:
		return formOne
	case mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14):
		return formFew
	}
	return formMany
}

// lookup returns the translation of msg, or msg.
func (p Printer) lookup(msg string) string {
	if t, ok := p.catalog().msgs[msg]; ok {
		return t
	}
	return msg
}

// catalog returns the merged catalog of p's language (empty for English).
func (p Printer) catalog() *catalog {
	if p.lang < numLangs {
		return &catalogs[p.lang]
	}
	return &catalogs[En]
}

// sprintf formats a looked-up message: plain text without args, otherwise
// fmt.Sprintf with %w read as %v and errors and Localizers rendered in p's
// language.
func (p Printer) sprintf(format string, args []any) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(wToV(format), p.render(args)...)
}

// render returns args with errors and Localizers replaced by their text in
// p's language. Other values are kept, so their verbs (%d, %q, …) work.
func (p Printer) render(args []any) []any {
	out := make([]any, len(args))
	for i, a := range args {
		switch v := a.(type) {
		case error:
			out[i] = p.Error(v)
		case Localizer:
			out[i] = v.Localize(p)
		default:
			out[i] = a
		}
	}
	return out
}

// contextKey is the catalog key of msg in context: context, U+0004, msg
// (gettext's separator). In a catalog file it is written "context\x04msg".
func contextKey(context, msg string) string { return context + "\x04" + msg }
