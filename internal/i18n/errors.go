package i18n

import (
	"fmt"
	"strings"
)

// Localizer is implemented by values that render themselves in a language:
// typed errors with fields or several lines (vault.OpenError), descriptions
// such as a print page's result, and [Message]. [Printer.Error] and the
// argument rendering of [Printer.T] use it.
//
// An error that implements Localizer should return from Localize(Printer{})
// the same text as from Error, which stays English.
type Localizer interface {
	Localize(p Printer) string
}

// NewError returns a sentinel error with the English text msg, like
// errors.New: each call returns a distinct error, matched by identity
// (errors.Is). [Printer.Error] translates msg. msg is plain text, not a
// format.
func NewError(msg string) error { return &textError{msg: msg} }

type textError struct{ msg string }

func (e *textError) Error() string { return e.msg }

// Localize implements [Localizer].
func (e *textError) Localize(p Printer) string { return p.T(e.msg) }

// Errorf is fmt.Errorf whose message [Printer.Error] can translate. The
// result's Error, Unwrap and errors.Is/As behave exactly as those of
// fmt.Errorf(format, args...): one %w gives Unwrap() error, several give
// Unwrap() []error, and the text is English. Localized, format is looked
// up in the catalog and the arguments that are errors or [Localizer]s are
// rendered in the language too.
//
// The error keeps args to render them later, so, like the message itself,
// they must hold no secret (SEC-3).
func Errorf(format string, args ...any) error {
	err := fmt.Errorf(format, args...)
	f := formatted{format: format, args: args, err: err}
	switch u := err.(type) { //nolint:errorlint // inspects the value fmt.Errorf just made, not a wrapped error
	case interface{ Unwrap() error }:
		return &wrapError{formatted: f, wrapped: u.Unwrap()}
	case interface{ Unwrap() []error }:
		return &wrapErrors{formatted: f, wrapped: u.Unwrap()}
	}
	return &f
}

// formatted is an Errorf error without %w.
type formatted struct {
	format string
	args   []any
	err    error // what fmt.Errorf made: the English text
}

func (e *formatted) Error() string { return e.err.Error() }

// Localize implements [Localizer]. Like fmt.Errorf, it always formats,
// even without args.
func (e *formatted) Localize(p Printer) string {
	return fmt.Sprintf(wToV(p.lookup(e.format)), p.render(e.args)...)
}

// wrapError is an Errorf error with one %w.
type wrapError struct {
	formatted
	wrapped error
}

func (e *wrapError) Unwrap() error { return e.wrapped }

// wrapErrors is an Errorf error with several %w.
type wrapErrors struct {
	formatted
	wrapped []error
}

func (e *wrapErrors) Unwrap() []error { return e.wrapped }

// Error renders err in p's language (nil gives ""):
//
//   - in English, err.Error(): English output never changes;
//   - a [Localizer] renders itself (the errors of NewError and Errorf, and
//     typed errors that implement Localize);
//   - an error whose whole text is a catalog key gets its translation
//     (errors from code that only has the text, e.g. the agent's answers);
//   - an error that wraps another one whose text ends its own ("context:
//     cause", as fmt.Errorf("context: %w", err) makes) keeps the context
//     and renders the cause; errors.Join's lines are rendered one by one;
//   - anything else, e.g. an operating system error, stays as it is.
func (p Printer) Error(err error) string {
	if err == nil {
		return ""
	}
	if p.lang == En {
		return err.Error()
	}
	if l, ok := err.(Localizer); ok { // the outermost error renders the chain itself
		return l.Localize(p)
	}
	text := err.Error()
	if t, ok := p.catalog().msgs[text]; ok {
		return t
	}
	switch u := err.(type) { //nolint:errorlint // walks the chain one level at a time on purpose
	case interface{ Unwrap() error }:
		in := u.Unwrap()
		if in == nil {
			break
		}
		if it := in.Error(); it != "" && strings.HasSuffix(text, it) {
			return text[:len(text)-len(it)] + p.Error(in)
		}
	case interface{ Unwrap() []error }:
		errs := u.Unwrap()
		texts := make([]string, len(errs))
		for i, e := range errs {
			if e == nil {
				return text
			}
			texts[i] = e.Error()
		}
		if strings.Join(texts, "\n") != text {
			break
		}
		for i, e := range errs {
			texts[i] = p.Error(e)
		}
		return strings.Join(texts, "\n")
	}
	return text
}

// Message is text for people whose translation waits for a [Printer]: what
// a package without a Printer hands to one that has one, such as a
// warning (vault.Options.Warn) or a question (vault.Options.Prompt). Its
// String is the English text. The zero Message is empty.
type Message struct {
	format string
	args   []any
	raw    bool
}

// Msg returns a Message: format and args as for [Printer.T]. It keeps args
// until the Message is rendered; they must hold no secret (SEC-3).
func Msg(format string, args ...any) Message { return Message{format: format, args: args} }

// Raw returns a Message that is shown as text in every language: data, a
// name, an operating system's message. It is never a catalog key.
func Raw(text string) Message { return Message{format: text, raw: true} }

// Mark returns msg unchanged. It marks msg as a catalog key where it is
// written, for text kept in a string and translated later with an
// i18n:dynamic call (a table of key help, a reason stored in an error
// field, an answer read from the agent's socket).
func Mark(msg string) string { return msg }

// String returns the English text.
func (m Message) String() string { return m.Localize(Printer{}) }

// Localize implements [Localizer].
func (m Message) Localize(p Printer) string {
	if m.raw {
		return m.format
	}
	return p.T(m.format, m.args...)
}

// IsZero reports whether m is the zero (empty) Message.
func (m Message) IsZero() bool { return m.format == "" && len(m.args) == 0 }
