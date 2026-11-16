// Package b has a constant and a wrapper used by package a.
package b

import "example.com/m/internal/i18n"

// Shared is used by package a.
const Shared = "shared constant"

// Warnf passes its message on.
//
// i18n:wrapper
func Warnf(format string, args ...any) { _ = i18n.Msg(format, args...) }

// bad is marked but has no message parameter.
//
// i18n:wrapper
func bad(x string) { _ = x }

func local() { Warnf("local call %s", "x") }
