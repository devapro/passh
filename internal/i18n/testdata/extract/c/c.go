// Package c imports internal/i18n with a dot, which hides its calls.
package c

import . "example.com/m/internal/i18n"

var errC = NewError("hidden")
