//go:build !linux && !darwin

package tty

// flushInput is only implemented on Linux and macOS, passh's platforms.
func flushInput(int) error { return nil }
