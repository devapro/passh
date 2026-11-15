//go:build !linux

package editor

// onTmpfs is false outside Linux: macOS has no tmpfs, and other systems
// aren't checked, so `edit --editor` falls back to the form there (S1).
func onTmpfs(string) bool { return false }
