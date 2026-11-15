//go:build !linux && !darwin

package tty

// fileDevice, pathDevice and controllingDevice are only implemented on
// Linux and macOS, passh's platforms; elsewhere DeviceName finds a device
// only through /proc.
func fileDevice(int) (uint64, bool) { return 0, false }

func pathDevice(string) (uint64, bool) { return 0, false }

func controllingDevice(int) (uint64, bool) { return 0, false }
