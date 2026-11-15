//go:build !linux && !darwin

package cli

func memoryCheck() (level, string) {
	return levelSkip, "not checked on this system"
}

func swapCheck() (level, string) {
	return levelSkip, "not checked on this system"
}

func onTmpfs(string) bool { return false }
