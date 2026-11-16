//go:build !linux && !darwin

package cli

import "github.com/devapro/passh/internal/i18n"

func memoryCheck(p i18n.Printer) (level, string) {
	return levelSkip, p.T("not checked on this system")
}

func swapCheck(p i18n.Printer) (level, string) {
	return levelSkip, p.T("not checked on this system")
}

func onTmpfs(string) bool { return false }
