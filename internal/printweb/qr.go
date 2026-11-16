package printweb

import (
	qrcode "github.com/skip2/go-qrcode"

	"github.com/devapro/passh/internal/i18n"
)

// TerminalQR renders s (the page's URL) as a QR code for a terminal, two
// rows of modules per line with half-block characters (▀ ▄ █), quiet zone
// included. Light modules are drawn and dark ones left blank, which suits
// the usual dark terminal background.
func TerminalQR(s string) (string, error) {
	q, err := qrcode.New(s, qrcode.Low)
	if err != nil {
		return "", i18n.Errorf("QR code: %w", err)
	}
	return q.ToSmallString(false), nil
}
