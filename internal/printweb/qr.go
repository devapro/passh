package printweb

import (
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

// TerminalQR renders s (the page's URL) as a QR code for a terminal, two
// rows of modules per line with half-block characters (▀ ▄ █), quiet zone
// included. Light modules are drawn and dark ones left blank, which suits
// the usual dark terminal background.
func TerminalQR(s string) (string, error) {
	q, err := qrcode.New(s, qrcode.Low)
	if err != nil {
		return "", fmt.Errorf("QR code: %w", err)
	}
	return q.ToSmallString(false), nil
}
