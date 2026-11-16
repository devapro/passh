package print

import (
	qrcode "github.com/skip2/go-qrcode"

	"github.com/devapro/passh/internal/i18n"
)

// QRBitmap encodes text as a QR code (error correction level M) and returns
// its modules, quiet zone included: bitmap[y][x] is true for a dark module.
// The print page draws the recovery key's QR code from it.
func QRBitmap(text string) ([][]bool, error) {
	q, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		return nil, i18n.Errorf("QR code: %w", err)
	}
	return q.Bitmap(), nil
}
