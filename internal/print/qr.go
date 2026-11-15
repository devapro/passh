package print

import (
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

// QRBitmap encodes text as a QR code (error correction level M) and returns
// its modules, quiet zone included: bitmap[y][x] is true for a dark module.
// The PDF and the print page draw the recovery key's QR code from it.
func QRBitmap(text string) ([][]bool, error) {
	q, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		return nil, fmt.Errorf("QR code: %w", err)
	}
	return q.Bitmap(), nil
}
