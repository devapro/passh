package importpass

import (
	"strings"
	"testing"
)

// FuzzParseStatus (TEST-12, CLI-020): gpg's --status-fd output decides
// whether an entry decrypted (S8). parseStatus never panics, never reports
// success without a DECRYPTION_OKAY line or with a failure keyword, and a
// failure always has an explanation. The seed corpus runs in every
// `go test`.
func FuzzParseStatus(f *testing.F) {
	for _, seed := range []string{
		"[GNUPG:] DECRYPTION_OKAY\n",
		"[GNUPG:] DECRYPTION_OKAY\n[GNUPG:] BADMDC\n",
		"[GNUPG:] NO_SECKEY ABCDEF\n[GNUPG:] DECRYPTION_FAILED\n",
		"[GNUPG:] ERROR pkdecrypt_failed 83886179\n",
		"[GNUPG:] FAILURE decrypt 99\n",
		"[GNUPG:] BAD_PASSPHRASE x\r\n[GNUPG:] DECRYPTION_OKAY\r\n",
		"[GNUPG:]  DECRYPTION_OKAY\n",
		"[GNUPG:] \n[GNUPG:]\n",
		"DECRYPTION_OKAY\n",
		"",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		st := parseStatus(b)
		okay, failed := false, false
		for line := range strings.SplitSeq(string(b), "\n") {
			rest, ok := strings.CutPrefix(strings.TrimSuffix(line, "\r"), "[GNUPG:] ")
			if !ok {
				continue
			}
			f := strings.Fields(rest)
			if len(f) == 0 {
				continue
			}
			okay = okay || f[0] == "DECRYPTION_OKAY"
			failed = failed || failureKeywords[f[0]]
		}
		if st.ok() && (!okay || failed) {
			t.Errorf("parseStatus(%q) reports success", b)
		}
		if !st.ok() && st.failure(nil).String() == "" {
			t.Errorf("parseStatus(%q): a failure without an explanation", b)
		}
	})
}
