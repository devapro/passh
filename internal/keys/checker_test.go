package keys

import "testing"

// Only sources whose key belongs to the key block they are given say so:
// the passphrase does, a paper key (FromIdentity) doesn't.
func TestChecksKeyBlock(t *testing.T) {
	id, err := NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	if !ChecksKeyBlock(&PassphraseSource{}) {
		t.Error("PassphraseSource doesn't check the key block")
	}
	if ChecksKeyBlock(FromIdentity(id)) || ChecksKeyBlock(nil) {
		t.Error("FromIdentity or nil checks the key block")
	}
}
