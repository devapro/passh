package keys

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// productionWorkFactor is scryptWorkFactor as the package defines it, before
// TestMain lowers it.
var productionWorkFactor = scryptWorkFactor

// testWorkFactor keeps scrypt cheap in tests (2^10: about a millisecond).
const testWorkFactor = 10

func TestMain(m *testing.M) {
	scryptWorkFactor = testWorkFactor
	os.Exit(m.Run())
}

func mustKey(t testing.TB) *age.X25519Identity {
	t.Helper()
	id, err := NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustWrap(t testing.TB, id *age.X25519Identity, pass string) []byte {
	t.Helper()
	kb, err := WrapKey(id, []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	return kb
}

// scryptBlock encrypts plaintext with a passphrase directly through age, for
// key blocks passh would never write.
func scryptBlock(t testing.TB, pass string, logN int, plaintext []byte) []byte {
	t.Helper()
	r, err := age.NewScryptRecipient(pass)
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkFactor(logN)
	out, err := encrypt(r, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// recipientString is the S9 secret: the vault key's public recipient.
// Only tests compute it, to check it never shows up anywhere.
func recipientString(id *age.X25519Identity) string { return id.Recipient().String() }

func TestProductionWorkFactorIs18(t *testing.T) {
	if productionWorkFactor != 18 {
		t.Fatalf("scryptWorkFactor = %d, want 18 (§4.1)", productionWorkFactor)
	}
}

func TestNewVaultKeyIsRandom(t *testing.T) {
	a, b := mustKey(t), mustKey(t)
	if a.String() == b.String() {
		t.Fatal("two vault keys are equal")
	}
	if !strings.HasPrefix(a.String(), "AGE-SECRET-KEY-1") {
		t.Fatalf("unexpected key format")
	}
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	id := mustKey(t)
	kb := mustWrap(t, id, "correct horse battery staple")
	got, err := UnwrapKey(kb, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != id.String() {
		t.Fatal("unwrapped key differs")
	}
	if !strings.Contains(string(kb), " "+strconv.Itoa(testWorkFactor)+"\n") {
		t.Fatalf("key block doesn't use the package work factor:\n%s", headerOf(kb))
	}
}

// TestWrapAtRealWorkFactor runs scrypt at 2^18 once, as production does.
func TestWrapAtRealWorkFactor(t *testing.T) {
	if testing.Short() {
		t.Skip("scrypt at 2^18 is slow")
	}
	scryptWorkFactor = productionWorkFactor
	t.Cleanup(func() { scryptWorkFactor = testWorkFactor })

	id := mustKey(t)
	start := time.Now()
	kb := mustWrap(t, id, "orbit velvet cactus lumen harbor quill")
	got, err := UnwrapKey(kb, []byte("orbit velvet cactus lumen harbor quill"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("wrap + unwrap at 2^18: %v", time.Since(start))
	if got.String() != id.String() {
		t.Fatal("unwrapped key differs")
	}
	hdr := headerOf(kb)
	lines := strings.Split(hdr, "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[1], "-> scrypt ") || !strings.HasSuffix(lines[1], " 18") {
		t.Fatalf("key block header doesn't carry work factor 18:\n%s", hdr)
	}
}

func TestKeyBlockIsAgeIdentityFile(t *testing.T) {
	id := mustKey(t)
	kb := mustWrap(t, id, "pass")
	sid, err := age.NewScryptIdentity("pass")
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(bytes.NewReader(kb), sid)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != id.String()+"\n" {
		t.Fatal("key block plaintext isn't the identity plus newline")
	}
	ids, err := age.ParseIdentities(bytes.NewReader(plain))
	if err != nil || len(ids) != 1 {
		t.Fatalf("not a valid age identity file: %v", err)
	}
}

func TestWrapErrors(t *testing.T) {
	if _, err := WrapKey(mustKey(t), nil); !errors.Is(err, ErrEmptyPassphrase) {
		t.Fatalf("empty passphrase: %v", err)
	}
	if _, err := WrapKey(nil, []byte("x")); err == nil {
		t.Fatal("nil key accepted")
	}
}

func TestUnwrapWrongPassphrase(t *testing.T) {
	kb := mustWrap(t, mustKey(t), "right")
	_, err := UnwrapKey(kb, []byte("wrong"))
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("got %v", err)
	}
	if err.Error() != "wrong passphrase, or the key block is damaged" {
		t.Fatalf("message %q", err)
	}
	if _, err := UnwrapKey(kb, nil); !errors.Is(err, ErrEmptyPassphrase) {
		t.Fatalf("empty passphrase: %v", err)
	}
	for _, junk := range [][]byte{nil, {}, []byte("age-encryption.org/v1\n"), []byte("garbage")} {
		if _, err := UnwrapKey(junk, []byte("right")); !errors.Is(err, ErrWrongPassphrase) {
			t.Fatalf("junk key block %q: %v", junk, err)
		}
	}
}

func TestUnwrapDamagedKeyBlock(t *testing.T) {
	id := mustKey(t)
	kb := mustWrap(t, id, "pass")
	for i := range kb {
		for _, mask := range []byte{0x01, 0x80} {
			bad := bytes.Clone(kb)
			bad[i] ^= mask
			got, err := UnwrapKey(bad, []byte("pass"))
			if !errors.Is(err, ErrWrongPassphrase) || got != nil {
				t.Fatalf("flip %#x at %d: key=%v err=%v", mask, i, got != nil, err)
			}
		}
	}
	for n := range len(kb) {
		if got, err := UnwrapKey(kb[:n], []byte("pass")); !errors.Is(err, ErrWrongPassphrase) || got != nil {
			t.Fatalf("truncated at %d: %v", n, err)
		}
	}
	if _, err := UnwrapKey(append(bytes.Clone(kb), 0), []byte("pass")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("extended key block: %v", err)
	}
}

// withWorkFactor returns a key block like kb (made by mustWrap at
// testWorkFactor) whose scrypt stanza asks for 2^logN instead. Its MAC no
// longer matches, which only scrypt at 2^logN would find out.
func withWorkFactor(t *testing.T, kb []byte, logN int) []byte {
	t.Helper()
	old := " " + strconv.Itoa(testWorkFactor) + "\n"
	if !bytes.Contains(kb, []byte(old)) {
		t.Fatalf("work factor not found in header:\n%s", headerOf(kb))
	}
	return bytes.Replace(kb, []byte(old), []byte(" "+strconv.Itoa(logN)+"\n"), 1)
}

func TestMaxWorkFactorIs18(t *testing.T) {
	if maxWorkFactor != productionWorkFactor || maxWorkFactor != 18 {
		t.Fatalf("maxWorkFactor = %d, want 18, the factor passh writes (§4.1, INV-10)", maxWorkFactor)
	}
}

// TestUnwrapRefusesWorkFactorAbove18 (INV-10): a key block asking for more
// scrypt work than passh ever writes is refused before scrypt runs (the
// refusal comes from workFactorCheck, ahead of age's identity), with a
// message that names the factor, and is not retried as a wrong
// passphrase.
func TestUnwrapRefusesWorkFactorAbove18(t *testing.T) {
	kb := mustWrap(t, mustKey(t), "pass")
	for _, logN := range []int{19, 22, 23, 30} {
		_, err := UnwrapKey(withWorkFactor(t, kb, logN), []byte("pass"))
		if !errors.Is(err, ErrWorkFactor) || errors.Is(err, ErrWrongPassphrase) {
			t.Fatalf("2^%d: got %v, want ErrWorkFactor", logN, err)
		}
		want := "key block asks for scrypt work factor 2^" + strconv.Itoa(logN) +
			"; passh uses 2^18: the file is damaged or not made by passh"
		if err.Error() != want {
			t.Fatalf("2^%d: message %q, want %q", logN, err, want)
		}
	}

	// A 2^19 key block, as another age tool could make it: the header is
	// built here instead of running scrypt at 2^19 (512 MiB) in a test.
	kb19 := withWorkFactor(t, kb, 19)
	if !strings.HasSuffix(strings.Split(headerOf(kb19), "\n")[1], " 19") {
		t.Fatalf("not a 2^19 stanza:\n%s", headerOf(kb19))
	}
	asked := 0
	src := &PassphraseSource{Attempts: 3, Read: func(string) ([]byte, error) {
		asked++
		return []byte("pass"), nil
	}}
	if _, err := src.VaultKey(context.Background(), kb19); !errors.Is(err, ErrWorkFactor) || asked != 1 {
		t.Fatalf("PassphraseSource: %v after %d prompts, want ErrWorkFactor after 1", err, asked)
	}

	// Up to 2^18 the stanza goes on to age (here: the right passphrase at
	// the factor the block was made with).
	if _, err := UnwrapKey(kb, []byte("pass")); err != nil {
		t.Fatalf("2^%d: %v", testWorkFactor, err)
	}
}

func TestUnwrapNotVaultKey(t *testing.T) {
	a, b := mustKey(t), mustKey(t)
	hybrid, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"empty":         "",
		"comment only":  "# nothing here\n",
		"two keys":      a.String() + "\n" + b.String() + "\n",
		"garbage":       "hello world\n",
		"lower case":    strings.ToLower(a.String()) + "\n",
		"hybrid key":    hybrid.String() + "\n",
		"bad checksum":  a.String()[:len(a.String())-1] + "Q\n",
		"recipient":     recipientString(a) + "\n",
		"key plus junk": a.String() + "\nAGE-SECRET-KEY-1JUNK\n",
	}
	if strings.HasSuffix(a.String(), "Q") {
		bad["bad checksum"] = a.String()[:len(a.String())-1] + "P\n"
	}
	for name, plain := range bad {
		kb := scryptBlock(t, "pass", testWorkFactor, []byte(plain))
		got, err := UnwrapKey(kb, []byte("pass"))
		if !errors.Is(err, ErrNotVaultKey) || got != nil {
			t.Errorf("%s: got %v", name, err)
		}
	}
	big := scryptBlock(t, "pass", testWorkFactor, bytes.Repeat([]byte("#"), maxKeyPlaintext+1))
	if _, err := UnwrapKey(big, []byte("pass")); !errors.Is(err, ErrNotVaultKey) {
		t.Errorf("oversized plaintext: %v", err)
	}

	// A hand-made key block (age-keygen output, CRLF) is a valid identity file.
	good := "# created: 2026-11-15T12:00:00Z\r\n\r\n" + a.String() + "\r\n"
	kb := scryptBlock(t, "pass", testWorkFactor, []byte(good))
	got, err := UnwrapKey(kb, []byte("pass"))
	if err != nil || got.String() != a.String() {
		t.Fatalf("identity file with comments: %v", err)
	}
}

func TestDataRoundTrip(t *testing.T) {
	id := mustKey(t)
	for _, size := range []int{0, 1, 1000, 64 * 1024, 64*1024 + 1, 200_000} {
		plain := bytes.Repeat([]byte("x"), size)
		db, err := EncryptData(id, plain)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecryptData(id, db)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("size %d: plaintext differs", size)
		}
	}
}

func TestDataOtherKeyRejected(t *testing.T) {
	db, err := EncryptData(mustKey(t), []byte(`{"format":"passh-vault-data"}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptData(mustKey(t), db)
	if !errors.Is(err, ErrKeyMismatch) || !errors.Is(err, ErrDataDamaged) || got != nil {
		t.Fatalf("got %v", err)
	}
	// A passphrase-encrypted block in the data position is rejected too.
	if _, err := DecryptData(mustKey(t), mustWrap(t, mustKey(t), "pass")); !errors.Is(err, ErrDataDamaged) {
		t.Fatalf("scrypt data block: %v", err)
	}
}

func TestDataDamaged(t *testing.T) {
	id := mustKey(t)
	db, err := EncryptData(id, []byte(`{"entries":[{"password":"s3cr3t"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	for i := range db {
		for _, mask := range []byte{0x01, 0x80} {
			bad := bytes.Clone(db)
			bad[i] ^= mask
			got, err := DecryptData(id, bad)
			if !errors.Is(err, ErrDataDamaged) || got != nil {
				t.Fatalf("flip %#x at %d: data=%q err=%v", mask, i, got, err)
			}
		}
	}
	for n := range len(db) {
		if got, err := DecryptData(id, db[:n]); !errors.Is(err, ErrDataDamaged) || got != nil {
			t.Fatalf("truncated at %d: data=%q err=%v", n, got, err)
		}
	}
	if _, err := DecryptData(id, append(bytes.Clone(db), 0)); !errors.Is(err, ErrDataDamaged) {
		t.Fatalf("extended data block: %v", err)
	}
	if _, err := DecryptData(nil, db); err == nil {
		t.Fatal("nil key accepted")
	}
	if _, err := EncryptData(nil, nil); err == nil {
		t.Fatal("nil key accepted")
	}
}

// TestDataDamagedMultiChunk: damage in a middle chunk of a large data block
// is caught, and nothing is returned.
func TestDataDamagedMultiChunk(t *testing.T) {
	id := mustKey(t)
	db, err := EncryptData(id, bytes.Repeat([]byte("y"), 3*64*1024))
	if err != nil {
		t.Fatal(err)
	}
	for _, off := range []int{len(db) / 2, len(db) - 100, len(db) - 1} {
		bad := bytes.Clone(db)
		bad[off] ^= 0x01
		if got, err := DecryptData(id, bad); !errors.Is(err, ErrDataDamaged) || got != nil {
			t.Fatalf("flip at %d: %v", off, err)
		}
	}
	// Dropping a whole final chunk leaves a well-formed but truncated stream.
	if got, err := DecryptData(id, db[:len(db)-(64*1024+16)]); !errors.Is(err, ErrDataDamaged) || got != nil {
		t.Fatalf("chunk dropped: %v", err)
	}
}

// TestRecipientNeverWritten (S9): no output of this package contains the
// vault key's recipient.
func TestRecipientNeverWritten(t *testing.T) {
	id := mustKey(t)
	rcpt := recipientString(id)
	db, err := EncryptData(id, []byte(rcpt[:10]))
	if err != nil {
		t.Fatal(err)
	}
	kb := mustWrap(t, id, "pass")
	for name, out := range map[string]string{
		"data block":   string(db),
		"key block":    string(kb),
		"recovery key": FormatRecoveryKey(id),
	} {
		if strings.Contains(strings.ToLower(out), rcpt) {
			t.Errorf("%s contains the recipient", name)
		}
	}
}

func headerOf(block []byte) string {
	h, err := age.ExtractHeader(bytes.NewReader(block))
	if err != nil {
		return "(bad header: " + err.Error() + ")"
	}
	return string(h)
}

func TestZero(t *testing.T) {
	b := []byte("secret")
	Zero(b)
	if !bytes.Equal(b, make([]byte, 6)) {
		t.Fatal("not zeroed")
	}
	Zero(nil)
}

func TestFromIdentity(t *testing.T) {
	id := mustKey(t)
	got, err := FromIdentity(id).VaultKey(context.Background(), nil)
	if err != nil || got != id {
		t.Fatalf("got %v", err)
	}
	if _, err := FromIdentity(nil).VaultKey(context.Background(), nil); err == nil {
		t.Fatal("nil key accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FromIdentity(id).VaultKey(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}
}

func TestPassphraseSource(t *testing.T) {
	id := mustKey(t)
	kb := mustWrap(t, id, "right")

	var given [][]byte
	var prompts []string
	reader := func(answers ...string) func(string) ([]byte, error) {
		return func(prompt string) ([]byte, error) {
			prompts = append(prompts, prompt)
			if len(given) == len(answers) {
				return nil, errors.New("no more answers")
			}
			b := []byte(answers[len(given)])
			given = append(given, b)
			return b, nil
		}
	}
	reset := func() { given, prompts = nil, nil }

	// Right passphrase: key returned, passphrase zeroed, default prompt.
	got, err := (&PassphraseSource{Read: reader("right")}).VaultKey(context.Background(), kb)
	if err != nil || got.String() != id.String() {
		t.Fatalf("got %v", err)
	}
	if prompts[0] != DefaultPrompt {
		t.Fatalf("prompt %q", prompts[0])
	}
	assertZeroed(t, given)

	// Wrong once, then right, with three attempts and a custom prompt.
	reset()
	src := &PassphraseSource{Read: reader("wrong", "right"), Prompt: "Vault passphrase: ", Attempts: 3}
	got, err = src.VaultKey(context.Background(), kb)
	if err != nil || got.String() != id.String() || len(prompts) != 2 || prompts[1] != "Vault passphrase: " {
		t.Fatalf("retry: %v, prompts %q", err, prompts)
	}
	assertZeroed(t, given)

	// Out of attempts.
	reset()
	src = &PassphraseSource{Read: reader("a", "b", "c"), Attempts: 2}
	if _, err := src.VaultKey(context.Background(), kb); !errors.Is(err, ErrWrongPassphrase) || len(given) != 2 {
		t.Fatalf("attempts: %v after %d", err, len(given))
	}
	assertZeroed(t, given)

	// Reader error.
	reset()
	if _, err := (&PassphraseSource{Read: reader()}).VaultKey(context.Background(), kb); err == nil ||
		!strings.Contains(err.Error(), "no more answers") {
		t.Fatalf("reader error: %v", err)
	}

	// A key block that decrypts to something else isn't retried.
	reset()
	odd := scryptBlock(t, "right", testWorkFactor, []byte("not a key\n"))
	src = &PassphraseSource{Read: reader("right", "right"), Attempts: 3}
	if _, err := src.VaultKey(context.Background(), odd); !errors.Is(err, ErrNotVaultKey) || len(given) != 1 {
		t.Fatalf("not a key: %v after %d", err, len(given))
	}

	// Canceled context: no prompt.
	reset()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (&PassphraseSource{Read: reader("right")}).VaultKey(ctx, kb); !errors.Is(err, context.Canceled) || len(prompts) != 0 {
		t.Fatalf("canceled: %v", err)
	}

	var nilSrc *PassphraseSource
	if _, err := nilSrc.VaultKey(context.Background(), kb); err == nil {
		t.Fatal("nil source accepted")
	}
}

func assertZeroed(t *testing.T, bufs [][]byte) {
	t.Helper()
	for i, b := range bufs {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatalf("passphrase %d not zeroed", i)
		}
	}
}

var _ KeySource = (*PassphraseSource)(nil)
var _ KeySource = FromIdentity(nil)
