package vault

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/vaultfile"
)

// containsAll reports each of want that s doesn't contain.
func containsAll(t *testing.T, what, s string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(s, w) {
			t.Errorf("%s: %q doesn't contain %q", what, s, w)
		}
	}
}

// A damaged vault in Russian and Serbian: the message and the heading of
// the backup list are translated, the paths and the backup lines are kept.
func TestDamagedTranslated(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	mustAdd(t, v, "a", "pw") // a save: one automatic backup
	snap := v.Snapshot()
	snap.Revision++
	plain, err := snap.Encode()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := keys.NewVaultKey()
	db, err := keys.EncryptData(other, plain)
	if err != nil {
		t.Fatal(err)
	}
	file, err := vaultfile.Encode(e.keyBlock, db)
	if err != nil {
		t.Fatal(err)
	}
	e.write(file)

	_, err = Open(context.Background(), e.path, checkedSource{keys.FromIdentity(e.key)}, e.opts())
	var oe *OpenError
	if !errors.As(err, &oe) || len(oe.Backups) == 0 {
		t.Fatalf("err = %v", err)
	}
	bk := oe.Backups[0].String()
	ru := i18n.New(i18n.Ru).Error(err)
	containsAll(t, "ru", ru, e.path+": данные повреждены; восстановите резервную копию",
		"автоматические резервные копии этого хранилища, сначала новые:\n  "+bk)
	sr := i18n.New(i18n.Sr).Error(err)
	containsAll(t, "sr", sr, e.path+": podaci su oštećeni; vratite rezervnu kopiju",
		"automatske rezervne kopije ovog trezora, prvo najnovije:\n  "+bk)
	if en := i18n.New(i18n.En).Error(err); en != err.Error() || !strings.Contains(en, "data is damaged; restore a backup") {
		t.Errorf("en: %q", en)
	}

	// With a key from elsewhere: the wrong key, not damage.
	_, err = Open(context.Background(), e.path, keys.FromIdentity(e.key), e.opts())
	if got := i18n.New(i18n.Ru).Error(err); got != e.path+": этот ключ не открывает это хранилище (rekey в другом месте? не тот ключ восстановления?)" {
		t.Errorf("ru: %q", got)
	}
}

// The rollback warning and question are Messages: translated with the
// revisions and dates kept, English as in §4.10.
func TestRollbackTranslated(t *testing.T) {
	e, old := olderCopy(t)
	e.write(old)
	var mu sync.Mutex
	var asked []i18n.Message
	o := e.opts()
	o.Prompt = func(w i18n.Message) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		asked = append(asked, w)
		return true, nil
	}
	if _, err := Open(context.Background(), e.path, keys.FromIdentity(e.key), o); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 {
		t.Fatalf("asked %d times", len(asked))
	}
	day := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC).Format(time.DateOnly)
	if en := asked[0].String(); !strings.HasPrefix(en, "this copy is older than one seen before on this machine (r2 of "+day+"; seen r3 of "+day+").") {
		t.Errorf("en: %q", en)
	}
	containsAll(t, "ru", asked[0].Localize(i18n.New(i18n.Ru)),
		"эта копия старше той, что уже открывалась на этом компьютере (r2 от "+day+"; ранее была r3 от "+day+")")
	containsAll(t, "sr", asked[0].Localize(i18n.New(i18n.Sr)),
		"ova kopija je starija od one koja je ranije viđena na ovom računaru (r2 od "+day+"; viđena je r3 od "+day+")")

	st := RollbackStatus{Revision: 2, SeenRevision: 3, Seen: true}
	if st.Localize(i18n.New(i18n.Sr)) == st.Message() || (RollbackStatus{}).Localize(i18n.New(i18n.Ru)) != "" {
		t.Error("RollbackStatus.Localize")
	}
	if got := i18n.New(i18n.Ru).Error(ErrRollbackDeclined); !strings.HasPrefix(got, "остановлено: ") {
		t.Errorf("ru: %q", got)
	}
}

// Errors of saving: the lock held by another process, a stopped wait (the
// context's own text is kept), and a file kept aside under a temporary name.
func TestSaveErrorsTranslated(t *testing.T) {
	ru, sr := i18n.New(i18n.Ru), i18n.New(i18n.Sr)
	if got := ru.Error(ErrLocked); got != "хранилище сохраняет другой процесс passh; ничего не сохранено: попробуйте ещё раз" {
		t.Errorf("ru: %q", got)
	}
	if got := sr.Error(ErrLocked); got != "drugi passh proces upravo čuva trezor; ništa nije sačuvano: pokušajte ponovo" {
		t.Errorf("sr: %q", got)
	}

	dir := t.TempDir()
	path := dir + "/x.lock"
	held, err := lockFile(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer held.unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = lockFile(ctx, path)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if got := ru.Error(err); got != "ожидание другого процесса passh прервано: context canceled" {
		t.Errorf("ru: %q", got)
	}

	k := keptFile{path: "/v/.vault.passh.tmp-1", temp: true}
	if got := i18n.New(i18n.Sr).Error(i18n.Errorf("%w; a file that was in its place is kept in %s", ErrChanged, k)); !strings.Contains(got,
		"sačuvana je u /v/.vault.passh.tmp-1 (privremeno ime: premestite datoteku") || !strings.HasPrefix(got, "trezor se promenio na disku") {
		t.Errorf("sr: %q", got)
	}
	if k.String() != "/v/.vault.passh.tmp-1 (a temporary name: move it elsewhere before the next save, which would remove it)" {
		t.Errorf("en: %q", k.String())
	}
}

// Text ignored around the vault: the warning names the file and counts the
// lines in the plural form of the language.
func TestWarningsTranslated(t *testing.T) {
	e := newEnv(t)
	e.write(append([]byte("hello\n"), e.read()...))
	var got []i18n.Message
	o := e.opts()
	o.Warn = func(m i18n.Message) { got = append(got, m) }
	v, err := Open(context.Background(), e.path, keys.FromIdentity(e.key), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(v.Info().Warnings) != 1 {
		t.Fatalf("warnings %v, info %v", got, v.Info().Warnings)
	}
	if en := got[0].String(); en != e.path+": ignored 1 line of text before the passh-vault line" {
		t.Errorf("en: %q", en)
	}
	if ru := got[0].Localize(i18n.New(i18n.Ru)); ru != e.path+": проигнорировано до строки passh-vault: 1 строка текста" {
		t.Errorf("ru: %q", ru)
	}
	if sr := v.Info().Warnings[0].Localize(i18n.New(i18n.Sr)); sr != "zanemareno pre reda passh-vault: 1 red teksta" {
		t.Errorf("sr: %q", sr)
	}
}
