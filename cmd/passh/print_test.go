package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/devapro/passh/internal/clipboard"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/print"
	"github.com/devapro/passh/internal/printweb"
)

func printEntries() []model.Entry {
	return []model.Entry{
		{Path: paths.MustParse("work/github"), Password: "s3cr3t-P@ss", Username: "arsenii", URL: "https://github.com"},
		{Path: paths.MustParse("bank/card"), Password: "0lI1-pin", Tags: []string{"money"}},
	}
}

// TestPrint (§7.2): never to a terminal; the confirmation rules of a
// plaintext export; the text sheet with mode 0600, never overwritten; the
// removed PDF options say why.
func TestPrint(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.withVault()
	e.addEntries(printEntries()...)

	r := e.start(sessOpts{}, "print").wait()
	if r.code != 1 || !strings.Contains(r.out, "refusing to write the sheet to a terminal") {
		t.Errorf("print to a terminal: %s", r)
	}
	r = e.fail(1, "print")
	mustContain(t, "print unconfirmed", r.stderr, "needs confirmation", "--confirm-plaintext")
	e.fail(2, "print", "--fields", "pass word")
	e.fail(2, "print", "--web", "-o", "x")
	// PDF output was removed: the old options say what to do instead.
	for _, args := range [][]string{
		{"print", "--format", "pdf"}, {"print", "--format", "txt", "--confirm-plaintext"},
		{"recovery-key", "print", "--format", "pdf"},
	} {
		r = e.fail(2, args...)
		mustContain(t, strings.Join(args, " "), r.stderr,
			"PDF output was removed; use --web to print from a browser (it can save as PDF), or omit --format for the text sheet")
	}
	r = e.fail(1, "print", "--web")
	mustContain(t, "print --web disabled", r.stderr, "the print page is off")

	e.unlock(fixturePass)
	txt := filepath.Join(e.root, "sheet.txt")
	r = e.ok("print", "--confirm-plaintext", "-o", txt)
	mustContain(t, "print txt", r.stderr, "printed 2 entries (text sheet) to", "delete the file")
	if !onTmpfs(t, txt) {
		mustContain(t, "print txt", r.stderr, "isn't on tmpfs")
	}
	if m := fileMode(t, txt); m != 0o600 {
		t.Errorf("sheet mode %o", m)
	}
	data, _ := os.ReadFile(txt)
	mustContain(t, "txt sheet", string(data), "passh password sheet", "CONFIDENTIAL", "github", "s3cr3t-P@ss", "arsenii", "0lI1-pin")
	r = e.fail(1, "print", "--confirm-plaintext", "-o", txt)
	mustContain(t, "print over a file", r.stderr, "already exists")

	// With a terminal: EXPORT PLAINTEXT on it, the sheet alone on stdout.
	s := e.start(sessOpts{pipeStdout: true}, "print", "--tag", "money", "--fields", "password")
	s.answer("Type EXPORT PLAINTEXT to confirm:", "EXPORT PLAINTEXT")
	r = s.waitOK()
	mustContain(t, "print piped", r.stdout, "card", "0lI1-pin")
	mustNotContain(t, "print piped", r.stdout, "EXPORT PLAINTEXT", "Type", "github", "(text sheet) to")
	r = e.fail(1, "print", "--confirm-plaintext", "--tag", "nope", "-o", filepath.Join(e.root, "none.txt"))
	mustContain(t, "print nothing", r.stderr, "no entries to print")
	e.ok("lock")
}

// sheetKey reads the vault key from a text recovery sheet: the line
// AGE-SECRET-KEY-1 and the lines of four-character groups after it.
func sheetKey(t *testing.T, sheet string) (spaced, bare string) {
	t.Helper()
	group := regexp.MustCompile(`^[02-9AC-HJ-NP-Z]{1,4}( [02-9AC-HJ-NP-Z]{1,4})*$`)
	lines := strings.Split(sheet, "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) != "AGE-SECRET-KEY-1" {
			continue
		}
		key := []string{"AGE-SECRET-KEY-1"}
		for _, g := range lines[i+1:] {
			g = strings.TrimSpace(g)
			if !group.MatchString(g) {
				break
			}
			key = append(key, g)
		}
		spaced = strings.Join(key, "\n")
		return spaced, strings.ReplaceAll(strings.ReplaceAll(spaced, "\n", ""), " ", "")
	}
	t.Fatalf("no key in the sheet:\n%s", sheet)
	return "", ""
}

// TestRecoverySheet (§5.4): recovery-key print needs a terminal and PRINT
// RECOVERY KEY; the sheet holds the key and never the recipient.
// Functional criterion 9 (paper key path of §8 with the stock age tool) and
// criterion 10 (recover with the key from the sheet).
func TestRecoverySheet(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.withVault()
	e.addEntries(printEntries()...)
	out := filepath.Join(e.root, "key.txt")

	r := e.fail(1, "recovery-key", "print", "-o", out)
	mustContain(t, "without a terminal", r.stderr, "needs a terminal")
	e.fail(2, "recovery-key", "print", "--web", "-o", out)
	s := e.start(sessOpts{}, "recovery-key", "print", "-o", out)
	s.answer("Type PRINT RECOVERY KEY to confirm:", "print recovery key")
	if r = s.wait(); r.code != 1 || !strings.Contains(r.out, "not confirmed") {
		t.Errorf("wrong phrase: %s", r)
	}
	r = e.start(sessOpts{}, "recovery-key", "print").wait()
	if r.code != 1 || !strings.Contains(r.out, "refusing to write the recovery key to a terminal") {
		t.Errorf("to a terminal: %s", r)
	}

	// The key comes from the usual chain: here the passphrase.
	s = e.start(sessOpts{}, "recovery-key", "print", "-o", out)
	s.answer("Type PRINT RECOVERY KEY to confirm:", "PRINT RECOVERY KEY")
	s.answer("Passphrase:", fixturePass)
	r = s.waitOK()
	mustContain(t, "recovery-key print", r.out, "Wrote the paper recovery key to", "delete the file")
	if m := fileMode(t, out); m != 0o600 {
		t.Errorf("sheet mode %o", m)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	sheet := string(data)
	mustNotContain(t, "sheet", sheet, "age1", fixtureKey.Recipient().String())
	spaced, bare := sheetKey(t, sheet)
	if bare != fixtureKey.String() {
		t.Fatalf("sheet key %q, want the vault key", bare)
	}
	cmds := print.RecoveryCommandList()
	for _, c := range cmds {
		mustContain(t, "sheet commands", sheet, c)
	}

	// CLI-001: with stdout redirected, the file holds the sheet and nothing
	// else; the confirmation goes to stderr (here the terminal).
	s = e.start(sessOpts{pipeStdout: true}, "recovery-key", "print")
	s.answer("Type PRINT RECOVERY KEY to confirm:", "PRINT RECOVERY KEY")
	s.answer("Passphrase:", fixturePass)
	r = s.waitOK()
	mustContain(t, "recovery-key print > file", r.out, "Wrote the paper recovery key to stdout.")
	if r.stdout != sheet {
		t.Errorf("redirected sheet differs from the -o file:\n%q\nwant\n%q", r.stdout, sheet)
	}

	// Criterion 9, paper key: write the key as one line, then run the
	// second, fourth and fifth commands of §8 (paths on /dev/shm moved into
	// the test folder) with the stock age tool.
	ageBin, err := filepath.Abs("../../.tools/bin/age")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ageBin); err != nil {
		t.Skip("no stock age tool in .tools/bin")
	}
	work := filepath.Join(e.root, "manual")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	vaultData, _ := os.ReadFile(e.vault)
	writeFile(t, filepath.Join(work, "vault.passh"), string(vaultData))
	writeFile(t, filepath.Join(work, "key.txt"), bare+"\n")
	for _, c := range []string{cmds[1], cmds[3], cmds[4]} {
		c = strings.ReplaceAll(c, "/dev/shm/", work+"/")
		c = strings.Replace(c, "age -d", ageBin+" -d", 1)
		cmd := exec.Command("sh", "-c", c)
		cmd.Dir = work
		cmd.Env = e.vars
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", c, err, out)
		}
	}
	plain, err := os.ReadFile(filepath.Join(work, "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, "vault.json", string(plain), `"format": "passh-vault-data"`, `"path": "work/github"`, `"password": "s3cr3t-P@ss"`)
	if _, err := os.Stat(filepath.Join(work, "key.txt")); err == nil {
		t.Error("the fifth command didn't remove key.txt")
	}

	// Criterion 10: recover with the key as printed (groups, lines).
	const pass = "orchard pebble lantern nimbus ribbon falcon"
	s = e.start(sessOpts{}, "recover")
	s.expectSecretPrompt("> ")
	s.send(strings.ReplaceAll(spaced, "\n", "\r") + "\r\r")
	s.answer("New passphrase:", pass)
	s.answer("Repeat passphrase:", pass)
	r = s.waitOK()
	mustContain(t, "recover", r.out, "New passphrase set", "> **** ****")
	// CLI-005: the typed key never shows on the terminal, so it can't stay
	// in the scrollback.
	mustNotContain(t, "recover", r.out, bare)
	for _, l := range strings.Split(spaced, "\n") {
		if !strings.HasPrefix(l, "AGE-") { // the prefix is in the prompt
			mustNotContain(t, "recover", r.out, l)
		}
	}
	s = e.start(sessOpts{pipeStdout: true}, "show", "work/github", "--field", "password")
	s.answer("Passphrase:", pass)
	if r = s.waitOK(); r.stdout != "s3cr3t-P@ss" {
		t.Errorf("after recover: %q", r.stdout)
	}
}

// privateIPv4 finds a local interface with an RFC 1918 IPv4 address.
func privateIPv4() (name string, addr netip.Addr) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", netip.Addr{}
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err == nil && p.Addr().Is4() && p.Addr().IsPrivate() {
				return ifc.Name, p.Addr()
			}
		}
	}
	return "", netip.Addr{}
}

// freePort asks the system for a free TCP port on addr.
func freePort(t *testing.T, addr netip.Addr) int {
	t.Helper()
	ln, err := net.Listen("tcp", netip.AddrPortFrom(addr, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

var urlRE = regexp.MustCompile(`https://[0-9.]+:[0-9]+/p/[A-Za-z0-9_-]+`)

// TestPrintWeb (§7.4, safety test 7 at the CLI): the print page binds only
// private addresses; with one, a real fetch over TLS 1.3 gets the page once,
// with the §7.4 headers and the fingerprint passh showed; c copies the URL,
// Esc stops.
func TestPrintWeb(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.withVault()
	e.addEntries(printEntries()...)
	e.writeConfig("[print_web]\nenabled = true\ninterfaces = [\"lo\"]\nttl = \"1m\"\n")
	e.unlock(fixturePass)

	// Loopback isn't a private address: refused.
	s := e.start(sessOpts{}, "print", "--web")
	s.answer("Type PRINT to confirm:", "PRINT")
	if r := s.wait(); r.code != 1 || !strings.Contains(r.out, "no private address to listen on") {
		t.Errorf("print --web on lo: %s", r)
	}
	e.fail(1, "print", "--web") // needs a terminal

	ifc, addr := privateIPv4()
	if ifc == "" {
		e.ok("lock")
		t.Skip("no interface with an RFC 1918 address: the fetch test needs one")
	}
	conf := func() {
		e.writeConfig(fmt.Sprintf("[clipboard]\nclear_after = \"1m\"\n[print_web]\nenabled = true\ninterfaces = [%q]\nport = %d\nttl = \"1m\"\n",
			ifc, freePort(t, addr)))
	}

	// A real fetch.
	conf()
	s = e.start(sessOpts{}, "print", "--web", "--fields", "password,username")
	s.answer("Type PRINT to confirm:", "PRINT")
	s.expect("stops after one load or in ")
	out := s.output()
	url := urlRE.FindString(out)
	fp := regexp.MustCompile(`certificate SHA-256  ([0-9A-F:]+)`).FindStringSubmatch(out)
	if url == "" || fp == nil {
		t.Fatalf("no URL or fingerprint in:\n%s", out)
	}
	mustContain(t, "print page", out, "▀", "Esc stops") // the QR code
	var seenFP string
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, // a self-signed certificate: the fingerprint is checked instead
		VerifyConnection: func(cs tls.ConnectionState) error {
			seenFP = printweb.Fingerprint(cs.PeerCertificates[0].Raw)
			return nil
		},
	}}}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.TLS.Version != tls.VersionTLS13 || seenFP != fp[1] {
		t.Errorf("status %d, TLS %x, fingerprint %s (shown %s)", resp.StatusCode, resp.TLS.Version, seenFP, fp[1])
	}
	for h, want := range map[string]string{
		"Cache-Control":          "no-store",
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := resp.Header.Get(h); got != want {
			t.Errorf("%s: %q, want %q", h, got, want)
		}
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.HasPrefix(csp, "default-src 'none'") {
		t.Errorf("CSP %q", csp)
	}
	mustContain(t, "page", string(body), "passh password sheet", "github", "s3cr3t-P@ss", "arsenii")
	r := s.waitOK()
	mustContain(t, "print --web", r.out, "Done: the page was served to "+addr.String())
	if _, err := client.Get(url); err == nil {
		t.Error("the page was served twice")
	}

	// c copies the URL (OSC 52 here), Esc stops; the copy is cleared.
	conf()
	s = e.start(sessOpts{}, "recovery-key", "print", "--web")
	s.answer("Type PRINT RECOVERY KEY to confirm:", "PRINT RECOVERY KEY")
	s.expect("stops after one load or in ")
	url = urlRE.FindString(s.output())
	s.send("c")
	s.expect("URL copied")
	s.send("\x1b")
	r = s.wait()
	if r.code != 1 || !strings.Contains(r.out, "the print page was stopped") {
		t.Errorf("Esc: %s", r)
	}
	mustContain(t, "c", r.out, string(clipboard.OSC52(url)), string(clipboard.OSC52("")))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if req, _ := http.NewRequestWithContext(ctx, "GET", url, nil); req != nil {
		if _, err := client.Do(req); err == nil {
			t.Error("the page still answers after Esc")
		}
	}
	e.ok("lock")
}
