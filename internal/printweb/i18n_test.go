package printweb

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/print"
)

// pageLang is what the print page shows in one language (§3.3).
type pageLang struct {
	lang      i18n.Lang
	attr      string // <html lang>
	title     string
	tip       string // the start of the printing tip
	printed   string
	legend    string // the start of the legend
	notice    string // CertNotice on first use
	skipped   string // Skipped for a public address
	served    string // Result.Localize, Served
	used      string // the answer to a second request
	misdirect string // the answer to an unknown Host
	qrLabel   string
	heading   string // a heading of the recovery sheet
	comment   string // the shell comment of the third recovery command
}

var pageLangs = []pageLang{
	{
		lang: i18n.En, attr: "en", title: "CONFIDENTIAL · passh password sheet",
		tip: "Print with Ctrl+P", printed: "printed 2026-11-15 14:03", legend: "Under 0 O 1 l I and spaces",
		notice:  "made a new certificate for the print page (first use); browsers will warn about it: compare the fingerprint",
		skipped: "pub: 203.0.113.5 is a public address, refused",
		served:  "the page was served to 127.0.0.1; if that wasn't you, start the print page again",
		used:    "already used: start the print page again in passh", misdirect: "misdirected request: unknown host",
		qrLabel: "QR code of the vault key", heading: "Forgotten passphrase",
		comment: "# asks for the passphrase",
	},
	{
		lang: i18n.Ru, attr: "ru", title: "КОНФИДЕНЦИАЛЬНО · лист паролей passh",
		tip: "Распечатайте страницу (Ctrl+P", printed: "напечатано 2026-11-15 14:03", legend: "Под 0 O 1 l I и пробелами",
		notice:  "для страницы печати создан новый сертификат (первое использование); браузеры будут о нём предупреждать: сверьте отпечаток",
		skipped: "pub: 203.0.113.5 — публичный адрес, отклонён",
		served:  "страница выдана адресу 127.0.0.1; если это были не вы, запустите страницу печати заново",
		used:    "страница уже использована: запустите страницу печати в passh заново", misdirect: "запрос не по адресу: неизвестный хост",
		qrLabel: "QR-код ключа хранилища", heading: "Если забыта парольная фраза",
		comment: "# запросит парольную фразу",
	},
	{
		lang: i18n.Sr, attr: "sr-Latn", title: "POVERLJIVO · passh list sa lozinkama",
		tip: "Odštampajte pomoću Ctrl+P", printed: "odštampano 2026-11-15 14:03", legend: "Ispod 0 O 1 l I i razmaka",
		notice:  "napravljen je novi sertifikat za stranicu za štampu (prva upotreba); pregledači će upozoriti na njega: uporedite otisak",
		skipped: "pub: 203.0.113.5 je javna adresa, odbijena je",
		served:  "stranica je poslata adresi 127.0.0.1; ako to niste bili vi, ponovo pokrenite stranicu za štampu",
		used:    "stranica je već iskorišćena: ponovo pokrenite stranicu za štampu u programu passh", misdirect: "pogrešno usmeren zahtev: nepoznat host",
		qrLabel: "QR kod ključa trezora", heading: "Zaboravljena pristupna fraza",
		comment: "# traži pristupnu frazu",
	},
}

// langSheet is testSheet in p's language.
func langSheet(t *testing.T, p i18n.Printer) *print.Sheet {
	t.Helper()
	es := []model.Entry{
		{Path: paths.MustParse("work/github"), Password: "<script>alert(1)</script>", Username: `<img src=x onerror="alert(1)">`},
		{Path: paths.MustParse("lični/pošta"), Password: "a0O1lI b", Username: "Đorđe Иван"},
	}
	s, err := print.NewSheet(es, print.Options{Date: testDate, Printer: p})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestPageInLanguages serves the page in each language: the lang
// attribute, the page's own text, CertNotice, Skipped and the result are
// translated; the headers, the CSP and the escaping are those of English.
func TestPageInLanguages(t *testing.T) {
	for _, pl := range pageLangs {
		t.Run(pl.lang.String(), func(t *testing.T) {
			p := i18n.New(pl.lang)
			ts := start(t, func(o *Options) {
				fakeInterfaces(t, map[string][]string{"lo": {"127.0.0.1/8"}, "pub": {"203.0.113.5/24"}})
				o.Settings.Interfaces = []string{"lo", "pub"}
				o.Doc = langSheet(t, p)
				o.Printer = p
			})
			if ts.CertNotice != pl.notice {
				t.Errorf("CertNotice %q, want %q", ts.CertNotice, pl.notice)
			}
			if len(ts.Skipped) != 1 || ts.Skipped[0] != pl.skipped {
				t.Errorf("Skipped %q, want %q", ts.Skipped, pl.skipped)
			}
			resp, body, err := ts.get(t, ts.URLs[0], "")
			if err != nil {
				t.Fatal(err)
			}
			m := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindAllStringSubmatch(body, -1)
			if len(m) != 1 || m[0][1] != pageCSS {
				t.Fatalf("the style element changed: %d", len(m))
			}
			sum := sha256.Sum256([]byte(m[0][1]))
			if got, want := resp.Header.Get("Content-Security-Policy"), "default-src 'none'; style-src 'sha256-"+
				base64.StdEncoding.EncodeToString(sum[:])+"'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"; got != want {
				t.Errorf("CSP %q, want %q", got, want)
			}
			for _, want := range []string{
				`<html lang="` + pl.attr + `">`,
				"<title>" + pl.title + "</title>",
				`<p class="tip">` + pl.tip,
				pl.printed, "<div>" + pl.legend,
				"&lt;script&gt;alert(1)&lt;/script&gt;",
				"&lt;img src=x onerror=&#34;alert(1)&#34;&gt;",
				"Đorđe Иван", "lični",
				// Field names are names in every language.
				`<span class="lb">  password  </span>`,
			} {
				if !strings.Contains(body, want) {
					t.Errorf("page lacks %q", want)
				}
			}
			if regexp.MustCompile(`(?i)<script|<[^>]*\son[a-z]+\s*=`).MatchString(body) {
				t.Error("markup from a value")
			}
			res := waitResult(t, ts.Server)
			if res.Outcome != Served || res.Localize(p) != pl.served {
				t.Errorf("result %q, want %q", res.Localize(p), pl.served)
			}
			if res.String() != pageLangs[0].served {
				t.Errorf("String %q is not English", res.String())
			}
		})
	}
}

// TestRefusalsInLanguages: what a browser is told after the page was
// served, or for an unknown Host, is in the page's language.
func TestRefusalsInLanguages(t *testing.T) {
	for _, pl := range pageLangs {
		s := &Server{
			token:   "tok",
			port:    8443,
			bound:   []netip.Addr{netip.MustParseAddr("192.168.1.10")},
			doc:     testSheet(t),
			p:       i18n.New(pl.lang),
			served:  make(chan struct{}),
			tooMany: make(chan struct{}),
		}
		do := func(host string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodGet, "/p/tok", nil)
			r.Host = host
			r.RemoteAddr = "192.168.1.23:50000"
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			return w
		}
		if w := do("evil.example"); w.Code != http.StatusMisdirectedRequest || w.Body.String() != pl.misdirect+"\n" {
			t.Errorf("%s: unknown host: %d %q", pl.lang, w.Code, w.Body.String())
		}
		if w := do("192.168.1.10"); w.Code != http.StatusOK {
			t.Fatalf("%s: GET %d", pl.lang, w.Code)
		}
		w := do("192.168.1.10")
		if w.Code != http.StatusGone || w.Body.String() != pl.used+"\n" ||
			w.Header().Get("Content-Security-Policy") != contentSecurityPolicy {
			t.Errorf("%s: second GET: %d %q", pl.lang, w.Code, w.Body.String())
		}
	}
}

// TestRecoveryPageInLanguages renders the recovery sheet's page: the QR
// code's label, the headings and the shell comment of a command are
// translated; the commands stay exact.
func TestRecoveryPageInLanguages(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, pl := range pageLangs {
		p := i18n.New(pl.lang)
		rs, err := print.NewRecoverySheet(id, "6f1c2a7e-0d4b-4c1e-9a55-3b7c9e2d1f00", testDate, p)
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		if err := renderPage(&b, rs, p); err != nil {
			t.Fatal(err)
		}
		body := b.String()
		for _, want := range []string{
			`<html lang="` + pl.attr + `">`, `aria-label="` + pl.qrLabel + `"`, pl.heading,
			"tr -d &#39;\\r&#39; &lt; vault.passh | awk",
			"age -d -o /dev/shm/key.txt key.age                            " + pl.comment,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: page lacks %q", pl.lang, want)
			}
		}
		for _, bad := range []string{"age1", id.Recipient().String(), id.String()} {
			if strings.Contains(body, bad) {
				t.Errorf("%s: page contains %q", pl.lang, bad)
			}
		}
	}
}

func TestResultInLanguages(t *testing.T) {
	c := netip.MustParseAddr("192.168.1.23")
	for _, tc := range []struct {
		r      Result
		ru, sr string
	}{
		{Result{Outcome: Expired, TTL: 5 * time.Minute},
			"страница печати остановлена: за 5m0s её никто не открыл",
			"stranica za štampu je zaustavljena posle 5m0s, a niko je nije otvorio"},
		{Result{Outcome: TooManyWrongTokens},
			"страница печати остановлена после 5 запросов с неверным адресом",
			"stranica za štampu je zaustavljena posle 5 zahteva sa pogrešnom adresom"},
		{Result{Outcome: Cancelled, Client: c},
			"страница печати остановлена во время отправки адресу 192.168.1.23",
			"stranica za štampu je zaustavljena dok je slata adresi 192.168.1.23"},
		{Result{Outcome: Failed, Client: c, Err: i18n.NewError("no address")},
			"страница лишь частично отправлена адресу 192.168.1.23 (нет адреса); запустите страницу печати заново",
			"stranica je samo delimično poslata adresi 192.168.1.23 (nema adrese); ponovo pokrenite stranicu za štampu"},
	} {
		if got := tc.r.Localize(i18n.New(i18n.Ru)); got != tc.ru {
			t.Errorf("ru %q, want %q", got, tc.ru)
		}
		if got := tc.r.Localize(i18n.New(i18n.Sr)); got != tc.sr {
			t.Errorf("sr %q, want %q", got, tc.sr)
		}
		// A Result passed as an argument translates itself.
		if got := i18n.New(i18n.Ru).Error(i18n.Errorf("%v", tc.r)); got != tc.ru {
			t.Errorf("as an argument: %q", got)
		}
	}
}
