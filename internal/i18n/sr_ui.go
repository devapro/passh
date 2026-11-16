package i18n

// srUI holds the Serbian (Latin script) messages of internal/{tty,editor,
// print,printweb,clipboard,session,harden}.
var srUI = catalog{
	msgs: map[string]string{
		// internal/tty/tty.go
		"no terminal":                         "nema terminala",
		"interrupted":                         "prekinuto",
		"not confirmed":                       "nije potvrđeno",
		"passphrases don't match":             "pristupne fraze se ne poklapaju",
		"%w: /dev/tty is not a terminal":      "%w: /dev/tty nije terminal",
		"%w: %s is not a terminal":            "%w: %s nije terminal",
		"reading the passphrase: %w":          "čitanje pristupne fraze: %w",
		"reading the input: %w":               "čitanje unosa: %w",
		"input longer than %d bytes":          "unos je duži od %d bajtova",
		"passphrase longer than %d bytes":     "pristupna fraza je duža od %d bajtova",
		"input line longer than %d bytes":     "uneti red je duži od %d bajtova",
		"reading from the terminal: %w":       "čitanje sa terminala: %w",
		"New passphrase: ":                    "Nova pristupna fraza: ",
		"Repeat passphrase: ":                 "Ponovite pristupnu frazu: ",
		"The passphrase must not be empty.":   "Pristupna fraza ne sme biti prazna.",
		"Passphrases don't match. Try again.": "Pristupne fraze se ne poklapaju. Pokušajte ponovo.",
		" [y/N] ":                             " [d/N] ",
		" [Y/n] ":                             " [D/n] ",
		"Please answer y or n.\n":             "Odgovorite sa d ili n.\n",
		"Type %s to confirm: ":                "Za potvrdu unesite %s: ",
		"%w: no answer":                       "%w: nema odgovora",
		"%w: you didn't type %s":              "%w: niste uneli %s",

		// internal/editor/form.go
		"cancelled":              "otkazano",
		"the form is still open": "obrazac je još otvoren",
		"Discard the changes? esc: discard · any other key: keep editing": "Odbaciti nesačuvane izmene? esc: odbaci · bilo koji drugi taster: nastavi uređivanje",
		"paste refused: the text is not valid UTF-8":                      "lepljenje je odbijeno: tekst nije ispravan UTF-8",
		"paste refused: %s is a single line and the text has line breaks": "lepljenje je odbijeno: %s je polje u jednom redu, a tekst ima prelome redova",
		"Password shown; it hides again in %d s (ctrl+r hides it now).":   "Lozinka je prikazana; ponovo se skriva za %d s (ctrl+r je odmah skriva).",
		"Generating a password failed: %v":                                "Generisanje lozinke nije uspelo: %v",
		"(empty)":                                                         "(prazno)",
		"changed":                                                         "izmenjena",
		"ctrl+s save":                                                     "ctrl+s sačuvaj",
		"esc cancel":                                                      "esc otkaži",
		"tab next":                                                        "tab sledeće polje",
		"enter new line":                                                  "enter novi red",
		"ctrl+r hide password":                                            "ctrl+r sakrij lozinku",
		"ctrl+r show password":                                            "ctrl+r prikaži lozinku",
		"ctrl+g generate":                                                 "ctrl+g generiši",
		"%s (kept as they are; edit them with --editor)":                  "%s (ostaju kakva jesu; izmenite ih pomoću --editor)",

		// internal/editor/run.go
		"the entry form needs a terminal: %w": "za obrazac stavke potreban je terminal: %w",
		"entry form: %w":                      "obrazac stavke: %w",

		// internal/editor/external.go
		"no tmpfs for the temporary file": "nema tmpfs-a za privremenu datoteku",
		"no change":                       "nema izmena",
		"editing interrupted":             "uređivanje je prekinuto",
		"%w (checked %s and %s): the entry would be written to disk in plain text; use the built-in form (passh edit without --editor)": "%w (provereno: %s i %s): stavka bi bila upisana na disk kao otvoreni tekst; koristite ugrađeni obrazac (passh edit bez --editor)",
		"%w (checked %s): the entry would be written to disk in plain text; use the built-in form (passh edit without --editor)":        "%w (provereno: %s): stavka bi bila upisana na disk kao otvoreni tekst; koristite ugrađeni obrazac (passh edit bez --editor)",
		"the editor command is empty": "komanda uređivača je prazna",
		"passh can't control backup, swap or history files of %s: they may keep a copy of the entry on disk. " +
			"Graphical editors must also wait until the file is closed (e.g. code --wait).": "passh ne može da kontroliše datoteke rezervnih kopija, swap datoteke i istoriju uređivača %s: u njima može ostati kopija stavke na disku. " +
			"Grafički uređivači moraju i da sačekaju da se datoteka zatvori (npr. code --wait).",
		"line %d: the text is not valid UTF-8":        "red %d: tekst nije ispravan UTF-8",
		"the editor needs a terminal: %w":             "uređivaču je potreban terminal: %w",
		"%w by %v; nothing was changed":               "%w signalom %v; ništa nije promenjeno",
		"creating the temporary folder: %w":           "pravljenje privremene fascikle: %w",
		"%w: %s is not on tmpfs":                      "%w: %s nije na tmpfs-u",
		"%w: %w; nothing was changed":                 "%w: %w; ništa nije promenjeno",
		"the editor failed (%w); nothing was changed": "uređivač je završio sa greškom (%w); ništa nije promenjeno",
		"creating the temporary file: %w":             "pravljenje privremene datoteke: %w",
		"writing the temporary file: %w":              "upisivanje privremene datoteke: %w",
		"reading the edited file: %w":                 "čitanje izmenjene datoteke: %w",
		"the edited file is larger than %d MiB":       "izmenjena datoteka je veća od %d MiB",
		"removing the temporary folder %s: %w; remove it yourself, it holds the entry in plain text": "uklanjanje privremene fascikle %s: %w; uklonite je sami, u njoj je stavka kao otvoreni tekst",

		// internal/print/doc.go, txt.go, layout.go, qr.go
		"CONFIDENTIAL":   "POVERLJIVO",
		"page %d of %d":  "strana %d od %d",
		"%s (continued)": "%s (nastavak)",
		"QR code: %w":    "QR kod: %w",

		// internal/print/recovery.go
		"recovery sheet: no vault key": "list sa ključem za oporavak: nema ključa trezora",
		"recovery sheet: no vault_id":  "list sa ključem za oporavak: nema vault_id",
		"passh paper recovery key":     "passh papirni ključ za oporavak",
		"printed %s":                   "odštampano %s",
		"Whoever has this sheet and a copy of the vault can read everything in the vault.": "Ko god ima ovaj list i kopiju trezora može da pročita sve što je u trezoru.",
		"Keep it offline, like cash. If it may have been seen, copied or lost, run `passh rekey` " +
			"and print a new sheet: the old key then no longer opens new versions of the vault " +
			"(copies made before still open with it).": "Čuvajte ga van mreže, kao gotovinu. Ako je list možda viđen, kopiran ili izgubljen, " +
			"pokrenite `passh rekey` i odštampajte novi list: stari ključ tada više ne otvara nove " +
			"verzije trezora (kopije napravljene ranije i dalje otvara).",
		"Vault key": "Ključ trezora",
		"After AGE-SECRET-KEY-1 the key never has the letters B, I or O or the digit 1: " +
			"0 is always the digit zero.": "Posle AGE-SECRET-KEY-1 u ključu nikada nema slova B, I i O ni cifre 1: " +
			"0 je uvek cifra nula.",
		"The key's QR code is on the web page (`passh recovery-key print --web`).": "QR kod ključa je na veb-stranici (`passh recovery-key print --web`).",
		"Forgotten passphrase": "Zaboravljena pristupna fraza",
		"Run `passh recover` and type the key above. Spaces, line breaks and letter case are " +
			"ignored, and the key's checksum catches typos. passh then asks for a new passphrase.": "Pokrenite `passh recover` i unesite ključ odštampan iznad. Razmaci, prelomi redova i veličina " +
			"slova se zanemaruju, a kontrolni zbir ključa otkriva greške u kucanju. passh zatim traži novu pristupnu frazu.",
		"Without passh": "Bez programa passh",
		// the shell comment of the third command; the command stays as is
		"asks for the passphrase": "traži pristupnu frazu",
		"On any machine with age (https://age-encryption.org) v1.0 or later, where vault.passh " +
			"is a copy of the vault file:": "Na bilo kom računaru sa programom age (https://age-encryption.org) verzije 1.0 ili novije, " +
			"gde je vault.passh kopija datoteke trezora:",
		"With this key instead of the passphrase: write it to /dev/shm/key.txt as one line, " +
			"without spaces, in capital letters as printed (AGE-SECRET-KEY-1 and then the groups), " +
			"instead of running the first and third commands. The other commands stay the same.": "Sa ovim ključem umesto pristupne fraze: umesto prve i treće komande upišite ključ u " +
			"/dev/shm/key.txt kao jedan red, bez razmaka, velikim slovima kako je odštampan " +
			"(AGE-SECRET-KEY-1, a zatim grupe). Ostale komande ostaju iste.",
		"vault.json is plaintext. Keep it on tmpfs (/dev/shm on Linux) and delete it when done.": "vault.json je otvoreni tekst. Držite ga na tmpfs-u (/dev/shm na Linuksu) i obrišite ga kada završite.",
		"If a mail client or editor re-wrapped the lines, age may reject the blocks. passh still " +
			"opens such a file, and `passh backup` writes it back in canonical form.": "Ako je klijent e-pošte ili uređivač prelomio redove, age može da odbije blokove. passh ipak " +
			"otvara takvu datoteku, a `passh backup` je ponovo upisuje u kanonskom obliku.",

		// internal/print/sheet.go
		"no entries to print": "nema stavki za štampu",
		"invalid field":       "neispravno polje",
		"%w %q: use %s, or the key of a custom field":        "%w %q: koristite %s ili ključ dodatnog polja",
		"%w: no fields to print":                             "%w: nema polja za štampu",
		"%w: the vault has no entries":                       "%w: trezor nema stavki",
		"%w: none matches %s":                                "%w: nema poklapanja (%s)",
		"%w %q: no selected entry has a field with this key": "%w %q: nijedna izabrana stavka nema polje sa ovim ključem",
		"folder %s":            "fascikla %s",
		"tag %s":               "oznaka %s",
		"tags %s":              "oznake %s",
		"passh password sheet": "passh list sa lozinkama",
		"fields: %s":           "polja: %s",
		"(top level)":          "(najviši nivo)",
		"Under 0 O 1 l I and spaces: D digit, U capital letter, L small letter, S space": "Ispod 0 O 1 l I i razmaka: D cifra, U veliko slovo, L malo slovo, S razmak",
		`%s continues the line above; \uXXXX is a character that can't be printed`:       `%s nastavlja red iznad; \uXXXX je znak koji ne može da se odštampa`,

		// internal/printweb/page.go
		"Print with Ctrl+P (Cmd+P on a Mac), then close this tab. This page was served once " +
			"and is gone from passh; the browser may still keep it in its session history.": "Odštampajte pomoću Ctrl+P (Cmd+P na Mac računaru), a zatim zatvorite ovu karticu. Stranica " +
			"se šalje samo jednom i u programu passh je više nema, ali pregledač je može čuvati u istoriji sesije.",
		"QR code of the vault key": "QR kod ključa trezora",

		// internal/printweb/cert.go
		"made a new certificate for the print page (%s); browsers will warn about it: compare the fingerprint": "napravljen je novi sertifikat za stranicu za štampu (%s); pregledači će upozoriti na njega: uporedite otisak",
		"first use": "prva upotreba",
		"the stored certificate can't be read: %v":                         "sačuvani sertifikat ne može da se pročita: %v",
		"the stored key can't be read: %v":                                 "sačuvani ključ ne može da se pročita: %v",
		"the stored key is not a regular file":                             "sačuvani ključ nije obična datoteka",
		"the stored key had mode %04o, readable by others":                 "sačuvani ključ je imao dozvole %04o, pa su ga mogli čitati i drugi",
		"the stored certificate can't be used: %v":                         "sačuvani sertifikat ne može da se koristi: %v",
		"the stored certificate is not valid until %s":                     "sačuvani sertifikat važi tek od %s",
		"the stored certificate expired on %s":                             "sačuvanom sertifikatu je istekao rok važenja %s",
		"the stored certificate expires on %s":                             "sačuvanom sertifikatu ističe rok važenja %s",
		"the addresses or hostnames changed: the old one doesn't cover %s": "adrese ili imena hostova su se promenila: stari sertifikat ne pokriva %s",
		"not an ECDSA P-256 key":                                           "nije ECDSA P-256 ključ",
		"print page certificate: %w":                                       "sertifikat stranice za štampu: %w",
		"print page certificate folder: %w":                                "fascikla sertifikata stranice za štampu: %w",
		"print page certificate folder %s is not a folder":                 "fascikla sertifikata stranice za štampu %s nije fascikla",

		// internal/printweb/net.go
		"no such network interface": "ne postoji takav mrežni interfejs",
		"no address":                "nema adrese",
		"%s: the print page never listens on all addresses (0.0.0.0 or ::)": "%s: stranica za štampu nikada ne sluša na svim adresama (0.0.0.0 ili ::)",
		"%s: not a private address":                                         "%s: nije privatna adresa",
		"%s is not a private address: the print page listens only on " +
			"10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 and fc00::/7, never on a public address": "%s nije privatna adresa: stranica za štampu sluša samo na " +
			"10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 i fc00::/7, nikada na javnoj adresi",
		"print_web.interfaces is empty: name the interfaces of your LAN or VPN, e.g. [\"eth0\", \"wg0\"]": "print_web.interfaces je prazno: navedite interfejse svoje lokalne mreže ili VPN-a, npr. [\"eth0\", \"wg0\"]",
		"%s: no address":                 "%s: nema adrese",
		"%s: %s is link-local, not used": "%s: %s je link-local adresa, ne koristi se",
		"the print page has no private address to listen on (print_web.interfaces): %s": "stranica za štampu nema privatnu adresu na kojoj bi slušala (print_web.interfaces): %s",
		"%s: %s is the wildcard address, never used":                                    "%s: %s je adresa svih interfejsa, nikada se ne koristi",
		"%s: %s is a loopback address, not private":                                     "%s: %s je loopback adresa, nije privatna",
		"%s: %s is a multicast address, not used":                                       "%s: %s je multicast adresa, ne koristi se",
		"%s: %s is a public address, refused":                                           "%s: %s je javna adresa, odbijena je",

		// internal/printweb/server.go
		"the print page is off: set enabled = true in the [print_web] table of the config file": "stranica za štampu je isključena: postavite enabled = true u tabeli [print_web] konfiguracione datoteke",
		"the page was served to %s; if that wasn't you, start the print page again":             "stranica je poslata adresi %s; ako to niste bili vi, ponovo pokrenite stranicu za štampu",
		"the page was only partly sent to %s (%v); start the print page again":                  "stranica je samo delimično poslata adresi %s (%v); ponovo pokrenite stranicu za štampu",
		"the print page stopped after %s without being opened":                                  "stranica za štampu je zaustavljena posle %s, a niko je nije otvorio",
		"the print page was stopped while it was sent to %s":                                    "stranica za štampu je zaustavljena dok je slata adresi %s",
		"the print page was stopped":                                                            "stranica za štampu je zaustavljena",
		"the print page stopped":                                                                "stranica za štampu je završila rad",
		"print page: nothing to print":                                                          "stranica za štampu: nema ničega za štampu",
		"print_web.ttl: %s is not between %s and %s":                                            "print_web.ttl: %s nije između %s i %s",
		"print_web.port: %d is not between 1 and 65535":                                         "print_web.port: %d nije između 1 i 65535",
		"print_web.hostnames: %q is not a hostname":                                             "print_web.hostnames: %q nije ime hosta",
		"print page: %w":                                    "stranica za štampu: %w",
		"misdirected request: unknown host":                 "pogrešno usmeren zahtev: nepoznat host",
		"method not allowed":                                "metod nije dozvoljen",
		"already used: start the print page again in passh": "stranica je već iskorišćena: ponovo pokrenite stranicu za štampu u programu passh",
		"stopped after too many wrong addresses: start the print page again in passh": "stranica je zaustavljena posle previše pogrešnih adresa: ponovo pokrenite stranicu za štampu u programu passh",

		// internal/clipboard/clipboard.go
		"clipboard command":               "komanda za ostavu",
		"clipboard method\x04none":        "nema",
		"no clipboard":                    "nema ostave",
		"clearing the clipboard failed":   "čišćenje ostave nije uspelo",
		"no clipboard: %s; copy with: %s": "nema ostave: %s; kopirajte pomoću: %s",
		"clipboard.command: the program name (first element) is empty":              "clipboard.command: ime programa (prvi element) je prazno",
		"clipboard.osc52 is off and clipboard.command is empty":                     "clipboard.osc52 je isključen, a clipboard.command je prazan",
		"OSC 52 needs a terminal and there is none, and clipboard.command is empty": "za OSC 52 potreban je terminal, a njega nema, i clipboard.command je prazan",
		"command %q":                             "komanda %q",
		"OSC 52 through the terminal":            "OSC 52 preko terminala",
		"clipboard: writing to the terminal: %w": "ostava: upisivanje u terminal: %w",
		"clipboard command: %w":                  "komanda za ostavu: %w",
		"clipboard: no method":                   "ostava: nema načina kopiranja",
		"%w (%s), and %v: %w":                    "%w (%s), i %v: %w",
		"%w (%s); the clipboard was cleared":     "%w (%s); ostava je očišćena",
		"inside tmux: OSC 52 needs `set -g set-clipboard on` in ~/.tmux.conf":                                              "unutar tmux-a: za OSC 52 potrebno je `set -g set-clipboard on` u ~/.tmux.conf",
		"inside GNU screen: screen doesn't pass OSC 52 to the terminal; set clipboard.command or run passh outside screen": "unutar GNU screen-a: screen ne prosleđuje OSC 52 terminalu; podesite clipboard.command ili pokrenite passh van screen-a",
		`Terminal.app has no OSC 52: set clipboard.command = ["pbcopy"]`:                                                   `Terminal.app nema OSC 52: podesite clipboard.command = ["pbcopy"]`,

		// internal/session/session.go
		"locked":                  "zaključano",
		"locked on exit":          "zaključano pri izlasku",
		"locked after inactivity": "zaključano zbog neaktivnosti",
		"locked by a signal":      "zaključano signalom",

		// internal/harden/harden.go
		"disabling core dumps: %w":    "isključivanje core dump datoteka: %w",
		"reading core dump limit: %w": "čitanje ograničenja za core dump datoteke: %w",
	},
	plurals: map[pluralKey][3]string{
		// internal/editor/form.go
		{"Generated a new password (%d character); it is shown.", "Generated a new password (%d characters); it is shown."}: {
			"Generisana je nova lozinka (%d znak); prikazana je.",
			"Generisana je nova lozinka (%d znaka); prikazana je.",
			"Generisana je nova lozinka (%d znakova); prikazana je.",
		},
		{"Generated a new password (%d character); ctrl+r shows it.", "Generated a new password (%d characters); ctrl+r shows it."}: {
			"Generisana je nova lozinka (%d znak); ctrl+r je prikazuje.",
			"Generisana je nova lozinka (%d znaka); ctrl+r je prikazuje.",
			"Generisana je nova lozinka (%d znakova); ctrl+r je prikazuje.",
		},

		// internal/print/sheet.go
		{"%d entry", "%d entries"}: {"%d stavka", "%d stavke", "%d stavki"},

		// internal/printweb/server.go
		{"the print page stopped after %d request with a wrong address", "the print page stopped after %d requests with a wrong address"}: {
			"stranica za štampu je zaustavljena posle %d zahteva sa pogrešnom adresom",
			"stranica za štampu je zaustavljena posle %d zahteva sa pogrešnom adresom",
			"stranica za štampu je zaustavljena posle %d zahteva sa pogrešnom adresom",
		},
	},
}
