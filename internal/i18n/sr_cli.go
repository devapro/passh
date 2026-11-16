package i18n

// srCLI holds the Serbian (Latin script) messages of internal/cli and
// cmd/passh.
var srCLI = catalog{
	msgs: map[string]string{
		// internal/cli/help.go: cobra's help and usage
		"Usage:":                  "Upotreba:",
		"Aliases:":                "Drugi nazivi:",
		"Examples:":               "Primeri:",
		"Available Commands:":     "Dostupne komande:",
		"Additional Commands:":    "Dodatne komande:",
		"Flags:":                  "Opcije:",
		"Global Flags:":           "Globalne opcije:",
		"Additional help topics:": "Dodatne teme pomoći:",
		"Use \"%s [command] --help\" for more information about a command.": "Pokrenite \"%s [command] --help\" za više informacija o komandi.",
		"help for %s":            "pomoć za %s",
		"version for %s":         "verzija programa %s",
		"Help about any command": "Pomoć za bilo koju komandu",
		"Help provides help for any command in the application.\n" +
			"Simply type %s help [path to command] for full details.": "Pomoć za bilo koju komandu programa.\nUnesite %s help [putanja do komande] za sve pojedinosti.",
		"Unknown help topic %#q\n": "Nepoznata tema pomoći %#q\n",
		"(default %s)":             "(podrazumevano %s)",
		"(DEPRECATED: %s)":         "(ZASTARELO: %s)",

		// internal/cli/cli.go
		"A password manager with one encrypted vault file": "Menadžer lozinki sa jednom šifrovanom datotekom trezora",
		"passh keeps passwords in one age-encrypted vault file.\n" +
			"\n" +
			"Run `passh init` to create a vault, then `passh` alone for the TUI. Commands that\n" +
			"read or change entries ask for the passphrase on the terminal, or use the agent\n" +
			"started by `passh unlock`.": "passh čuva lozinke u jednoj datoteci trezora šifrovanoj alatom age.\n" +
			"\n" +
			"Pokrenite `passh init` da napravite trezor, a zatim samo `passh` za TUI. Komande\n" +
			"koje čitaju ili menjaju stavke traže pristupnu frazu na terminalu ili koriste\n" +
			"agenta pokrenutog komandom `passh unlock`.",
		"Run 'passh --help' or 'passh <command> --help' for usage.": "Pomoć: 'passh --help' ili 'passh <command> --help'.",

		// internal/cli/initcmd.go
		"Creating the vault %s.\n" +
			"Choose a passphrase: 6 or more random words are best.\n": "Pravljenje trezora %s.\n" +
			"Izaberite pristupnu frazu: najbolje je 6 ili više nasumičnih reči.\n",
		"Created the vault %s.": "Napravljen je trezor %s.",

		// internal/cli/agentcmd.go
		"Start the agent: no passphrase prompts for a while, also without a terminal": "Pokreni agenta: neko vreme bez traženja pristupne fraze, i bez terminala",
		"Ask for the passphrase and start the agent, which keeps the vault key in memory\n" +
			"so later commands, including ones without a terminal (ssh host passh show …),\n" +
			"don't ask for it. The agent exits after agent.idle_ttl without use, after\n" +
			"agent.max_ttl (or --ttl) in any case, and on `passh lock`.\n" +
			"\n" +
			"With an agent already running for the vault, unlock restarts its idle time and\n" +
			"says how long it has left. --ttl only applies to a new agent: passh says when it\n" +
			"wasn't applied (run `passh lock` first).": "Traži pristupnu frazu i pokreće agenta, koji drži ključ trezora u memoriji, pa\n" +
			"je kasnije komande, i one bez terminala (ssh host passh show …), ne traže.\n" +
			"Agent se gasi posle agent.idle_ttl bez korišćenja, u svakom slučaju posle\n" +
			"agent.max_ttl (ili --ttl), i na `passh lock`.\n" +
			"\n" +
			"Ako za trezor već radi agent, unlock ponovo počinje odbrojavanje neaktivnosti i\n" +
			"kaže koliko mu je ostalo. --ttl važi samo za novog agenta: passh javlja kada\n" +
			"nije primenjen (prvo pokrenite `passh lock`).",
		"--ttl must be more than zero": "--ttl mora biti veći od nule",
		"the running agent was unlocked with another key block (passwd elsewhere?); replacing it":        "pokrenuti agent je otključan drugim blokom ključa (passwd na drugom mestu?); biće zamenjen",
		"passh unlock needs a terminal to ask for the passphrase (over SSH: `ssh -t host passh unlock`)": "passh unlock zahteva terminal da bi tražio pristupnu frazu (preko SSH-a: `ssh -t host passh unlock`)",
		"Unlocked %s: %s.\nRun `passh lock` to stop the agent now.":                                      "Trezor %s je otključan: %s.\nPokrenite `passh lock` da odmah zaustavite agenta.",
		"stop a new agent after this long in any case (overrides agent.max_ttl), e.g. 30m":               "zaustavi novog agenta posle ovoliko vremena u svakom slučaju (umesto agent.max_ttl), npr. 30m",
		"an agent is running, but the vault can't be checked against it: %w":                             "agent radi, ali trezor ne može da se proveri prema njemu: %w",
		"an agent is running, but the vault can't be checked against it: %s: %w":                         "agent radi, ali trezor ne može da se proveri prema njemu: %s: %w",
		"Already unlocked: %s.": "Već je otključano: %s.",
		"--ttl was not applied: the agent was already running; run `passh lock`, then `passh unlock --ttl …`": "--ttl nije primenjen: agent je već radio; pokrenite `passh lock`, a zatim `passh unlock --ttl …`",
		"the agent (pid %d) exits in %s":                                "agent (pid %d) će se ugasiti za %s",
		"the agent (pid %d) exits in %s if unused, in %s at the latest": "agent (pid %d) će se ugasiti za %s ako se ne koristi, a najkasnije za %s",
		"Stop the agent":                                               "Zaustavi agenta",
		"No agent is running for %s.":                                  "Za %s ne radi nijedan agent.",
		"Locked: the agent (pid %d) stopped.":                          "Zaključano: agent (pid %d) je zaustavljen.",
		"the agent couldn't be stopped: %v; stop it with `passh lock`": "agent nije mogao da se zaustavi: %v; zaustavite ga komandom `passh lock`",
		"The agent held the old key and was stopped; run `passh unlock` again if you need it.":                    "Agent je čuvao stari ključ i zaustavljen je; ako vam treba, ponovo pokrenite `passh unlock`.",
		"The agent was unlocked with the old key block and was stopped; run `passh unlock` again if you need it.": "Agent je bio otključan starim blokom ključa i zaustavljen je; ako vam treba, ponovo pokrenite `passh unlock`.",

		// internal/cli/cli.go
		"warning: ": "upozorenje: ",
		"%s needs a terminal (over SSH: use `ssh -t`)":                          "%s zahteva terminal (preko SSH-a: koristite `ssh -t`)",
		"unknown command %q for passh":                                          "nepoznata komanda %q za passh",
		"config file (default $PASSH_CONFIG, then ~/.config/passh/config.toml)": "konfiguraciona datoteka (podrazumevano $PASSH_CONFIG, zatim ~/.config/passh/config.toml)",
		"vault file, overriding the config's vault (no config file needed)":     "datoteka trezora umesto one iz konfiguracije (konfiguraciona datoteka nije potrebna)",
		"Print passh's version":                                                 "Prikaži verziju programa passh",
		"accepts %d arg(s), received %d":                                        "prihvata argumenata: %d, primljeno: %d",
		"accepts between %d and %d arg(s), received %d":                         "prihvata od %d do %d argumenata, primljeno: %d",
		"unknown command %q for %q":                                             "nepoznata komanda %q za %q",

		// internal/cli/copy.go
		"Copy a field (default: the password) to the clipboard, cleared after a while": "Kopiraj polje (podrazumevano lozinku) u ostavu, koja se posle čisti",
		"Copy the password, or another field, to the clipboard: through the terminal\n" +
			"(OSC 52, which works over SSH) or with clipboard.command. passh waits and clears\n" +
			"the clipboard after clipboard.clear_after; Ctrl-C clears it at once. The value\n" +
			"is never printed.": "Kopira lozinku ili drugo polje u ostavu: preko terminala (OSC 52, radi i preko\n" +
			"SSH-a) ili komandom clipboard.command. passh čeka i čisti ostavu posle\n" +
			"clipboard.clear_after; Ctrl-C je odmah čisti. Vrednost se nikad ne ispisuje.",
		"%s has no field %q":                      "stavka %s nema polje %q",
		"%s: the %s is empty; nothing was copied": "%s: polje %s je prazno; ništa nije kopirano",
		"Copied the %s of %s (%s); the clipboard clears in %s, Ctrl-C clears it now.": "Polje %s stavke %s je kopirano (%s); ostava se čisti za %s, Ctrl-C je čisti odmah.",
		"field to copy: password, username, url, tags, notes or a custom field":       "polje za kopiranje: password, username, url, tags, notes ili dodatno polje",
		"Clipboard cleared.":  "Ostava je očišćena.",
		"%w (%s), and %v: %w": "%w (%s), i %v: %w",

		// internal/cli/doctor.go
		"doctor\u0004ok":           "ok",
		"doctor\u0004info":         "info",
		"doctor\u0004skip":         "preskočeno",
		"doctor\u0004warn":         "upozorenje",
		"doctor\u0004error":        "greška",
		"doctor\u0004config":       "konfiguracija",
		"doctor\u0004vault":        "trezor",
		"doctor\u0004vault mode":   "dozvole trezora",
		"doctor\u0004vault folder": "fascikla trezora",
		"doctor\u0004temp files":   "privremene datoteke",
		"doctor\u0004state folder": "fascikla stanja",
		"doctor\u0004agent":        "agent",
		"doctor\u0004agent folder": "fascikla agenta",
		"doctor\u0004memory":       "memorija",
		"doctor\u0004swap":         "swap",
		"doctor\u0004core dumps":   "core dump",
		"doctor\u0004terminal":     "terminal",
		"doctor\u0004edit temp":    "datoteke edit",
		"doctor\u0004clipboard":    "ostava",
		"Check the config, the vault file, the state and agent folders, memory and swap": "Proveri konfiguraciju, trezor, fascikle, agenta, memoriju i swap",
		"Read-only checks of everything passh depends on: the config file, the vault\n" +
			"file (structure, mode 0600, writable folder, leftover temporary files), the\n" +
			"state and agent folders, the agent, free memory for unlock (scrypt needs\n" +
			"256 MiB), swap, core dumps and the terminal. It reports, never fixes. The exit\n" +
			"status is 1 if a check found an error; warnings are advice.": "Proverava, samo čitanjem, sve od čega passh zavisi: konfiguracionu datoteku,\n" +
			"datoteku trezora (struktura, dozvole 0600, upisiva fascikla, zaostale\n" +
			"privremene datoteke), fascikle stanja i agenta, agenta, slobodnu memoriju za\n" +
			"otključavanje (scrypt traži 256 MiB), swap, core dump i terminal. Samo\n" +
			"izveštava, nikad ne popravlja. Izlazni status je 1 ako je neka provera našla\n" +
			"grešku; upozorenja su saveti.",
		"no config file at %s; using --vault and the defaults":                                              "nema konfiguracione datoteke %s; koriste se --vault i podrazumevane vrednosti",
		"--vault overrides the config's vault":                                                              "--vault zamenjuje trezor iz konfiguracije",
		"no config, so no vault to check":                                                                   "nema konfiguracije, pa nema trezora za proveru",
		"%s doesn't exist: run `passh init`, or point the config's vault at your vault file":                "%s ne postoji: pokrenite `passh init` ili u konfiguraciji podesite vault na datoteku svog trezora",
		"%s is a symlink that can't be resolved: %v":                                                        "%s je simbolička veza koja ne može da se razreši: %v",
		"%s is a symlink to %s; saves write the target":                                                     "%s je simbolička veza ka %s; čuvanje upisuje u njen cilj",
		"%s: %v (SHA-256 %s)":                                                                               "%s: %v (SHA-256 %s)",
		"not in canonical form (line endings or wrapping changed); it opens, and the next save rewrites it": "nije u kanonskom obliku (promenjeni su krajevi redova ili prelom); otvara se, a sledeće čuvanje ga prepisuje",
		"mode %04o, not 0600: fix it with chmod 600 %s":                                                     "dozvole %04o, a ne 0600: ispravite komandom chmod 600 %s",
		"%s isn't writable (%v): saving needs a temporary file there":                                       "u %s ne može da se piše (%v): za čuvanje je tu potrebna privremena datoteka",
		"%s is writable":                    "u %s može da se piše",
		"can't list the vault's folder: %v": "sadržaj fascikle trezora ne može da se izlista: %v",
		"none":                              "nema",
		"%s doesn't exist yet; the first save creates it":                                                "%s još ne postoji; napraviće je prvo čuvanje",
		"%s is not a folder (backups, locks and the agent's socket go there)":                            "%s nije fascikla (tu idu rezervne kopije, zaključavanja i soket agenta)",
		"%s belongs to uid %d, not to you":                                                               "%s pripada uid-u %d, a ne vama",
		"%s isn't writable: %v":                                                                          "u %s ne može da se piše: %v",
		"%s has mode %04o: other users can look inside (the backups are encrypted); chmod 700 is better": "%s ima dozvole %04o: drugi korisnici mogu da vide sadržaj (rezervne kopije su šifrovane); bolje je chmod 700",
		"no vault to check the agent for":                                                                "nema trezora za koji bi se proverio agent",
		"%s doesn't exist yet; `passh unlock` creates it":                                                "%s još ne postoji; napraviće je `passh unlock`",
		"%s (0700, yours)":                                         "%s (0700, vaša)",
		"not running (`passh unlock` starts it)":                   "ne radi (`passh unlock` ga pokreće)",
		"running: %s":                                              "radi: %s",
		"disabled for passh and the agent":                         "isključeno za passh i agenta",
		"not disabled: a crash could write secrets to a core file": "nije isključeno: pri padu tajne mogu da završe u core datoteci",
		"none: prompts are impossible, so commands need the agent (`passh unlock` in a terminal)": "nema: upiti nisu mogući, pa komandama treba agent (`passh unlock` u terminalu)",
		"/dev/tty: passphrase prompts work":                                                                          "/dev/tty: traženje pristupne fraze radi",
		"no files left by an interrupted `edit --editor`":                                                            "nema datoteka koje je ostavio prekinuti `edit --editor`",
		"left by an interrupted `edit --editor`, possibly with an entry in plain text: %s; delete them (rm -r)":      "ostale su od prekinutog `edit --editor`, možda sa stavkom kao otvorenim tekstom: %s; obrišite ih (rm -r)",
		"no config, so no clipboard settings to check":                                                               "nema konfiguracije, pa nema podešavanja ostave za proveru",
		"not tested without a terminal: run `passh doctor` in one (over SSH: ssh -t)":                                "bez terminala se ne proverava: pokrenite `passh doctor` u terminalu (preko SSH-a: ssh -t)",
		"Testing the clipboard: copied %q (%s). Paste it somewhere to check; it is cleared in %s.\n":                 "Provera ostave: kopirano je %q (%s). Nalepite to negde da proverite; ostava se čisti za %s.\n",
		"sent a test string with command %q and cleared it; if pasting gave %q, copying works":                       "probni tekst je poslat komandom %q i obrisan; ako je nalepljeno %q, kopiranje radi",
		"sent a test string with OSC 52 through the terminal and cleared it; if pasting gave %q, copying works":      "probni tekst je poslat preko terminala (OSC 52) i obrisan; ako je nalepljeno %q, kopiranje radi",
		"%s in total: unlock needs 256 MiB for scrypt and may fail or swap; available memory isn't checked on macOS": "ukupno %s: otključavanju treba 256 MiB za scrypt i može da ne uspe ili da koristi swap; na macOS-u se dostupna memorija ne proverava",
		"%s available: unlock needs 256 MiB for scrypt and may fail or swap":                                         "dostupno %s: otključavanju treba 256 MiB za scrypt i može da ne uspe ili da koristi swap",
		"%s in total (unlock needs 256 MiB); available memory isn't checked on macOS":                                "ukupno %s (otključavanju treba 256 MiB); na macOS-u se dostupna memorija ne proverava",
		"%s available (unlock needs 256 MiB)":                                                                        "dostupno %s (otključavanju treba 256 MiB)",

		// internal/cli/edit.go
		"Add an entry interactively: password (or generate), username, url, tags, notes": "Dodaj stavku interaktivno: lozinka, kor. ime, url, oznake, beleške",
		"%s already exists: use --force to replace it":                                   "stavka %s već postoji: zamenite je opcijom --force",
		"Saved %s.":                         "Stavka %s je sačuvana.",
		"replace an existing entry":         "zameni postojeću stavku",
		"Username: ":                        "Korisničko ime: ",
		"URL: ":                             "URL: ",
		"Tags (comma-separated): ":          "Oznake (odvojene zarezom): ",
		"Notes (end with an empty line):\n": "Beleške (završite praznim redom):\n",
		"Password (empty to generate): ":    "Lozinka (prazno za generisanje): ",
		"Repeat password: ":                 "Ponovite lozinku: ",
		"Passwords don't match. Try again.": "Lozinke se ne poklapaju. Pokušajte ponovo.",
		"passwords don't match":             "lozinke se ne poklapaju",
		"Generate and store a password":     "Generiši i sačuvaj lozinku",
		"Generate a random password (default 24 letters and digits) and store it.\n" +
			"\n" +
			"A new path makes a new entry. For an existing entry, --force replaces its\n" +
			"password and keeps its other values (username, url, tags, fields, notes).\n" +
			"The password is not printed; show it with `passh show <path> --field password`.": "Generiše nasumičnu lozinku (podrazumevano 24 slova i cifre) i čuva je.\n" +
			"\n" +
			"Nova putanja pravi novu stavku. Za postojeću stavku --force zamenjuje njenu\n" +
			"lozinku i zadržava ostale vrednosti (username, url, tags, fields, notes).\n" +
			"Lozinka se ne ispisuje; prikažite je komandom\n" +
			"`passh show <path> --field password`.",
		"length %q: give a number from 1 to %d":                                              "dužina %q: navedite broj od 1 do %d",
		"%s already exists: use --force to replace its password (its other values are kept)": "stavka %s već postoji: --force zamenjuje njenu lozinku (ostale vrednosti se zadržavaju)",
		"letters and digits":                        "slova i cifre",
		"letters, digits and symbols":               "slova, cifre i simboli",
		"also use punctuation characters":           "koristi i znakove interpunkcije",
		"replace the password of an existing entry": "zameni lozinku postojeće stavke",
		"Move or rename an entry or a folder":       "Premesti ili preimenuj stavku ili fasciklu",
		"Move or rename an entry. A destination ending in / moves the entry into that\n" +
			"folder, keeping its name. If <src> is a folder, every entry in it moves, in\n" +
			"one save; nothing moves if any destination is taken.": "Premešta ili preimenuje stavku. Odredište koje se završava sa / premešta\n" +
			"stavku u tu fasciklu, sa istim imenom. Ako je <src> fascikla, sve stavke u\n" +
			"njoj se premeštaju u jednom čuvanju; ništa se ne premešta ako je neko odredište\n" +
			"zauzeto.",
		"Moved %s to %s.":                         "Stavka %s je premeštena u %s.",
		"can't move the folder %s into itself":    "fascikla %s ne može da se premesti u samu sebe",
		"Delete an entry (asks for confirmation)": "Obriši stavku (uz potvrdu)",
		"passh rm asks for confirmation on a terminal: run it in one, or add --force": "passh rm traži potvrdu na terminalu: pokrenite ga u terminalu ili dodajte --force",
		"Delete %s?":                                      "Obrisati %s?",
		"not deleted":                                     "nije obrisano",
		"Deleted %s.":                                     "Stavka %s je obrisana.",
		"don't ask for confirmation":                      "ne traži potvrdu",
		"Add and remove tags of an entry":                 "Dodaj i ukloni oznake stavke",
		"give --add and/or --remove":                      "navedite --add i/ili --remove",
		"%s: no tags":                                     "%s: nema oznaka",
		"%s: no tags (unchanged)":                         "%s: nema oznaka (bez promena)",
		"%s: tags %s":                                     "%s: oznake %s",
		"%s: tags %s (unchanged)":                         "%s: oznake %s (bez promena)",
		"tag to add (repeat, or separate with commas)":    "oznaka za dodavanje (ponovite opciju ili razdvojite zarezima)",
		"tag to remove (repeat, or separate with commas)": "oznaka za uklanjanje (ponovite opciju ili razdvojite zarezima)",

		// internal/cli/editcmd.go
		"Edit an entry in the built-in form, or in $EDITOR": "Izmeni stavku u ugrađenom obrascu ili u $EDITOR",
		"Edit an entry in the built-in form: password, username, url, tags and notes\n" +
			"(ctrl+s saves, esc cancels, ctrl+r reveals the password, ctrl+g generates one).\n" +
			"\n" +
			"--editor opens the entry's text form in $EDITOR instead, in a temporary file on\n" +
			"tmpfs that is wiped afterwards. vim, neovim and nano get flags that keep them\n" +
			"from writing swap, backup or history files. Where there is no tmpfs (macOS),\n" +
			"the built-in form is used.": "Menja stavku u ugrađenom obrascu: lozinka, korisničko ime, url, oznake i\n" +
			"beleške (ctrl+s čuva, esc otkazuje, ctrl+r prikazuje lozinku, ctrl+g je\n" +
			"generiše).\n" +
			"\n" +
			"--editor umesto toga otvara tekstualni oblik stavke u $EDITOR, u privremenoj\n" +
			"datoteci na tmpfs-u koja se posle briše. vim, neovim i nano dobijaju opcije\n" +
			"koje ih sprečavaju da pišu swap, rezervne datoteke ili istoriju. Gde nema\n" +
			"tmpfs-a (macOS), koristi se ugrađeni obrazac.",
		"warning: %s\n":                "upozorenje: %s\n",
		"The entry isn't valid: %s\n":  "Stavka nije ispravna: %s\n",
		"Edit it again?":               "Izmeniti je ponovo?",
		"edit %s":                      "izmena %s",
		"No change.":                   "Nema promena.",
		"cancelled; nothing was saved": "otkazano; ništa nije sačuvano",
		"nothing was saved: %w":        "ništa nije sačuvano: %w",
		"edit the text form in $EDITOR (temporary file on tmpfs)":                          "izmeni tekstualni oblik u $EDITOR (privremena datoteka na tmpfs-u)",
		"%v; using the built-in form instead":                                              "%v; umesto toga se koristi ugrađeni obrazac",
		"The vault changed on disk since it was opened; reload and apply your edit again?": "Trezor se promenio na disku otkako je otvoren; ponovo ga učitati i primeniti izmenu?",
		"not saved: %w": "nije sačuvano: %w",
		"not saved: the vault changed on disk since it was opened":   "nije sačuvano: trezor se promenio na disku otkako je otvoren",
		"not saved: reloading the vault: %w":                         "nije sačuvano: ponovno učitavanje trezora: %w",
		"not saved: %s was deleted or replaced in the vault on disk": "nije sačuvano: stavka %s je obrisana ili zamenjena u trezoru na disku",

		// internal/cli/entries.go
		"Print the tree of entries, optionally filtered by tag": "Prikaži stablo stavki, po želji filtrirano po oznaci",
		"%s: no such folder": "%s: takva fascikla ne postoji",
		"only entries with this tag (repeat for several: all must match)": "samo stavke sa ovom oznakom (opcija može da se ponovi: potrebne su sve oznake)",
		"Fuzzy search on paths and tags":                                  "Približna pretraga po putanjama i oznakama",
		"no entry matches %q":                                             "nijedna stavka ne odgovara upitu %q",
		"Print an entry (text form) or one field":                         "Prikaži stavku (tekstualni oblik) ili jedno polje",
		"Print an entry in its text form: the password on line 1, then username, url,\n" +
			"tags and other fields, then the notes after ---.\n" +
			"\n" +
			"Control characters and escape sequences in the entry are shown escaped, so an\n" +
			"entry can't drive your terminal. --raw prints the exact bytes instead.\n" +
			"--field prints one value (password, username, url, tags, notes or a custom\n" +
			"field). When stdout is not a terminal (a pipe or a file), --field prints the\n" +
			"exact value without a final newline, e.g.\n" +
			"  passh show work/github --field password | pbcopy": "Prikazuje stavku u tekstualnom obliku: lozinka u 1. redu, zatim username, url,\n" +
			"tags i ostala polja, pa beleške posle ---.\n" +
			"\n" +
			"Kontrolni znakovi i escape sekvence u stavci prikazuju se kao kodovi, pa stavka\n" +
			"ne može da upravlja terminalom. --raw umesto toga ispisuje tačne bajtove.\n" +
			"--field ispisuje jednu vrednost (password, username, url, tags, notes ili\n" +
			"dodatno polje). Kada stdout nije terminal (cev ili datoteka), --field\n" +
			"ispisuje tačnu vrednost bez završnog prelaska u novi red, npr.\n" +
			"  passh show work/github --field password | pbcopy",
		"print only this field: password, username, url, tags, notes or a custom field": "ispiši samo ovo polje: password, username, url, tags, notes ili dodatno polje",
		"print exact bytes, without escaping control characters":                        "ispiši tačne bajtove, bez zamene kontrolnih znakova kodovima",
		"%s is a folder, not an entry: list it with `passh ls %s`":                      "%s je fascikla, a ne stavka: izlistajte je komandom `passh ls %s`",
		"List tags with their entry counts":                                             "Prikaži oznake sa brojem stavki",
		"no tags":                                                                       "nema oznaka",

		// internal/cli/exportcmd.go
		"Export entries for other tools (plaintext unless --age)": "Izvezi stavke za druge alate (otvoreni tekst, osim uz --age)",
		"Export entries as csv, json (the vault's data format) or bitwarden-json.\n" +
			"\n" +
			"Export data is never written to a terminal: use -o file or redirect stdout.\n" +
			"A plaintext export needs confirmation: with a terminal you type EXPORT PLAINTEXT;\n" +
			"without one (e.g. over ssh without -t) add --confirm-plaintext. --age <recipient>\n" +
			"encrypts the export to an age public key instead. -o creates a new file with\n" +
			"mode 0600 and never overwrites one.\n" +
			"\n" +
			"For a backup, don't export: copy the vault file (passh backup).": "Izvozi stavke kao csv, json (format podataka trezora) ili bitwarden-json.\n" +
			"\n" +
			"Podaci izvoza se nikad ne upisuju na terminal: koristite -o file ili\n" +
			"preusmerite stdout. Izvoz kao otvoreni tekst traži potvrdu: na terminalu\n" +
			"ukucajte EXPORT PLAINTEXT; bez njega (npr. preko ssh-a bez -t) dodajte\n" +
			"--confirm-plaintext. --age <recipient> umesto toga šifruje izvoz javnim\n" +
			"ključem age. -o pravi novu datoteku sa dozvolama 0600 i nikad ne prepisuje\n" +
			"postojeću.\n" +
			"\n" +
			"Za rezervnu kopiju nemojte izvoziti: kopirajte datoteku trezora (passh backup).",
		"--format is required: csv, json or bitwarden-json":                                        "potrebna je opcija --format: csv, json ili bitwarden-json",
		"This writes your passwords unencrypted.\n":                                                "Vaše lozinke će biti upisane nešifrovane.\n",
		"csv, json or bitwarden-json":                                                              "csv, json ili bitwarden-json",
		"only entries in this folder":                                                              "samo stavke u ovoj fascikli",
		"write to this new file (mode 0600) instead of stdout":                                     "upiši u ovu novu datoteku (dozvole 0600) umesto na stdout",
		"encrypt to this age public key (age1…)":                                                   "šifruj ovim javnim ključem age (age1…)",
		"confirm a plaintext export when there is no terminal":                                     "potvrdi izvoz kao otvoreni tekst kada nema terminala",
		"CSV: prefix ' to cells starting with = + - @ (changes values; not for password managers)": "CSV: dodaj ' ispred ćelija koje počinju sa = + - @ (menja vrednosti; nije za menadžere lozinki)",

		// internal/cli/files.go
		"%s is not a regular file":                    "%s nije obična datoteka",
		"%s is larger than 64 MiB: not a passh vault": "%s je veća od 64 MiB: nije passh trezor",
		"Check the vault or a copy of it":             "Proveri trezor ili njegovu kopiju",
		"Check a vault file without the passphrase: the passh-vault line, both blocks\n" +
			"complete, base64 and age headers valid. It prints the file's SHA-256 and size;\n" +
			"a byte-exact copy has the same SHA-256 as the original.\n" +
			"\n" +
			"--full also decrypts the file (through the agent, or by asking for the\n" +
			"passphrase) and prints its vault_id, revision, saved_at and entry count, and\n" +
			"how it compares with the newest revision seen on this machine.": "Proverava datoteku trezora bez pristupne fraze: red passh-vault, oba bloka\n" +
			"potpuna, base64 i age zaglavlja ispravna. Ispisuje SHA-256 i veličinu\n" +
			"datoteke; kopija identična bajt po bajt ima isti SHA-256 kao original.\n" +
			"\n" +
			"--full takođe dešifruje datoteku (preko agenta ili traženjem pristupne fraze)\n" +
			"i ispisuje njen vault_id, revision, saved_at i broj stavki, kao i poređenje sa\n" +
			"najnovijom revizijom viđenom na ovom računaru.",
		"note: %v": "napomena: %v",
		"note: the file isn't in passh's canonical form (line endings or line wrapping changed in copying); it opens, and `passh backup` writes a canonical copy": "napomena: datoteka nije u kanonskom obliku programa passh (pri kopiranju su promenjeni krajevi redova ili prelom redova); otvara se, a `passh backup` upisuje kanonsku kopiju",
		"also decrypt the file and check its data":                "takođe dešifruj datoteku i proveri njene podatke",
		"this machine hasn't seen this vault before":              "ovaj računar ranije nije video ovaj trezor",
		"OLDER than seen before on this machine (seen r%d of %s)": "STARIJA od ranije viđene na ovom računaru (viđena je r%d od %s)",
		"OK: the newest revision seen on this machine (r%d)":      "OK: najnovija revizija viđena na ovom računaru (r%d)",
		"OK: newer than seen before on this machine (r%d)":        "OK: novija od ranije viđene na ovom računaru (r%d)",
		"Make a checked copy of the vault in a file or folder":    "Napravi proverenu kopiju trezora u datoteci ili fascikli",
		"Copy the vault to a file, or into a folder as <name>-<UTC time>.passh, with\n" +
			"mode 0600. The copy is flushed to disk, read back and compared by SHA-256.\n" +
			"An existing file is never overwritten. A vault that isn't in canonical form\n" +
			"(e.g. after an email or a paste) is written in canonical form. No passphrase\n" +
			"is needed.": "Kopira trezor u datoteku ili u fasciklu kao <name>-<UTC time>.passh, sa\n" +
			"dozvolama 0600. Kopija se upisuje na disk, ponovo čita i poredi po SHA-256.\n" +
			"Postojeća datoteka se nikad ne prepisuje. Trezor koji nije u kanonskom obliku\n" +
			"(npr. posle imejla ili lepljenja) upisuje se u kanonskom obliku. Pristupna\n" +
			"fraza nije potrebna.",
		"Backed up %s to %s.": "Kopija trezora %s je upisana u %s.",
		"The copy is byte for byte the vault; `passh verify` shows the same SHA-256 for both.": "Kopija je bajt po bajt jednaka trezoru; `passh verify` prikazuje isti SHA-256 za obe datoteke.",
		"The vault isn't in canonical form, so the copy was written in canonical form;\n" +
			"its SHA-256 differs from the vault's, and the stock age tool reads its blocks (§8).": "Trezor nije u kanonskom obliku, pa je kopija upisana u kanonskom obliku;\n" +
			"njen SHA-256 se razlikuje od SHA-256 trezora, a standardni alat age čita njene blokove (§8).",
		"List the automatic backups of the vault": "Prikaži automatske rezervne kopije trezora",
		"List the automatic backups passh made before each save (§4.7), newest first,\n" +
			"with time and revision. To restore one, copy it over the vault file and run\n" +
			"`passh verify --full`. No passphrase is needed.": "Prikazuje automatske rezervne kopije koje je passh napravio pre svakog čuvanja\n" +
			"(§4.7), prvo najnovije, sa vremenom i revizijom. Da biste vratili jednu,\n" +
			"kopirajte je preko datoteke trezora i pokrenite `passh verify --full`.\n" +
			"Pristupna fraza nije potrebna.",
		"note: %s can't be read (%v); listing every automatic backup on this machine":                                                                                                        "napomena: %s ne može da se pročita (%v); prikazuju se sve automatske rezervne kopije na ovom računaru",
		"No automatic backups yet. passh makes one before each save (backup.keep = %d).":                                                                                                     "Još nema automatskih rezervnih kopija. passh pravi jednu pre svakog čuvanja (backup.keep = %d).",
		"note: no backup has this vault's current key block (it was changed by passwd or rekey and not saved since, or the file is damaged); listing every automatic backup on this machine": "napomena: nijedna kopija nema trenutni blok ključa ovog trezora (promenio ga je passwd ili rekey i od tada nije sačuvan, ili je datoteka oštećena); prikazuju se sve automatske rezervne kopije na ovom računaru",

		// internal/cli/help.go
		"unknown flag: --%s":                  "nepoznata opcija: --%s",
		"unknown shorthand flag: %q in -%s":   "nepoznata kratka opcija %q u -%s",
		"flag needs an argument: --%s":        "opciji je potrebna vrednost: --%s",
		"flag needs an argument: %q in -%s":   "opciji je potrebna vrednost: %q u -%s",
		"invalid argument %q for %q flag: %v": "neispravna vrednost %q za opciju %q: %v",
		"bad flag syntax: %s":                 "neispravna sintaksa opcije: %s",

		// internal/cli/importcmd.go
		"Import entries from another password manager":      "Uvezi stavke iz drugog menadžera lozinki",
		"say what to import from, e.g. `passh import pass`": "navedite odakle se uvozi, npr. `passh import pass`",
		"One-way import from a pass store (needs gpg)":      "Jednosmerni uvoz iz skladišta pass-a (treba gpg)",
		"Import a pass store (password-store.org) into the vault, in one save. The store\n" +
			"is only read. dir defaults to $PASSWORD_STORE_DIR, then ~/.password-store.\n" +
			"Each entry is decrypted with gpg, as pass does. Paths already in the vault are\n" +
			"skipped unless --overwrite is given. --dry-run lists what would be imported\n" +
			"and the conflicts without decrypting anything.": "Uvozi skladište pass-a (password-store.org) u trezor, u jednom čuvanju.\n" +
			"Skladište se samo čita. dir je podrazumevano $PASSWORD_STORE_DIR, zatim\n" +
			"~/.password-store. Svaka stavka se dešifruje sa gpg, kao što radi pass.\n" +
			"Putanje koje već postoje u trezoru se preskaču, osim uz --overwrite. --dry-run\n" +
			"ispisuje šta bi bilo uvezeno i konflikte, bez dešifrovanja bilo čega.",
		"Decrypting %d/%d…":                                              "Dešifrovanje %d/%d…",
		"nothing was imported: %w":                                       "ništa nije uvezeno: %w",
		"replace entries whose path is already in the vault":             "zameni stavke čija putanja već postoji u trezoru",
		"list what would be imported and the conflicts; decrypt nothing": "ispiši šta bi bilo uvezeno i konflikte; ne dešifruj ništa",
		"Dry run: nothing was decrypted or saved. Store: %s":             "Probno pokretanje: ništa nije dešifrovano ni sačuvano. Skladište pass-a: %s",
		"%s  (replaces the entry in the vault)":                          "%s  (zamenjuje stavku u trezoru)",

		// internal/cli/initcmd.go
		"Create a new vault, and the config file if it doesn't exist": "Napravi novi trezor i konfiguracionu datoteku ako ne postoji",
		"%s already exists; passh init doesn't overwrite a vault":     "%s već postoji; passh init ne prepisuje trezor",
		"the vault was created, but the config file wasn't: %w":       "trezor je napravljen, ali konfiguraciona datoteka nije: %w",
		"Wrote the config file %s.":                                   "Konfiguraciona datoteka %s je upisana.",
		"The config file %s exists and wasn't changed; it names the vault %s.\n" +
			"Use --vault %s with each command, or change vault in the config file.": "Konfiguraciona datoteka %s postoji i nije promenjena; u njoj je naveden trezor %s.\n" +
			"Koristite --vault %s uz svaku komandu ili promenite vault u konfiguracionoj datoteci.",
		"the vault was created, but the recovery sheet wasn't written: %w; run `passh recovery-key print` later": "trezor je napravljen, ali list sa ključem za oporavak nije upisan: %w; pokrenite `passh recovery-key print` kasnije",

		// internal/cli/open.go
		"vault is locked: run `passh unlock` in a terminal (over SSH: `ssh -t host passh unlock`)": "trezor je zaključan: pokrenite `passh unlock` u terminalu (preko SSH-a: `ssh -t host passh unlock`)",
		"no vault at %s: run `passh init` to create one, or pass --vault <file>":                   "trezor %s ne postoji: napravite ga komandom `passh init` ili prosledite --vault <file>",
		"vault %s: %w":                  "trezor %s: %w",
		"Continue with this copy?":      "Nastaviti sa ovom kopijom?",
		"%v; asking for the passphrase": "%v; traži se pristupna fraza",
		"can't use the agent of %s: %v": "agent za %s ne može da se koristi: %v",
		"the agent's key doesn't open %s (was it rekeyed elsewhere?); asking for the passphrase":                                                                                                              "ključ agenta ne otvara %s (ključ je promenjen na drugom mestu?); traži se pristupna fraza",
		"The key block only protects the vault key with the passphrase: if the data block is intact, `passh recover` with the paper recovery key writes a new key block":                                      "Blok ključa samo štiti ključ trezora pristupnom frazom: ako je blok podataka čitav, `passh recover` sa papirnim ključem za oporavak upisuje novi blok ključa",
		"The key block only protects the vault key with the passphrase: if the data block is intact, `passh recover` with the paper recovery key writes a new key block; or restore a backup (passh backups)": "Blok ključa samo štiti ključ trezora pristupnom frazom: ako je blok podataka čitav, `passh recover` sa papirnim ključem za oporavak upisuje novi blok ključa; ili vratite rezervnu kopiju (passh backups)",
		"Passphrase: ":                   "Pristupna fraza: ",
		"Wrong passphrase. Try again.\n": "Pogrešna pristupna fraza. Pokušajte ponovo.\n",
		"warning: %s":                    "upozorenje: %s",

		// internal/cli/output.go
		"refusing to write export data to a terminal: add -o file or redirect stdout":        "podaci izvoza se ne upisuju na terminal: dodajte -o file ili preusmerite stdout",
		"refusing to write the sheet to a terminal: add -o file or redirect stdout":          "list se ne upisuje na terminal: dodajte -o file ili preusmerite stdout",
		"refusing to write the recovery key to a terminal: add -o file or redirect stdout":   "ključ za oporavak se ne upisuje na terminal: dodajte -o file ili preusmerite stdout",
		"%s already exists; passh doesn't overwrite files":                                   "%s već postoji; passh ne prepisuje datoteke",
		"%s isn't on tmpfs: the plaintext is on persistent disk. Delete it when you're done": "%s nije na tmpfs-u: otvoreni tekst je na trajnom disku. Obrišite datoteku kad završite",
		"%w; the partial file %s could not be removed (%v): delete it":                       "%w; nepotpuna datoteka %s nije mogla da se ukloni (%v): obrišite je",
		"%w; the partial file was removed":                                                   "%w; nepotpuna datoteka je uklonjena",
		"writing %s: %w":                                                                     "upisivanje %s: %w",

		// internal/cli/passphrase.go
		"Change the passphrase (the paper recovery key stays valid)": "Promeni pristupnu frazu (papirni ključ za oporavak ostaje važeći)",
		"Change the passphrase: only the key block is rewritten, and the paper recovery\n" +
			"key stays valid. It asks for the current passphrase on the terminal, also while\n" +
			"the agent runs: the agent's key isn't enough to change it. A running agent is\n" +
			"stopped afterwards.": "Menja pristupnu frazu: prepisuje se samo blok ključa, a papirni ključ za\n" +
			"oporavak ostaje važeći. Trenutna pristupna fraza se traži na terminalu, i dok\n" +
			"agent radi: ključ agenta nije dovoljan za njenu promenu. Pokrenuti agent se\n" +
			"zatim zaustavlja.",
		"Choose the new passphrase.\n": "Izaberite novu pristupnu frazu.\n",
		"Passphrase changed. The paper recovery key stays valid.\n" +
			"Copies and backups made before still open with the old passphrase.": "Pristupna fraza je promenjena. Papirni ključ za oporavak ostaje važeći.\n" +
			"Kopije i rezervne kopije napravljene ranije i dalje se otvaraju starom pristupnom frazom.",
		"Make a new vault key (the old passphrase and paper key stop working on new versions)": "Napravi novi ključ trezora (stara fraza i papirni ključ ne otvaraju nove verzije)",
		"Make a new vault key and re-encrypt the data to it, with a passphrase (the same or\n" +
			"a new one). The old passphrase and paper recovery key don't open new versions of\n" +
			"the file. It asks for the current passphrase on the terminal, also while the\n" +
			"agent runs: the agent's key isn't enough to replace the vault key. A running\n" +
			"agent is stopped afterwards.": "Pravi novi ključ trezora i njime ponovo šifruje podatke, uz pristupnu frazu\n" +
			"(istu ili novu). Stara pristupna fraza i papirni ključ za oporavak ne otvaraju\n" +
			"nove verzije datoteke. Trenutna pristupna fraza se traži na terminalu, i dok\n" +
			"agent radi: ključ agenta nije dovoljan za zamenu ključa trezora. Pokrenuti\n" +
			"agent se zatim zaustavlja.",
		"Choose the passphrase for the new vault key (it may be the same as before).\n": "Izaberite pristupnu frazu za novi ključ trezora (može biti ista kao ranije).\n",
		"The vault has a new key. The old passphrase and the old paper recovery key\n" +
			"no longer open new versions of it; copies made before still open with them.\n" +
			"Print a new paper recovery key now: passh recovery-key print": "Trezor ima novi ključ. Stara pristupna fraza i stari papirni ključ za oporavak\n" +
			"više ne otvaraju njegove nove verzije; kopije napravljene ranije i dalje se otvaraju njima.\n" +
			"Odštampajte novi papirni ključ za oporavak sada: passh recovery-key print",
		"passh %s needs the current passphrase, typed on a terminal; the agent's key isn't enough to change the passphrase or the vault key (over SSH: `ssh -t host passh %s`)": "passh %s zahteva trenutnu pristupnu frazu, ukucanu na terminalu; ključ agenta nije dovoljan za promenu pristupne fraze ili ključa trezora (preko SSH-a: `ssh -t host passh %s`)",
		"Current passphrase: ": "Trenutna pristupna fraza: ",
		"Open the vault with the paper recovery key and set a new passphrase":                                                  "Otvori trezor papirnim ključem i postavi novu pristupnu frazu",
		"this recovery key doesn't open %s: it belongs to another vault, or the vault was rekeyed after the sheet was printed": "ovaj ključ za oporavak ne otvara %s: pripada drugom trezoru ili je ključ trezora promenjen posle štampanja lista",
		"The recovery key opens the vault. Choose a new passphrase.\n":                                                         "Ključ za oporavak otvara trezor. Izaberite novu pristupnu frazu.\n",
		"New passphrase set for %s. The paper recovery key stays valid.":                                                       "Za %s je postavljena nova pristupna fraza. Papirni ključ za oporavak ostaje važeći.",
		"Type the recovery key from the paper sheet (AGE-SECRET-KEY-1…); it shows as *.\n" +
			"Spaces, line breaks and letter case don't matter. End with an empty line.\n": "Ukucajte ključ za oporavak sa papirnog lista (AGE-SECRET-KEY-1…); prikazuje se kao *.\n" +
			"Razmaci, prelomi redova i velika i mala slova nisu bitni. Završite praznim redom.\n",
		"%v. Type it again.\n": "%v. Ukucajte ga ponovo.\n",

		// internal/cli/printcmd.go
		"the print page needs a terminal (over SSH: use `ssh -t`)":                                                            "stranica za štampu zahteva terminal (preko SSH-a: koristite `ssh -t`)",
		"PDF output was removed; use --web to print from a browser (it can save as PDF), or omit --format for the text sheet": "izlaz u PDF je uklonjen; koristite --web za štampu iz pregledača (može da sačuva kao PDF) ili izostavite --format za tekstualni list",
		"show the sheet on the one-shot print page (§7.4), with a QR code; a browser can print it or save it as PDF":          "prikaži list na jednokratnoj stranici za štampu (§7.4), sa QR kodom; pregledač može da ga odštampa ili sačuva kao PDF",
		"--output can't be used with --web":                                   "--output ne može da se koristi uz --web",
		"Print a password sheet (text), or show it on the print page (--web)": "Odštampaj list sa lozinkama: kao tekst ili na stranici za štampu (--web)",
		"Lay out the chosen entries as a text password sheet, grouped by folder, with\n" +
			"the chosen fields (default password,username,url; also tags, notes, fields, or\n" +
			"a custom field's key). Ambiguous characters are marked.\n" +
			"\n" +
			"The sheet is plaintext: it is never written to a terminal, and it needs\n" +
			"confirmation as a plaintext export does (type EXPORT PLAINTEXT, or\n" +
			"--confirm-plaintext without a terminal). Use -o file (mode 0600) or redirect\n" +
			"stdout; print it, then delete the file.\n" +
			"\n" +
			"--web shows it on the one-shot print page instead (print_web.enabled; needs a\n" +
			"terminal and typing PRINT); the browser prints it, or saves it as PDF.": "Raspoređuje izabrane stavke u tekstualni list sa lozinkama, po fasciklama, sa\n" +
			"izabranim poljima (podrazumevano password,username,url; takođe tags, notes,\n" +
			"fields ili ključ dodatnog polja). Dvosmisleni znakovi su označeni.\n" +
			"\n" +
			"List je otvoreni tekst: nikad se ne upisuje na terminal i traži potvrdu kao i\n" +
			"izvoz kao otvoreni tekst (ukucajte EXPORT PLAINTEXT ili --confirm-plaintext\n" +
			"bez terminala). Koristite -o file (dozvole 0600) ili preusmerite stdout;\n" +
			"odštampajte ga, pa obrišite datoteku.\n" +
			"\n" +
			"--web ga umesto toga prikazuje na jednokratnoj stranici za štampu\n" +
			"(print_web.enabled; traži terminal i kucanje PRINT); pregledač ga štampa ili\n" +
			"čuva kao PDF.",
		"--confirm-plaintext can't be used with --web: the print page needs a terminal": "--confirm-plaintext ne može da se koristi uz --web: stranica za štampu zahteva terminal",
		"printing needs confirmation: without a terminal, add --confirm-plaintext":      "štampa traži potvrdu: bez terminala dodajte --confirm-plaintext",
		"The sheet holds your passwords unencrypted.\n":                                 "List sadrži vaše lozinke nešifrovane.\n",
		"fields to print, comma-separated (default password,username,url)":              "polja za štampu, odvojena zarezima (podrazumevano password,username,url)",
		"confirm a plaintext sheet when there is no terminal":                           "potvrdi list kao otvoreni tekst kada nema terminala",

		// internal/cli/printpage.go
		"not used: %s":            "ne koriste se: %s",
		"certificate SHA-256  %s": "SHA-256 sertifikata  %s",
		"Compare it with the fingerprint your browser shows before you accept the certificate.": "Uporedite ga sa otiskom koji prikazuje pregledač pre nego što prihvatite sertifikat.",
		"c copies the URL · Esc stops":       "c kopira URL · Esc zaustavlja",
		"Done: %s.":                          "Gotovo: %s.",
		"stops after one load or in %d:%02d": "zaustavlja se posle jednog učitavanja ili za %d:%02d",
		"no clipboard":                       "nema ostave",
		"copy failed":                        "kopiranje nije uspelo",
		"URL copied":                         "URL je kopiran",

		// internal/cli/recoverykey.go
		"The paper recovery key":                                                        "Papirni ključ za oporavak",
		"say what to do, e.g. `passh recovery-key print`":                               "navedite šta treba uraditi, npr. `passh recovery-key print`",
		"Print the paper recovery key (needs a terminal and typing PRINT RECOVERY KEY)": "Odštampaj papirni ključ za oporavak (traži terminal i kucanje PRINT RECOVERY KEY)",
		"Print the paper recovery key as a text sheet: the vault key in groups of four\n" +
			"characters, the vault_id, the print date, a warning and the manual recovery\n" +
			"steps. Whoever has the sheet and a copy of the vault can read everything: keep\n" +
			"it offline, and print a new one after `passh rekey`.\n" +
			"\n" +
			"It needs a terminal and typing PRINT RECOVERY KEY. The sheet is never written\n" +
			"to a terminal: use -o file (mode 0600) or redirect stdout, print it, then delete\n" +
			"the file. --web shows it on the one-shot print page instead, with the key as a\n" +
			"QR code; the browser prints it, or saves it as PDF.": "Štampa papirni ključ za oporavak kao tekstualni list: ključ trezora u grupama\n" +
			"od po četiri znaka, vault_id, datum štampe, upozorenje i korake ručnog\n" +
			"oporavka. Ko ima list i kopiju trezora može da pročita sve: čuvajte list van\n" +
			"mreže i odštampajte novi posle `passh rekey`.\n" +
			"\n" +
			"Traži terminal i kucanje PRINT RECOVERY KEY. List se nikad ne upisuje na\n" +
			"terminal: koristite -o file (dozvole 0600) ili preusmerite stdout,\n" +
			"odštampajte ga, pa obrišite datoteku. --web ga umesto toga prikazuje na\n" +
			"jednokratnoj stranici za štampu, sa ključem kao QR kodom; pregledač ga štampa\n" +
			"ili čuva kao PDF.",
		"Wrote the paper recovery key to %s.":                           "Papirni ključ za oporavak je upisan u %s.",
		"print it, keep the sheet offline, then delete the file: rm %s": "odštampajte ga, čuvajte list van mreže, pa obrišite datoteku: rm %s",
		"Print the recovery key now?":                                   "Odštampati ključ za oporavak sada?",
		"Print the paper recovery key now and keep the sheet offline:\n" +
			"  passh recovery-key print -o <file>   (or --web, with the key as a QR code)\n" +
			"Without it, a forgotten passphrase means the data is lost.": "Odštampajte papirni ključ za oporavak sada i čuvajte list van mreže:\n" +
			"  passh recovery-key print -o <file>   (ili --web, sa ključem kao QR kodom)\n" +
			"Bez njega, zaboravljena pristupna fraza znači da su podaci izgubljeni.",
		"Write the text sheet to [%s]: ":                                          "Datoteka za tekstualni list [%s]: ",
		"For a version with the key as a QR code: passh recovery-key print --web": "Za verziju sa ključem kao QR kodom: passh recovery-key print --web",

		// internal/cli/sys_darwin.go
		"can't read the memory size: %v":                  "veličina memorije ne može da se pročita: %v",
		"can't read vm.swapusage: %v":                     "vm.swapusage ne može da se pročita: %v",
		"no swap is in use":                               "swap se ne koristi",
		"swap is active (%s used) and encrypted by macOS": "swap je aktivan (zauzeto %s) i macOS ga šifruje",
		"swap is active (%s used) and not encrypted: process memory, decrypted secrets included, may be written to disk": "swap je aktivan (zauzeto %s) i nije šifrovan: memorija procesa, uključujući dešifrovane tajne, može da se upiše na disk",

		// internal/cli/sys_linux.go
		"can't read the available memory: %v": "dostupna memorija ne može da se pročita: %v",
		"can't read /proc/swaps: %v":          "/proc/swaps ne može da se pročita: %v",
		"no swap is active":                   "swap nije aktivan",

		// internal/cli/sys_other.go
		"not checked on this system": "ne proverava se na ovom sistemu",

		// internal/cli/tuicmd.go
		"the TUI needs a terminal: run passh in one (over SSH: `ssh -t host passh`); without a terminal, use the commands (passh --help) after `passh unlock`": "TUI zahteva terminal: pokrenite passh u terminalu (preko SSH-a: `ssh -t host passh`); bez terminala koristite komande (passh --help) posle `passh unlock`",
		"the TUI was stopped (%w); it locked first": "TUI je zaustavljen (%w); prethodno se zaključao",
	},
	plurals: map[pluralKey][3]string{
		// internal/cli/doctor.go
		{"%d error", "%d errors"}:                                    {"%d greška", "%d greške", "%d grešaka"},
		{"%d warning", "%d warnings"}:                                {"%d upozorenje", "%d upozorenja", "%d upozorenja"},
		{"%s: structure OK, %d bytes", "%s: structure OK, %d bytes"}: {"%s: struktura je u redu, %d bajt", "%s: struktura je u redu, %d bajta", "%s: struktura je u redu, %d bajtova"},
		{"%d file left by an interrupted save (%s); the next save removes them", "%d files left by an interrupted save (%s); the next save removes them"}: {"%d datoteka je ostala od prekinutog čuvanja (%s); sledeće čuvanje je uklanja", "%d datoteke su ostale od prekinutog čuvanja (%s); sledeće čuvanje ih uklanja", "%d datoteka je ostalo od prekinutog čuvanja (%s); sledeće čuvanje ih uklanja"},
		{"%d byte", "%d bytes"}: {"%d bajt", "%d bajta", "%d bajtova"},
		// internal/cli/edit.go
		{"Generated a %d-character password.", "Generated a %d-character password."}: {"Generisana je lozinka od %d znaka.", "Generisana je lozinka od %d znaka.", "Generisana je lozinka od %d znakova."},
		{"%s, %d bits", "%s, %d bits"}: {"%s, %d bit", "%s, %d bita", "%s, %d bitova"},
		{"Replaced the password of %s: a new %d-character password (%s).\nShow it with: passh show %s --field password", "Replaced the password of %s: a new %d-character password (%s).\nShow it with: passh show %s --field password"}: {"Lozinka stavke %s je zamenjena: nova lozinka od %d znaka (%s).\nPrikažite je komandom: passh show %s --field password", "Lozinka stavke %s je zamenjena: nova lozinka od %d znaka (%s).\nPrikažite je komandom: passh show %s --field password", "Lozinka stavke %s je zamenjena: nova lozinka od %d znakova (%s).\nPrikažite je komandom: passh show %s --field password"},
		{"Stored %s: a new %d-character password (%s).\nShow it with: passh show %s --field password", "Stored %s: a new %d-character password (%s).\nShow it with: passh show %s --field password"}:                                     {"Stavka %s je sačuvana: nova lozinka od %d znaka (%s).\nPrikažite je komandom: passh show %s --field password", "Stavka %s je sačuvana: nova lozinka od %d znaka (%s).\nPrikažite je komandom: passh show %s --field password", "Stavka %s je sačuvana: nova lozinka od %d znakova (%s).\nPrikažite je komandom: passh show %s --field password"},
		{"Moved the folder %s/ to %s/ (%d entry).", "Moved the folder %s/ to %s/ (%d entries)."}:                                                                                                                                         {"Fascikla %s/ je premeštena u %s/ (%d stavka).", "Fascikla %s/ je premeštena u %s/ (%d stavke).", "Fascikla %s/ je premeštena u %s/ (%d stavki)."},
		// internal/cli/exportcmd.go
		{"exported %d entry (%s, encrypted with age) to %s", "exported %d entries (%s, encrypted with age) to %s"}: {"izvezena je %d stavka (%s, šifrovano alatom age) u %s", "izvezene su %d stavke (%s, šifrovano alatom age) u %s", "izvezeno je %d stavki (%s, šifrovano alatom age) u %s"},
		{"exported %d entry (%s, plaintext) to %s", "exported %d entries (%s, plaintext) to %s"}:                   {"izvezena je %d stavka (%s, otvoreni tekst) u %s", "izvezene su %d stavke (%s, otvoreni tekst) u %s", "izvezeno je %d stavki (%s, otvoreni tekst) u %s"},
		{"CSV has no column for custom fields: %d field was left out (otp fields included); use --format json or bitwarden-json to keep them", "CSV has no column for custom fields: %d fields were left out (otp fields included); use --format json or bitwarden-json to keep them"}: {"CSV nema kolonu za dodatna polja: %d polje je izostavljeno (uključujući otp polja); koristite --format json ili bitwarden-json da ih zadržite", "CSV nema kolonu za dodatna polja: %d polja su izostavljena (uključujući otp polja); koristite --format json ili bitwarden-json da ih zadržite", "CSV nema kolonu za dodatna polja: %d polja je izostavljeno (uključujući otp polja); koristite --format json ili bitwarden-json da ih zadržite"},
		// internal/cli/importcmd.go
		{"Would import %d entry:", "Would import %d entries:"}:                                           {"Biće uvezena %d stavka:", "Biće uvezene %d stavke:", "Biće uvezeno %d stavki:"},
		{" (%d replacing entries already in the vault)", " (%d replacing entries already in the vault)"}: {" (%d od njih zamenjuje stavku koja već postoji u trezoru)", " (%d od njih zamenjuju stavke koje već postoje u trezoru)", " (%d od njih zamenjuje stavke koje već postoje u trezoru)"},
		{"Would import %d entry%s.", "Would import %d entries%s."}:                                       {"Biće uvezena %d stavka%s.", "Biće uvezene %d stavke%s.", "Biće uvezeno %d stavki%s."},
		{"Would skip %d: %s.", "Would skip %d: %s."}:                                                     {"Biće preskočena %d datoteka (%s).", "Biće preskočene %d datoteke (%s).", "Biće preskočeno %d datoteka (%s)."},
		{"Skipped %d: %s.", "Skipped %d: %s."}:                                                           {"Preskočena je %d datoteka (%s).", "Preskočene su %d datoteke (%s).", "Preskočeno je %d datoteka (%s)."},
		{"Imported %d entry%s from %s.", "Imported %d entries%s from %s."}:                               {"Uvezena je %d stavka%s iz %s.", "Uvezene su %d stavke%s iz %s.", "Uvezeno je %d stavki%s iz %s."},
		// internal/cli/printcmd.go
		{"printed %d entry (text sheet) to %s; print it, then delete the file", "printed %d entries (text sheet) to %s; print it, then delete the file"}: {"tekstualni list je upisan u %[2]s: %[1]d stavka; odštampajte ga, pa obrišite datoteku", "tekstualni list je upisan u %[2]s: %[1]d stavke; odštampajte ga, pa obrišite datoteku", "tekstualni list je upisan u %[2]s: %[1]d stavki; odštampajte ga, pa obrišite datoteku"},
		// internal/cli/sys_linux.go
		{"%d swap area is active (%s): process memory, decrypted secrets included, may be written to disk. passh doesn't change this; turn swap off or encrypt it if that matters to you", "%d swap areas are active (%s): process memory, decrypted secrets included, may be written to disk. passh doesn't change this; turn swap off or encrypt it if that matters to you"}: {"%d swap oblast je aktivna (%s): memorija procesa, uključujući dešifrovane tajne, može da se upiše na disk. passh to ne menja; isključite swap ili ga šifrujte ako vam je to važno", "%d swap oblasti su aktivne (%s): memorija procesa, uključujući dešifrovane tajne, može da se upiše na disk. passh to ne menja; isključite swap ili ga šifrujte ako vam je to važno", "%d swap oblasti je aktivno (%s): memorija procesa, uključujući dešifrovane tajne, može da se upiše na disk. passh to ne menja; isključite swap ili ga šifrujte ako vam je to važno"},
	},
}
