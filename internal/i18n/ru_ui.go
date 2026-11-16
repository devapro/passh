package i18n

// ruUI holds the Russian messages of internal/{tty,editor,print,printweb,
// clipboard,session,harden}.
var ruUI = catalog{
	msgs: map[string]string{
		// internal/tty/tty.go
		"no terminal":                         "нет терминала",
		"interrupted":                         "прервано",
		"not confirmed":                       "не подтверждено",
		"passphrases don't match":             "парольные фразы не совпадают",
		"%w: /dev/tty is not a terminal":      "%w: /dev/tty — не терминал",
		"%w: %s is not a terminal":            "%w: %s — не терминал",
		"reading the passphrase: %w":          "чтение парольной фразы: %w",
		"reading the input: %w":               "чтение ввода: %w",
		"input longer than %d bytes":          "ввод длиннее %d байт",
		"passphrase longer than %d bytes":     "парольная фраза длиннее %d байт",
		"input line longer than %d bytes":     "введённая строка длиннее %d байт",
		"reading from the terminal: %w":       "чтение с терминала: %w",
		"New passphrase: ":                    "Новая парольная фраза: ",
		"Repeat passphrase: ":                 "Повторите парольную фразу: ",
		"The passphrase must not be empty.":   "Парольная фраза не может быть пустой.",
		"Passphrases don't match. Try again.": "Парольные фразы не совпадают. Попробуйте ещё раз.",
		" [y/N] ":                             " [д/Н] ",
		" [Y/n] ":                             " [Д/н] ",
		"Please answer y or n.\n":             "Ответьте д или н.\n",
		"Type %s to confirm: ":                "Для подтверждения введите %s: ",
		"%w: no answer":                       "%w: нет ответа",
		"%w: you didn't type %s":              "%w: вы не ввели %s",

		// internal/editor/form.go
		"cancelled":              "отменено",
		"the form is still open": "форма ещё открыта",
		"Discard the changes? esc: discard · any other key: keep editing": "Отбросить несохранённые изменения? esc: отбросить · любая другая клавиша: продолжить редактирование",
		"paste refused: the text is not valid UTF-8":                      "вставка отклонена: текст не является корректным UTF-8",
		"paste refused: %s is a single line and the text has line breaks": "вставка отклонена: %s — однострочное поле, а в тексте есть переводы строк",
		"Password shown; it hides again in %d s (ctrl+r hides it now).":   "Пароль показан; он скроется через %d с (ctrl+r — скрыть сейчас).",
		"Generating a password failed: %v":                                "Не удалось сгенерировать пароль: %v",
		"(empty)":                                                         "(пусто)",
		"changed":                                                         "изменён",
		"ctrl+s save":                                                     "ctrl+s сохранить",
		"esc cancel":                                                      "esc отменить",
		"tab next":                                                        "tab далее",
		"enter new line":                                                  "enter новая строка",
		"ctrl+r hide password":                                            "ctrl+r скрыть пароль",
		"ctrl+r show password":                                            "ctrl+r показать пароль",
		"ctrl+g generate":                                                 "ctrl+g сгенерировать",
		"%s (kept as they are; edit them with --editor)":                  "%s (сохраняются как есть; изменить их можно через --editor)",

		// internal/editor/run.go
		"the entry form needs a terminal: %w": "для формы записи нужен терминал: %w",
		"entry form: %w":                      "форма записи: %w",

		// internal/editor/external.go
		"no tmpfs for the temporary file": "нет tmpfs для временного файла",
		"no change":                       "изменений нет",
		"editing interrupted":             "редактирование прервано",
		"%w (checked %s and %s): the entry would be written to disk in plain text; use the built-in form (passh edit without --editor)": "%w (проверено: %s и %s): запись попала бы на диск открытым текстом; используйте встроенную форму (passh edit без --editor)",
		"%w (checked %s): the entry would be written to disk in plain text; use the built-in form (passh edit without --editor)":        "%w (проверено: %s): запись попала бы на диск открытым текстом; используйте встроенную форму (passh edit без --editor)",
		"the editor command is empty": "команда редактора пуста",
		"passh can't control backup, swap or history files of %s: they may keep a copy of the entry on disk. " +
			"Graphical editors must also wait until the file is closed (e.g. code --wait).": "passh не может управлять файлами резервных копий, подкачки и истории редактора %s: в них может остаться копия записи на диске. " +
			"Кроме того, графический редактор должен ждать, пока файл не закроют (например, code --wait).",
		"line %d: the text is not valid UTF-8":        "строка %d: текст не является корректным UTF-8",
		"the editor needs a terminal: %w":             "для редактора нужен терминал: %w",
		"%w by %v; nothing was changed":               "%w сигналом %v; ничего не изменено",
		"creating the temporary folder: %w":           "создание временной папки: %w",
		"%w: %s is not on tmpfs":                      "%w: %s не на tmpfs",
		"%w: %w; nothing was changed":                 "%w: %w; ничего не изменено",
		"the editor failed (%w); nothing was changed": "редактор завершился с ошибкой (%w); ничего не изменено",
		"creating the temporary file: %w":             "создание временного файла: %w",
		"writing the temporary file: %w":              "запись временного файла: %w",
		"reading the edited file: %w":                 "чтение отредактированного файла: %w",
		"the edited file is larger than %d MiB":       "отредактированный файл больше %d MiB",
		"removing the temporary folder %s: %w; remove it yourself, it holds the entry in plain text": "удаление временной папки %s: %w; удалите её сами, в ней запись открытым текстом",

		// internal/print/doc.go, txt.go, layout.go, qr.go
		"CONFIDENTIAL":   "КОНФИДЕНЦИАЛЬНО",
		"page %d of %d":  "страница %d из %d",
		"%s (continued)": "%s (продолжение)",
		"QR code: %w":    "QR-код: %w",

		// internal/print/recovery.go
		"recovery sheet: no vault key": "лист с ключом восстановления: нет ключа хранилища",
		"recovery sheet: no vault_id":  "лист с ключом восстановления: нет vault_id",
		// Short: with CONFIDENTIAL, the date and the page number it must
		// fit the 80 columns of the text sheet's header.
		"passh paper recovery key": "ключ восстановления passh",
		"printed %s":               "напечатано %s",
		"Whoever has this sheet and a copy of the vault can read everything in the vault.": "Тот, у кого есть этот лист и копия хранилища, может прочитать всё, что есть в хранилище.",
		"Keep it offline, like cash. If it may have been seen, copied or lost, run `passh rekey` " +
			"and print a new sheet: the old key then no longer opens new versions of the vault " +
			"(copies made before still open with it).": "Храните его офлайн, как наличные. Если лист могли увидеть, скопировать или потерять, " +
			"выполните `passh rekey` и распечатайте новый лист: тогда старый ключ перестанет открывать " +
			"новые версии хранилища (сделанные раньше копии он по-прежнему открывает).",
		"Vault key": "Ключ хранилища",
		"After AGE-SECRET-KEY-1 the key never has the letters B, I or O or the digit 1: " +
			"0 is always the digit zero.": "После AGE-SECRET-KEY-1 в ключе не бывает букв B, I и O и цифры 1: " +
			"0 — это всегда цифра ноль.",
		"The key's QR code is on the web page (`passh recovery-key print --web`).": "QR-код ключа есть на веб-странице (`passh recovery-key print --web`).",
		"Forgotten passphrase": "Если забыта парольная фраза",
		"Run `passh recover` and type the key above. Spaces, line breaks and letter case are " +
			"ignored, and the key's checksum catches typos. passh then asks for a new passphrase.": "Выполните `passh recover` и введите ключ, напечатанный выше. Пробелы, переводы строк и регистр " +
			"букв не важны, а контрольная сумма ключа выявляет опечатки. Затем passh запросит новую парольную фразу.",
		"Without passh": "Без passh",
		// the shell comment of the third command; the command stays as is
		"asks for the passphrase": "запросит парольную фразу",
		"On any machine with age (https://age-encryption.org) v1.0 or later, where vault.passh " +
			"is a copy of the vault file:": "На любой машине с age (https://age-encryption.org) версии 1.0 или новее, где vault.passh — " +
			"копия файла хранилища:",
		"With this key instead of the passphrase: write it to /dev/shm/key.txt as one line, " +
			"without spaces, in capital letters as printed (AGE-SECRET-KEY-1 and then the groups), " +
			"instead of running the first and third commands. The other commands stay the same.": "С этим ключом вместо парольной фразы: вместо первой и третьей команд запишите ключ в " +
			"/dev/shm/key.txt одной строкой, без пробелов, заглавными буквами, как напечатано " +
			"(AGE-SECRET-KEY-1, затем группы). Остальные команды не меняются.",
		"vault.json is plaintext. Keep it on tmpfs (/dev/shm on Linux) and delete it when done.": "vault.json — открытый текст. Держите его на tmpfs (/dev/shm в Linux) и удалите после использования.",
		"If a mail client or editor re-wrapped the lines, age may reject the blocks. passh still " +
			"opens such a file, and `passh backup` writes it back in canonical form.": "Если почтовый клиент или редактор перенёс строки, age может отклонить блоки. passh такой файл " +
			"всё равно открывает, а `passh backup` записывает его обратно в канонической форме.",

		// internal/print/sheet.go
		"no entries to print": "нет записей для печати",
		"invalid field":       "недопустимое поле",
		"%w %q: use %s, or the key of a custom field":        "%w %q: используйте %s или ключ дополнительного поля",
		"%w: no fields to print":                             "%w: нет полей для печати",
		"%w: the vault has no entries":                       "%w: в хранилище нет записей",
		"%w: none matches %s":                                "%w: нет совпадений (%s)",
		"%w %q: no selected entry has a field with this key": "%w %q: ни у одной выбранной записи нет поля с таким ключом",
		"folder %s":            "папка %s",
		"tag %s":               "тег %s",
		"tags %s":              "теги %s",
		"passh password sheet": "лист паролей passh",
		"fields: %s":           "поля: %s",
		"(top level)":          "(верхний уровень)",
		"Under 0 O 1 l I and spaces: D digit, U capital letter, L small letter, S space": "Под 0 O 1 l I и пробелами: D — цифра, U — заглавная, L — строчная, S — пробел",
		`%s continues the line above; \uXXXX is a character that can't be printed`:       `%s продолжает строку выше; \uXXXX — символ, который нельзя напечатать`,

		// internal/printweb/page.go
		"Print with Ctrl+P (Cmd+P on a Mac), then close this tab. This page was served once " +
			"and is gone from passh; the browser may still keep it in its session history.": "Распечатайте страницу (Ctrl+P, на Mac — Cmd+P) и закройте эту вкладку. Страница выдаётся " +
			"только один раз, и в passh её уже нет, но браузер может сохранить её в истории сеанса.",
		"QR code of the vault key": "QR-код ключа хранилища",

		// internal/printweb/cert.go
		"made a new certificate for the print page (%s); browsers will warn about it: compare the fingerprint": "для страницы печати создан новый сертификат (%s); браузеры будут о нём предупреждать: сверьте отпечаток",
		"first use": "первое использование",
		"the stored certificate can't be read: %v":                         "сохранённый сертификат не читается: %v",
		"the stored key can't be read: %v":                                 "сохранённый ключ не читается: %v",
		"the stored key is not a regular file":                             "сохранённый ключ — не обычный файл",
		"the stored key had mode %04o, readable by others":                 "у сохранённого ключа были права %04o, его могли читать другие",
		"the stored certificate can't be used: %v":                         "сохранённый сертификат нельзя использовать: %v",
		"the stored certificate is not valid until %s":                     "сохранённый сертификат действителен только с %s",
		"the stored certificate expired on %s":                             "срок действия сохранённого сертификата истёк %s",
		"the stored certificate expires on %s":                             "срок действия сохранённого сертификата истекает %s",
		"the addresses or hostnames changed: the old one doesn't cover %s": "адреса или имена хостов изменились: старый сертификат не покрывает %s",
		"not an ECDSA P-256 key":                                           "это не ключ ECDSA P-256",
		"print page certificate: %w":                                       "сертификат страницы печати: %w",
		"print page certificate folder: %w":                                "папка сертификата страницы печати: %w",
		"print page certificate folder %s is not a folder":                 "папка сертификата страницы печати %s — не папка",

		// internal/printweb/net.go
		"no such network interface": "нет такого сетевого интерфейса",
		"no address":                "нет адреса",
		"%s: the print page never listens on all addresses (0.0.0.0 or ::)": "%s: страница печати никогда не слушает на всех адресах (0.0.0.0 или ::)",
		"%s: not a private address":                                         "%s: не частный адрес",
		"%s is not a private address: the print page listens only on " +
			"10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 and fc00::/7, never on a public address": "%s — не частный адрес: страница печати слушает только на " +
			"10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 и fc00::/7 и никогда на публичном адресе",
		"print_web.interfaces is empty: name the interfaces of your LAN or VPN, e.g. [\"eth0\", \"wg0\"]": "print_web.interfaces пуст: укажите интерфейсы вашей локальной сети или VPN, например [\"eth0\", \"wg0\"]",
		"%s: no address":                 "%s: нет адреса",
		"%s: %s is link-local, not used": "%s: %s — адрес link-local, не используется",
		"the print page has no private address to listen on (print_web.interfaces): %s": "у страницы печати нет частного адреса, на котором можно слушать (print_web.interfaces): %s",
		"%s: %s is the wildcard address, never used":                                    "%s: %s — адрес всех интерфейсов, никогда не используется",
		"%s: %s is a loopback address, not private":                                     "%s: %s — адрес loopback, не частный",
		"%s: %s is a multicast address, not used":                                       "%s: %s — групповой адрес (multicast), не используется",
		"%s: %s is a public address, refused":                                           "%s: %s — публичный адрес, отклонён",

		// internal/printweb/server.go
		"the print page is off: set enabled = true in the [print_web] table of the config file": "страница печати выключена: задайте enabled = true в таблице [print_web] конфигурационного файла",
		"the page was served to %s; if that wasn't you, start the print page again":             "страница выдана адресу %s; если это были не вы, запустите страницу печати заново",
		"the page was only partly sent to %s (%v); start the print page again":                  "страница лишь частично отправлена адресу %s (%v); запустите страницу печати заново",
		"the print page stopped after %s without being opened":                                  "страница печати остановлена: за %s её никто не открыл",
		"the print page was stopped while it was sent to %s":                                    "страница печати остановлена во время отправки адресу %s",
		"the print page was stopped":                                                            "страница печати остановлена",
		"the print page stopped":                                                                "страница печати завершила работу",
		"print page: nothing to print":                                                          "страница печати: нечего печатать",
		"print_web.ttl: %s is not between %s and %s":                                            "print_web.ttl: %s не в пределах от %s до %s",
		"print_web.port: %d is not between 1 and 65535":                                         "print_web.port: %d не в пределах от 1 до 65535",
		"print_web.hostnames: %q is not a hostname":                                             "print_web.hostnames: %q — не имя хоста",
		"print page: %w":                                    "страница печати: %w",
		"misdirected request: unknown host":                 "запрос не по адресу: неизвестный хост",
		"method not allowed":                                "метод не разрешён",
		"already used: start the print page again in passh": "страница уже использована: запустите страницу печати в passh заново",
		"stopped after too many wrong addresses: start the print page again in passh": "страница остановлена после слишком многих неверных адресов: запустите страницу печати в passh заново",

		// internal/clipboard/clipboard.go
		"clipboard command":               "команда буфера обмена",
		"clipboard method\x04none":        "нет",
		"no clipboard":                    "нет буфера обмена",
		"clearing the clipboard failed":   "не удалось очистить буфер обмена",
		"no clipboard: %s; copy with: %s": "нет буфера обмена: %s; скопируйте так: %s",
		"clipboard.command: the program name (first element) is empty":              "clipboard.command: имя программы (первый элемент) пустое",
		"clipboard.osc52 is off and clipboard.command is empty":                     "clipboard.osc52 выключен, а clipboard.command пуст",
		"OSC 52 needs a terminal and there is none, and clipboard.command is empty": "для OSC 52 нужен терминал, а его нет, и clipboard.command пуст",
		"command %q":                             "команда %q",
		"OSC 52 through the terminal":            "OSC 52 через терминал",
		"clipboard: writing to the terminal: %w": "буфер обмена: запись в терминал: %w",
		"clipboard command: %w":                  "команда буфера обмена: %w",
		"clipboard: no method":                   "буфер обмена: нет способа копирования",
		"%w (%s), and %v: %w":                    "%w (%s), и %v: %w",
		"%w (%s); the clipboard was cleared":     "%w (%s); буфер обмена очищен",
		"inside tmux: OSC 52 needs `set -g set-clipboard on` in ~/.tmux.conf":                                              "внутри tmux: для OSC 52 нужно `set -g set-clipboard on` в ~/.tmux.conf",
		"inside GNU screen: screen doesn't pass OSC 52 to the terminal; set clipboard.command or run passh outside screen": "внутри GNU screen: screen не передаёт OSC 52 терминалу; задайте clipboard.command или запускайте passh вне screen",
		`Terminal.app has no OSC 52: set clipboard.command = ["pbcopy"]`:                                                   `в Terminal.app нет OSC 52: задайте clipboard.command = ["pbcopy"]`,

		// internal/session/session.go
		"locked":                  "заблокировано",
		"locked on exit":          "заблокировано при выходе",
		"locked after inactivity": "заблокировано из-за бездействия",
		"locked by a signal":      "заблокировано сигналом",

		// internal/harden/harden.go
		"disabling core dumps: %w":    "отключение дампов памяти: %w",
		"reading core dump limit: %w": "чтение ограничения на дампы памяти: %w",
	},
	plurals: map[pluralKey][3]string{
		// internal/editor/form.go
		{"Generated a new password (%d character); it is shown.", "Generated a new password (%d characters); it is shown."}: {
			"Сгенерирован новый пароль (%d символ); он показан.",
			"Сгенерирован новый пароль (%d символа); он показан.",
			"Сгенерирован новый пароль (%d символов); он показан.",
		},
		{"Generated a new password (%d character); ctrl+r shows it.", "Generated a new password (%d characters); ctrl+r shows it."}: {
			"Сгенерирован новый пароль (%d символ); ctrl+r — показать.",
			"Сгенерирован новый пароль (%d символа); ctrl+r — показать.",
			"Сгенерирован новый пароль (%d символов); ctrl+r — показать.",
		},

		// internal/print/sheet.go
		{"%d entry", "%d entries"}: {"%d запись", "%d записи", "%d записей"},

		// internal/printweb/server.go
		{"the print page stopped after %d request with a wrong address", "the print page stopped after %d requests with a wrong address"}: {
			"страница печати остановлена после %d запроса с неверным адресом",
			"страница печати остановлена после %d запросов с неверным адресом",
			"страница печати остановлена после %d запросов с неверным адресом",
		},
	},
}
