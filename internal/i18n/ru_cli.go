package i18n

// ruCLI holds the Russian messages of internal/cli and cmd/passh.
var ruCLI = catalog{
	msgs: map[string]string{
		// internal/cli/help.go: cobra's help and usage
		"Usage:":                  "Использование:",
		"Aliases:":                "Псевдонимы:",
		"Examples:":               "Примеры:",
		"Available Commands:":     "Доступные команды:",
		"Additional Commands:":    "Дополнительные команды:",
		"Flags:":                  "Флаги:",
		"Global Flags:":           "Глобальные флаги:",
		"Additional help topics:": "Дополнительные разделы справки:",
		"Use \"%s [command] --help\" for more information about a command.": "Подробнее о команде: \"%s [command] --help\".",
		"help for %s":            "справка по %s",
		"version for %s":         "версия %s",
		"Help about any command": "Справка по любой команде",
		"Help provides help for any command in the application.\n" +
			"Simply type %s help [path to command] for full details.": "Справка по любой команде программы.\nНаберите %s help [путь к команде], чтобы увидеть подробности.",
		"Unknown help topic %#q\n": "Неизвестный раздел справки %#q\n",
		"(default %s)":             "(по умолчанию %s)",
		"(DEPRECATED: %s)":         "(УСТАРЕЛО: %s)",

		// internal/cli/cli.go
		"A password manager with one encrypted vault file": "Менеджер паролей с одним зашифрованным файлом хранилища",
		"passh keeps passwords in one age-encrypted vault file.\n" +
			"\n" +
			"Run `passh init` to create a vault, then `passh` alone for the TUI. Commands that\n" +
			"read or change entries ask for the passphrase on the terminal, or use the agent\n" +
			"started by `passh unlock`.": "passh хранит пароли в одном файле хранилища, зашифрованном age.\n" +
			"\n" +
			"Запустите `passh init`, чтобы создать хранилище, затем `passh` без аргументов\n" +
			"для TUI. Команды, которые читают или меняют записи, спрашивают парольную фразу\n" +
			"в терминале или используют агент, запущенный `passh unlock`.",
		"Run 'passh --help' or 'passh <command> --help' for usage.": "Справка: 'passh --help' или 'passh <command> --help'.",

		// internal/cli/initcmd.go
		"Creating the vault %s.\n" +
			"Choose a passphrase: 6 or more random words are best.\n": "Создание хранилища %s.\n" +
			"Придумайте парольную фразу: лучше всего 6 или больше случайных слов.\n",
		"Created the vault %s.": "Хранилище %s создано.",

		// internal/cli/agentcmd.go
		"Start the agent: no passphrase prompts for a while, also without a terminal": "Запустить агент: парольная фраза какое-то время не нужна, даже без терминала",
		"Ask for the passphrase and start the agent, which keeps the vault key in memory\n" +
			"so later commands, including ones without a terminal (ssh host passh show …),\n" +
			"don't ask for it. The agent exits after agent.idle_ttl without use, after\n" +
			"agent.max_ttl (or --ttl) in any case, and on `passh lock`.\n" +
			"\n" +
			"With an agent already running for the vault, unlock restarts its idle time and\n" +
			"says how long it has left. --ttl only applies to a new agent: passh says when it\n" +
			"wasn't applied (run `passh lock` first).": "Спрашивает парольную фразу и запускает агент, который держит ключ хранилища в\n" +
			"памяти, чтобы следующие команды, в том числе без терминала\n" +
			"(ssh host passh show …), её не спрашивали. Агент завершается после\n" +
			"agent.idle_ttl без использования, в любом случае после agent.max_ttl (или\n" +
			"--ttl) и по `passh lock`.\n" +
			"\n" +
			"Если для хранилища уже запущен агент, unlock заново начинает отсчёт его простоя\n" +
			"и сообщает, сколько ему осталось. --ttl действует только на новый агент: passh\n" +
			"сообщает, если флаг не применён (сначала выполните `passh lock`).",
		"--ttl must be more than zero": "--ttl должен быть больше нуля",
		"the running agent was unlocked with another key block (passwd elsewhere?); replacing it":        "запущенный агент разблокирован другим блоком ключа (passwd в другом месте?); он будет заменён",
		"passh unlock needs a terminal to ask for the passphrase (over SSH: `ssh -t host passh unlock`)": "для passh unlock нужен терминал, чтобы спросить парольную фразу (по SSH: `ssh -t host passh unlock`)",
		"Unlocked %s: %s.\nRun `passh lock` to stop the agent now.":                                      "Хранилище %s разблокировано: %s.\nЧтобы остановить агент сейчас, выполните `passh lock`.",
		"stop a new agent after this long in any case (overrides agent.max_ttl), e.g. 30m":               "остановить новый агент через это время в любом случае (вместо agent.max_ttl), например 30m",
		"an agent is running, but the vault can't be checked against it: %w":                             "агент запущен, но сверить с ним хранилище не удаётся: %w",
		"an agent is running, but the vault can't be checked against it: %s: %w":                         "агент запущен, но сверить с ним хранилище не удаётся: %s: %w",
		"Already unlocked: %s.": "Уже разблокировано: %s.",
		"--ttl was not applied: the agent was already running; run `passh lock`, then `passh unlock --ttl …`": "--ttl не применён: агент уже был запущен; выполните `passh lock`, затем `passh unlock --ttl …`",
		"the agent (pid %d) exits in %s":                                "агент (pid %d) завершится через %s",
		"the agent (pid %d) exits in %s if unused, in %s at the latest": "агент (pid %d) завершится через %s, если им не пользоваться, но не позже чем через %s",
		"Stop the agent":                                               "Остановить агент",
		"No agent is running for %s.":                                  "Для %s агент не запущен.",
		"Locked: the agent (pid %d) stopped.":                          "Заблокировано: агент (pid %d) остановлен.",
		"the agent couldn't be stopped: %v; stop it with `passh lock`": "не удалось остановить агент: %v; остановите его командой `passh lock`",
		"The agent held the old key and was stopped; run `passh unlock` again if you need it.":                    "Агент хранил старый ключ и был остановлен; если он нужен, снова выполните `passh unlock`.",
		"The agent was unlocked with the old key block and was stopped; run `passh unlock` again if you need it.": "Агент был разблокирован старым блоком ключа и остановлен; если он нужен, снова выполните `passh unlock`.",

		// internal/cli/cli.go
		"warning: ": "предупреждение: ",
		"%s needs a terminal (over SSH: use `ssh -t`)":                          "для %s нужен терминал (по SSH: используйте `ssh -t`)",
		"unknown command %q for passh":                                          "неизвестная команда %q для passh",
		"config file (default $PASSH_CONFIG, then ~/.config/passh/config.toml)": "конфигурационный файл (по умолчанию $PASSH_CONFIG, затем ~/.config/passh/config.toml)",
		"vault file, overriding the config's vault (no config file needed)":     "файл хранилища вместо указанного в конфигурации (конфигурационный файл не нужен)",
		"Print passh's version":                                                 "Вывести версию passh",
		"accepts %d arg(s), received %d":                                        "принимает аргументов: %d, получено: %d",
		"accepts between %d and %d arg(s), received %d":                         "принимает от %d до %d аргументов, получено: %d",
		"unknown command %q for %q":                                             "неизвестная команда %q для %q",

		// internal/cli/copy.go
		"Copy a field (default: the password) to the clipboard, cleared after a while": "Скопировать поле (по умолчанию пароль) в буфер обмена на время",
		"Copy the password, or another field, to the clipboard: through the terminal\n" +
			"(OSC 52, which works over SSH) or with clipboard.command. passh waits and clears\n" +
			"the clipboard after clipboard.clear_after; Ctrl-C clears it at once. The value\n" +
			"is never printed.": "Копирует пароль или другое поле в буфер обмена: через терминал (OSC 52,\n" +
			"работает и по SSH) или командой clipboard.command. passh ждёт и очищает буфер\n" +
			"обмена через clipboard.clear_after; Ctrl-C очищает его сразу. Значение никогда\n" +
			"не выводится.",
		"%s has no field %q":                      "у записи %s нет поля %q",
		"%s: the %s is empty; nothing was copied": "%s: поле %s пустое; ничего не скопировано",
		"Copied the %s of %s (%s); the clipboard clears in %s, Ctrl-C clears it now.": "Поле %s записи %s скопировано (%s); буфер обмена очистится через %s, Ctrl-C очистит его сейчас.",
		"field to copy: password, username, url, tags, notes or a custom field":       "поле для копирования: password, username, url, tags, notes или дополнительное поле",
		"Clipboard cleared.":  "Буфер обмена очищен.",
		"%w (%s), and %v: %w": "%w (%s), и %v: %w",

		// internal/cli/doctor.go
		"doctor\u0004ok":           "ок",
		"doctor\u0004info":         "инфо",
		"doctor\u0004skip":         "пропуск",
		"doctor\u0004warn":         "внимание",
		"doctor\u0004error":        "ошибка",
		"doctor\u0004config":       "конфигурация",
		"doctor\u0004vault":        "хранилище",
		"doctor\u0004vault mode":   "права хранилища",
		"doctor\u0004vault folder": "папка хранилища",
		"doctor\u0004temp files":   "временные файлы",
		"doctor\u0004state folder": "папка состояния",
		"doctor\u0004agent":        "агент",
		"doctor\u0004agent folder": "папка агента",
		"doctor\u0004memory":       "память",
		"doctor\u0004swap":         "swap",
		"doctor\u0004core dumps":   "дампы памяти",
		"doctor\u0004terminal":     "терминал",
		"doctor\u0004edit temp":    "файлы edit",
		"doctor\u0004clipboard":    "буфер обмена",
		"Check the config, the vault file, the state and agent folders, memory and swap": "Проверить конфигурацию, хранилище, папки, агент, память и swap",
		"Read-only checks of everything passh depends on: the config file, the vault\n" +
			"file (structure, mode 0600, writable folder, leftover temporary files), the\n" +
			"state and agent folders, the agent, free memory for unlock (scrypt needs\n" +
			"256 MiB), swap, core dumps and the terminal. It reports, never fixes. The exit\n" +
			"status is 1 if a check found an error; warnings are advice.": "Проверяет всё, от чего зависит passh, ничего не меняя: конфигурационный файл,\n" +
			"файл хранилища (структура, права 0600, доступность папки для записи, оставшиеся\n" +
			"временные файлы), папки состояния и агента, агент, свободную память для\n" +
			"разблокировки (scrypt нужно 256 MiB), swap, дампы памяти и терминал. Только\n" +
			"сообщает, ничего не исправляет. Код выхода — 1, если хотя бы одна проверка\n" +
			"нашла ошибку; предупреждения — это советы.",
		"no config file at %s; using --vault and the defaults":                                              "конфигурационного файла %s нет; используются --vault и значения по умолчанию",
		"--vault overrides the config's vault":                                                              "--vault заменяет хранилище из конфигурации",
		"no config, so no vault to check":                                                                   "нет конфигурации, поэтому хранилище не проверяется",
		"%s doesn't exist: run `passh init`, or point the config's vault at your vault file":                "%s не существует: выполните `passh init` или укажите в vault конфигурации ваш файл хранилища",
		"%s is a symlink that can't be resolved: %v":                                                        "%s — символическая ссылка, которую не удаётся разрешить: %v",
		"%s is a symlink to %s; saves write the target":                                                     "%s — символическая ссылка на %s; сохранение записывает в файл, на который она указывает",
		"%s: %v (SHA-256 %s)":                                                                               "%s: %v (SHA-256 %s)",
		"not in canonical form (line endings or wrapping changed); it opens, and the next save rewrites it": "не в канонической форме (изменились окончания строк или переносы); файл открывается, а следующее сохранение перепишет его",
		"mode %04o, not 0600: fix it with chmod 600 %s":                                                     "права %04o, а не 0600: исправьте командой chmod 600 %s",
		"%s isn't writable (%v): saving needs a temporary file there":                                       "в %s нельзя писать (%v): для сохранения там нужен временный файл",
		"%s is writable":                    "в %s можно писать",
		"can't list the vault's folder: %v": "не удаётся прочитать список файлов папки хранилища: %v",
		"none":                              "нет",
		"%s doesn't exist yet; the first save creates it":                                                "%s пока не существует; её создаст первое сохранение",
		"%s is not a folder (backups, locks and the agent's socket go there)":                            "%s — не папка (там хранятся резервные копии, блокировки и сокет агента)",
		"%s belongs to uid %d, not to you":                                                               "%s принадлежит uid %d, а не вам",
		"%s isn't writable: %v":                                                                          "в %s нельзя писать: %v",
		"%s has mode %04o: other users can look inside (the backups are encrypted); chmod 700 is better": "у %s права %04o: другие пользователи могут заглянуть внутрь (резервные копии зашифрованы); лучше chmod 700",
		"no vault to check the agent for":                                                                "нет хранилища, для которого можно проверить агент",
		"%s doesn't exist yet; `passh unlock` creates it":                                                "%s пока не существует; её создаст `passh unlock`",
		"%s (0700, yours)":                                         "%s (0700, ваша)",
		"not running (`passh unlock` starts it)":                   "не запущен (его запускает `passh unlock`)",
		"running: %s":                                              "запущен: %s",
		"disabled for passh and the agent":                         "отключены для passh и агента",
		"not disabled: a crash could write secrets to a core file": "не отключены: при сбое секреты могут попасть в core-файл",
		"none: prompts are impossible, so commands need the agent (`passh unlock` in a terminal)": "нет: запросы невозможны, поэтому командам нужен агент (`passh unlock` в терминале)",
		"/dev/tty: passphrase prompts work":                                                                          "/dev/tty: запрос парольной фразы работает",
		"no files left by an interrupted `edit --editor`":                                                            "нет файлов, оставшихся от прерванного `edit --editor`",
		"left by an interrupted `edit --editor`, possibly with an entry in plain text: %s; delete them (rm -r)":      "остались от прерванного `edit --editor`, возможно, с записью в открытом виде: %s; удалите их (rm -r)",
		"no config, so no clipboard settings to check":                                                               "нет конфигурации, поэтому настройки буфера обмена не проверяются",
		"not tested without a terminal: run `passh doctor` in one (over SSH: ssh -t)":                                "без терминала не проверяется: запустите `passh doctor` в терминале (по SSH: ssh -t)",
		"Testing the clipboard: copied %q (%s). Paste it somewhere to check; it is cleared in %s.\n":                 "Проверка буфера обмена: скопировано %q (%s). Вставьте это куда-нибудь для проверки; буфер очистится через %s.\n",
		"sent a test string with command %q and cleared it; if pasting gave %q, copying works":                       "проверочная строка отправлена командой %q и стёрта; если вставилось %q, копирование работает",
		"sent a test string with OSC 52 through the terminal and cleared it; if pasting gave %q, copying works":      "проверочная строка отправлена через терминал (OSC 52) и стёрта; если вставилось %q, копирование работает",
		"%s in total: unlock needs 256 MiB for scrypt and may fail or swap; available memory isn't checked on macOS": "всего %s: разблокировке нужно 256 MiB для scrypt, она может не удаться или использовать swap; на macOS доступная память не проверяется",
		"%s available: unlock needs 256 MiB for scrypt and may fail or swap":                                         "доступно %s: разблокировке нужно 256 MiB для scrypt, она может не удаться или использовать swap",
		"%s in total (unlock needs 256 MiB); available memory isn't checked on macOS":                                "всего %s (разблокировке нужно 256 MiB); на macOS доступная память не проверяется",
		"%s available (unlock needs 256 MiB)":                                                                        "доступно %s (разблокировке нужно 256 MiB)",

		// internal/cli/edit.go
		"Add an entry interactively: password (or generate), username, url, tags, notes": "Добавить запись интерактивно: пароль, логин, url, теги, заметки",
		"%s already exists: use --force to replace it":                                   "запись %s уже существует: чтобы заменить её, добавьте --force",
		"Saved %s.":                         "Запись %s сохранена.",
		"replace an existing entry":         "заменить существующую запись",
		"Username: ":                        "Имя пользователя: ",
		"URL: ":                             "URL: ",
		"Tags (comma-separated): ":          "Теги (через запятую): ",
		"Notes (end with an empty line):\n": "Заметки (завершите пустой строкой):\n",
		"Password (empty to generate): ":    "Пароль (пусто — сгенерировать): ",
		"Repeat password: ":                 "Повторите пароль: ",
		"Passwords don't match. Try again.": "Пароли не совпадают. Попробуйте ещё раз.",
		"passwords don't match":             "пароли не совпадают",
		"Generate and store a password":     "Сгенерировать и сохранить пароль",
		"Generate a random password (default 24 letters and digits) and store it.\n" +
			"\n" +
			"A new path makes a new entry. For an existing entry, --force replaces its\n" +
			"password and keeps its other values (username, url, tags, fields, notes).\n" +
			"The password is not printed; show it with `passh show <path> --field password`.": "Генерирует случайный пароль (по умолчанию 24 буквы и цифры) и сохраняет его.\n" +
			"\n" +
			"Новый путь создаёт новую запись. Для существующей записи --force заменяет её\n" +
			"пароль и сохраняет остальные значения (username, url, tags, fields, notes).\n" +
			"Пароль не выводится; показать его: `passh show <path> --field password`.",
		"length %q: give a number from 1 to %d":                                              "длина %q: укажите число от 1 до %d",
		"%s already exists: use --force to replace its password (its other values are kept)": "запись %s уже существует: --force заменит её пароль (остальные значения сохранятся)",
		"letters and digits":                        "буквы и цифры",
		"letters, digits and symbols":               "буквы, цифры и символы",
		"also use punctuation characters":           "использовать также знаки препинания",
		"replace the password of an existing entry": "заменить пароль существующей записи",
		"Move or rename an entry or a folder":       "Переместить или переименовать запись или папку",
		"Move or rename an entry. A destination ending in / moves the entry into that\n" +
			"folder, keeping its name. If <src> is a folder, every entry in it moves, in\n" +
			"one save; nothing moves if any destination is taken.": "Перемещает или переименовывает запись. Если назначение оканчивается на /,\n" +
			"запись перемещается в эту папку под прежним именем. Если <src> — папка, все\n" +
			"записи в ней перемещаются за одно сохранение; если хотя бы одно назначение\n" +
			"занято, не перемещается ничего.",
		"Moved %s to %s.":                         "Запись %s перемещена в %s.",
		"can't move the folder %s into itself":    "нельзя переместить папку %s в саму себя",
		"Delete an entry (asks for confirmation)": "Удалить запись (с подтверждением)",
		"passh rm asks for confirmation on a terminal: run it in one, or add --force": "passh rm запрашивает подтверждение в терминале: запустите его в терминале или добавьте --force",
		"Delete %s?":                                      "Удалить %s?",
		"not deleted":                                     "не удалено",
		"Deleted %s.":                                     "Запись %s удалена.",
		"don't ask for confirmation":                      "не запрашивать подтверждение",
		"Add and remove tags of an entry":                 "Добавить или удалить теги записи",
		"give --add and/or --remove":                      "укажите --add и/или --remove",
		"%s: no tags":                                     "%s: тегов нет",
		"%s: no tags (unchanged)":                         "%s: тегов нет (без изменений)",
		"%s: tags %s":                                     "%s: теги %s",
		"%s: tags %s (unchanged)":                         "%s: теги %s (без изменений)",
		"tag to add (repeat, or separate with commas)":    "добавляемый тег (повторите флаг или перечислите через запятую)",
		"tag to remove (repeat, or separate with commas)": "удаляемый тег (повторите флаг или перечислите через запятую)",

		// internal/cli/editcmd.go
		"Edit an entry in the built-in form, or in $EDITOR": "Изменить запись во встроенной форме или в $EDITOR",
		"Edit an entry in the built-in form: password, username, url, tags and notes\n" +
			"(ctrl+s saves, esc cancels, ctrl+r reveals the password, ctrl+g generates one).\n" +
			"\n" +
			"--editor opens the entry's text form in $EDITOR instead, in a temporary file on\n" +
			"tmpfs that is wiped afterwards. vim, neovim and nano get flags that keep them\n" +
			"from writing swap, backup or history files. Where there is no tmpfs (macOS),\n" +
			"the built-in form is used.": "Изменяет запись во встроенной форме: пароль, имя пользователя, url, теги и\n" +
			"заметки (ctrl+s сохраняет, esc отменяет, ctrl+r показывает пароль, ctrl+g\n" +
			"генерирует его).\n" +
			"\n" +
			"--editor вместо этого открывает текстовую форму записи в $EDITOR, во временном\n" +
			"файле на tmpfs, который потом стирается. vim, neovim и nano запускаются с\n" +
			"флагами, которые не дают им писать файлы подкачки, резервных копий и истории.\n" +
			"Где tmpfs нет (macOS), используется встроенная форма.",
		"warning: %s\n":                "предупреждение: %s\n",
		"The entry isn't valid: %s\n":  "Запись некорректна: %s\n",
		"Edit it again?":               "Вернуться к редактированию?",
		"edit %s":                      "изменение %s",
		"No change.":                   "Изменений нет.",
		"cancelled; nothing was saved": "отменено; ничего не сохранено",
		"nothing was saved: %w":        "ничего не сохранено: %w",
		"edit the text form in $EDITOR (temporary file on tmpfs)":                          "изменить текстовую форму в $EDITOR (временный файл на tmpfs)",
		"%v; using the built-in form instead":                                              "%v; вместо этого используется встроенная форма",
		"The vault changed on disk since it was opened; reload and apply your edit again?": "Хранилище изменилось на диске после открытия; перечитать его и применить правку заново?",
		"not saved: %w": "не сохранено: %w",
		"not saved: the vault changed on disk since it was opened":   "не сохранено: хранилище изменилось на диске после открытия",
		"not saved: reloading the vault: %w":                         "не сохранено: перечитывание хранилища: %w",
		"not saved: %s was deleted or replaced in the vault on disk": "не сохранено: запись %s удалена или заменена в хранилище на диске",

		// internal/cli/entries.go
		"Print the tree of entries, optionally filtered by tag": "Вывести дерево записей, при необходимости с фильтром по тегу",
		"%s: no such folder": "%s: такой папки нет",
		"only entries with this tag (repeat for several: all must match)": "только записи с этим тегом (флаг можно повторить: нужны все теги)",
		"Fuzzy search on paths and tags":                                  "Нечёткий поиск по путям и тегам",
		"no entry matches %q":                                             "ни одна запись не подходит под %q",
		"Print an entry (text form) or one field":                         "Вывести запись (текстовая форма) или одно поле",
		"Print an entry in its text form: the password on line 1, then username, url,\n" +
			"tags and other fields, then the notes after ---.\n" +
			"\n" +
			"Control characters and escape sequences in the entry are shown escaped, so an\n" +
			"entry can't drive your terminal. --raw prints the exact bytes instead.\n" +
			"--field prints one value (password, username, url, tags, notes or a custom\n" +
			"field). When stdout is not a terminal (a pipe or a file), --field prints the\n" +
			"exact value without a final newline, e.g.\n" +
			"  passh show work/github --field password | pbcopy": "Выводит запись в текстовой форме: пароль в строке 1, затем username, url, tags\n" +
			"и другие поля, затем заметки после ---.\n" +
			"\n" +
			"Управляющие символы и escape-последовательности записи выводятся\n" +
			"экранированными, чтобы запись не могла управлять терминалом. --raw вместо этого\n" +
			"выводит точные байты. --field выводит одно значение (password, username, url,\n" +
			"tags, notes или дополнительное поле). Когда stdout — не терминал (канал или\n" +
			"файл), --field выводит точное значение без перевода строки в конце, например\n" +
			"  passh show work/github --field password | pbcopy",
		"print only this field: password, username, url, tags, notes or a custom field": "вывести только это поле: password, username, url, tags, notes или дополнительное поле",
		"print exact bytes, without escaping control characters":                        "выводить точные байты, не экранируя управляющие символы",
		"%s is a folder, not an entry: list it with `passh ls %s`":                      "%s — папка, а не запись: её содержимое покажет `passh ls %s`",
		"List tags with their entry counts":                                             "Вывести список тегов с количеством записей",
		"no tags":                                                                       "тегов нет",

		// internal/cli/exportcmd.go
		"Export entries for other tools (plaintext unless --age)": "Экспортировать записи (в открытом виде, если не задан --age)",
		"Export entries as csv, json (the vault's data format) or bitwarden-json.\n" +
			"\n" +
			"Export data is never written to a terminal: use -o file or redirect stdout.\n" +
			"A plaintext export needs confirmation: with a terminal you type EXPORT PLAINTEXT;\n" +
			"without one (e.g. over ssh without -t) add --confirm-plaintext. --age <recipient>\n" +
			"encrypts the export to an age public key instead. -o creates a new file with\n" +
			"mode 0600 and never overwrites one.\n" +
			"\n" +
			"For a backup, don't export: copy the vault file (passh backup).": "Экспортирует записи в csv, json (формат данных хранилища) или bitwarden-json.\n" +
			"\n" +
			"Данные экспорта никогда не пишутся в терминал: используйте -o file или\n" +
			"перенаправьте stdout. Экспорт в открытом виде требует подтверждения: в\n" +
			"терминале введите EXPORT PLAINTEXT; без терминала (например, по ssh без -t)\n" +
			"добавьте --confirm-plaintext. --age <recipient> вместо этого шифрует экспорт\n" +
			"открытым ключом age. -o создаёт новый файл с правами 0600 и никогда не\n" +
			"перезаписывает существующий.\n" +
			"\n" +
			"Для резервной копии экспорт не нужен: скопируйте файл хранилища (passh backup).",
		"--format is required: csv, json or bitwarden-json":                                        "нужен --format: csv, json или bitwarden-json",
		"This writes your passwords unencrypted.\n":                                                "Ваши пароли будут записаны без шифрования.\n",
		"csv, json or bitwarden-json":                                                              "csv, json или bitwarden-json",
		"only entries in this folder":                                                              "только записи в этой папке",
		"write to this new file (mode 0600) instead of stdout":                                     "записать в этот новый файл (права 0600) вместо stdout",
		"encrypt to this age public key (age1…)":                                                   "зашифровать этим открытым ключом age (age1…)",
		"confirm a plaintext export when there is no terminal":                                     "подтвердить экспорт в открытом виде, когда нет терминала",
		"CSV: prefix ' to cells starting with = + - @ (changes values; not for password managers)": "CSV: добавить ' перед ячейками, начинающимися с = + - @ (меняет значения; не для менеджеров паролей)",

		// internal/cli/files.go
		"%s is not a regular file":                    "%s — не обычный файл",
		"%s is larger than 64 MiB: not a passh vault": "%s больше 64 MiB: это не хранилище passh",
		"Check the vault or a copy of it":             "Проверить хранилище или его копию",
		"Check a vault file without the passphrase: the passh-vault line, both blocks\n" +
			"complete, base64 and age headers valid. It prints the file's SHA-256 and size;\n" +
			"a byte-exact copy has the same SHA-256 as the original.\n" +
			"\n" +
			"--full also decrypts the file (through the agent, or by asking for the\n" +
			"passphrase) and prints its vault_id, revision, saved_at and entry count, and\n" +
			"how it compares with the newest revision seen on this machine.": "Проверяет файл хранилища без парольной фразы: строка passh-vault, оба блока\n" +
			"целы, base64 и заголовки age корректны. Выводит SHA-256 и размер файла;\n" +
			"у побайтной копии SHA-256 тот же, что у оригинала.\n" +
			"\n" +
			"--full также расшифровывает файл (через агент или спросив парольную фразу) и\n" +
			"выводит его vault_id, revision, saved_at и число записей, а также сравнение с\n" +
			"самой новой ревизией, которая открывалась на этом компьютере.",
		"note: %v": "примечание: %v",
		"note: the file isn't in passh's canonical form (line endings or line wrapping changed in copying); it opens, and `passh backup` writes a canonical copy": "примечание: файл не в канонической форме passh (при копировании изменились окончания или переносы строк); он открывается, а `passh backup` запишет каноническую копию",
		"also decrypt the file and check its data":                "также расшифровать файл и проверить его данные",
		"this machine hasn't seen this vault before":              "это хранилище на этом компьютере ещё не открывалось",
		"OLDER than seen before on this machine (seen r%d of %s)": "СТАРЕЕ той, что уже открывалась на этом компьютере (была r%d от %s)",
		"OK: the newest revision seen on this machine (r%d)":      "OK: самая новая ревизия из открывавшихся на этом компьютере (r%d)",
		"OK: newer than seen before on this machine (r%d)":        "OK: новее той, что уже открывалась на этом компьютере (r%d)",
		"Make a checked copy of the vault in a file or folder":    "Сделать проверенную копию хранилища в файле или папке",
		"Copy the vault to a file, or into a folder as <name>-<UTC time>.passh, with\n" +
			"mode 0600. The copy is flushed to disk, read back and compared by SHA-256.\n" +
			"An existing file is never overwritten. A vault that isn't in canonical form\n" +
			"(e.g. after an email or a paste) is written in canonical form. No passphrase\n" +
			"is needed.": "Копирует хранилище в файл или в папку как <name>-<UTC time>.passh с правами\n" +
			"0600. Копия сбрасывается на диск, читается обратно и сверяется по SHA-256.\n" +
			"Существующий файл никогда не перезаписывается. Хранилище не в канонической\n" +
			"форме (например, после письма или вставки) записывается в канонической форме.\n" +
			"Парольная фраза не нужна.",
		"Backed up %s to %s.": "Копия %s записана в %s.",
		"The copy is byte for byte the vault; `passh verify` shows the same SHA-256 for both.": "Копия побайтно совпадает с хранилищем; `passh verify` покажет для обоих файлов один и тот же SHA-256.",
		"The vault isn't in canonical form, so the copy was written in canonical form;\n" +
			"its SHA-256 differs from the vault's, and the stock age tool reads its blocks (§8).": "Хранилище не в канонической форме, поэтому копия записана в канонической форме;\n" +
			"её SHA-256 отличается от SHA-256 хранилища, и стандартный age читает её блоки (§8).",
		"List the automatic backups of the vault": "Вывести список автоматических резервных копий хранилища",
		"List the automatic backups passh made before each save (§4.7), newest first,\n" +
			"with time and revision. To restore one, copy it over the vault file and run\n" +
			"`passh verify --full`. No passphrase is needed.": "Выводит автоматические резервные копии, которые passh сделал перед каждым\n" +
			"сохранением (§4.7), сначала новые, с временем и ревизией. Чтобы восстановить\n" +
			"копию, скопируйте её поверх файла хранилища и выполните `passh verify --full`.\n" +
			"Парольная фраза не нужна.",
		"note: %s can't be read (%v); listing every automatic backup on this machine":                                                                                                        "примечание: %s не читается (%v); выводятся все автоматические резервные копии на этом компьютере",
		"No automatic backups yet. passh makes one before each save (backup.keep = %d).":                                                                                                     "Автоматических резервных копий пока нет. passh делает копию перед каждым сохранением (backup.keep = %d).",
		"note: no backup has this vault's current key block (it was changed by passwd or rekey and not saved since, or the file is damaged); listing every automatic backup on this machine": "примечание: ни в одной копии нет текущего блока ключа этого хранилища (его изменили passwd или rekey, и с тех пор хранилище не сохранялось, или файл повреждён); выводятся все автоматические резервные копии на этом компьютере",

		// internal/cli/help.go
		"unknown flag: --%s":                  "неизвестный флаг: --%s",
		"unknown shorthand flag: %q in -%s":   "неизвестный короткий флаг %q в -%s",
		"flag needs an argument: --%s":        "флагу нужно значение: --%s",
		"flag needs an argument: %q in -%s":   "флагу нужно значение: %q в -%s",
		"invalid argument %q for %q flag: %v": "недопустимое значение %q для флага %q: %v",
		"bad flag syntax: %s":                 "неверный синтаксис флага: %s",

		// internal/cli/importcmd.go
		"Import entries from another password manager":      "Импортировать записи из другого менеджера паролей",
		"say what to import from, e.g. `passh import pass`": "укажите, откуда импортировать, например `passh import pass`",
		"One-way import from a pass store (needs gpg)":      "Односторонний импорт из хранилища pass (нужен gpg)",
		"Import a pass store (password-store.org) into the vault, in one save. The store\n" +
			"is only read. dir defaults to $PASSWORD_STORE_DIR, then ~/.password-store.\n" +
			"Each entry is decrypted with gpg, as pass does. Paths already in the vault are\n" +
			"skipped unless --overwrite is given. --dry-run lists what would be imported\n" +
			"and the conflicts without decrypting anything.": "Импортирует хранилище pass (password-store.org) в хранилище passh за одно\n" +
			"сохранение. Хранилище pass только читается. dir по умолчанию —\n" +
			"$PASSWORD_STORE_DIR, затем ~/.password-store. Каждая запись расшифровывается\n" +
			"gpg, как это делает pass. Пути, уже имеющиеся в хранилище, пропускаются, если\n" +
			"не указан --overwrite. --dry-run выводит, что было бы импортировано, и\n" +
			"конфликты, ничего не расшифровывая.",
		"Decrypting %d/%d…":                                              "Расшифровка %d/%d…",
		"nothing was imported: %w":                                       "ничего не импортировано: %w",
		"replace entries whose path is already in the vault":             "заменять записи, путь которых уже есть в хранилище",
		"list what would be imported and the conflicts; decrypt nothing": "вывести, что было бы импортировано, и конфликты; ничего не расшифровывать",
		"Dry run: nothing was decrypted or saved. Store: %s":             "Пробный запуск: ничего не расшифровано и не сохранено. Хранилище pass: %s",
		"%s  (replaces the entry in the vault)":                          "%s  (заменит запись в хранилище)",

		// internal/cli/initcmd.go
		"Create a new vault, and the config file if it doesn't exist": "Создать новое хранилище и конфигурационный файл, если его нет",
		"%s already exists; passh init doesn't overwrite a vault":     "%s уже существует; passh init не перезаписывает хранилище",
		"the vault was created, but the config file wasn't: %w":       "хранилище создано, а конфигурационный файл — нет: %w",
		"Wrote the config file %s.":                                   "Конфигурационный файл %s записан.",
		"The config file %s exists and wasn't changed; it names the vault %s.\n" +
			"Use --vault %s with each command, or change vault in the config file.": "Конфигурационный файл %s уже есть и не изменён; в нём указано хранилище %s.\n" +
			"Добавляйте --vault %s к каждой команде или измените vault в конфигурационном файле.",
		"the vault was created, but the recovery sheet wasn't written: %w; run `passh recovery-key print` later": "хранилище создано, но лист с ключом восстановления не записан: %w; выполните `passh recovery-key print` позже",

		// internal/cli/open.go
		"vault is locked: run `passh unlock` in a terminal (over SSH: `ssh -t host passh unlock`)": "хранилище заблокировано: выполните `passh unlock` в терминале (по SSH: `ssh -t host passh unlock`)",
		"no vault at %s: run `passh init` to create one, or pass --vault <file>":                   "хранилища %s нет: создайте его командой `passh init` или передайте --vault <file>",
		"vault %s: %w":                  "хранилище %s: %w",
		"Continue with this copy?":      "Продолжить с этой копией?",
		"%v; asking for the passphrase": "%v; запрашивается парольная фраза",
		"can't use the agent of %s: %v": "не удаётся использовать агент для %s: %v",
		"the agent's key doesn't open %s (was it rekeyed elsewhere?); asking for the passphrase":                                                                                                              "ключ агента не открывает %s (ключ сменили в другом месте?); запрашивается парольная фраза",
		"The key block only protects the vault key with the passphrase: if the data block is intact, `passh recover` with the paper recovery key writes a new key block":                                      "Блок ключа лишь защищает ключ хранилища парольной фразой: если блок данных цел, `passh recover` с бумажным ключом восстановления запишет новый блок ключа",
		"The key block only protects the vault key with the passphrase: if the data block is intact, `passh recover` with the paper recovery key writes a new key block; or restore a backup (passh backups)": "Блок ключа лишь защищает ключ хранилища парольной фразой: если блок данных цел, `passh recover` с бумажным ключом восстановления запишет новый блок ключа; или восстановите резервную копию (passh backups)",
		"Passphrase: ":                   "Парольная фраза: ",
		"Wrong passphrase. Try again.\n": "Неверная парольная фраза. Попробуйте ещё раз.\n",
		"warning: %s":                    "предупреждение: %s",

		// internal/cli/output.go
		"refusing to write export data to a terminal: add -o file or redirect stdout":        "данные экспорта не пишутся в терминал: добавьте -o file или перенаправьте stdout",
		"refusing to write the sheet to a terminal: add -o file or redirect stdout":          "лист не пишется в терминал: добавьте -o file или перенаправьте stdout",
		"refusing to write the recovery key to a terminal: add -o file or redirect stdout":   "ключ восстановления не пишется в терминал: добавьте -o file или перенаправьте stdout",
		"%s already exists; passh doesn't overwrite files":                                   "%s уже существует; passh не перезаписывает файлы",
		"%s isn't on tmpfs: the plaintext is on persistent disk. Delete it when you're done": "%s не на tmpfs: открытый текст лежит на постоянном диске. Удалите файл, когда закончите",
		"%w; the partial file %s could not be removed (%v): delete it":                       "%w; неполный файл %s не удалось удалить (%v): удалите его",
		"%w; the partial file was removed":                                                   "%w; неполный файл удалён",
		"writing %s: %w":                                                                     "запись %s: %w",

		// internal/cli/passphrase.go
		"Change the passphrase (the paper recovery key stays valid)": "Сменить парольную фразу (бумажный ключ остаётся в силе)",
		"Change the passphrase: only the key block is rewritten, and the paper recovery\n" +
			"key stays valid. It asks for the current passphrase on the terminal, also while\n" +
			"the agent runs: the agent's key isn't enough to change it. A running agent is\n" +
			"stopped afterwards.": "Меняет парольную фразу: переписывается только блок ключа, а бумажный ключ\n" +
			"восстановления остаётся в силе. Текущая парольная фраза спрашивается в\n" +
			"терминале, даже когда работает агент: ключа агента для её смены недостаточно.\n" +
			"Запущенный агент после этого останавливается.",
		"Choose the new passphrase.\n": "Придумайте новую парольную фразу.\n",
		"Passphrase changed. The paper recovery key stays valid.\n" +
			"Copies and backups made before still open with the old passphrase.": "Парольная фраза изменена. Бумажный ключ восстановления остаётся в силе.\n" +
			"Копии и резервные копии, сделанные раньше, по-прежнему открываются старой парольной фразой.",
		"Make a new vault key (the old passphrase and paper key stop working on new versions)": "Создать новый ключ хранилища (старые фраза и бумажный ключ не откроют новые версии)",
		"Make a new vault key and re-encrypt the data to it, with a passphrase (the same or\n" +
			"a new one). The old passphrase and paper recovery key don't open new versions of\n" +
			"the file. It asks for the current passphrase on the terminal, also while the\n" +
			"agent runs: the agent's key isn't enough to replace the vault key. A running\n" +
			"agent is stopped afterwards.": "Создаёт новый ключ хранилища и перешифровывает им данные, с парольной фразой\n" +
			"(той же или новой). Старые парольная фраза и бумажный ключ восстановления не\n" +
			"открывают новые версии файла. Текущая парольная фраза спрашивается в\n" +
			"терминале, даже когда работает агент: ключа агента недостаточно, чтобы\n" +
			"заменить ключ хранилища. Запущенный агент после этого останавливается.",
		"Choose the passphrase for the new vault key (it may be the same as before).\n": "Придумайте парольную фразу для нового ключа хранилища (можно прежнюю).\n",
		"The vault has a new key. The old passphrase and the old paper recovery key\n" +
			"no longer open new versions of it; copies made before still open with them.\n" +
			"Print a new paper recovery key now: passh recovery-key print": "У хранилища новый ключ. Старые парольная фраза и бумажный ключ восстановления\n" +
			"больше не открывают его новые версии; копии, сделанные раньше, ими по-прежнему открываются.\n" +
			"Распечатайте новый бумажный ключ восстановления сейчас: passh recovery-key print",
		"passh %s needs the current passphrase, typed on a terminal; the agent's key isn't enough to change the passphrase or the vault key (over SSH: `ssh -t host passh %s`)": "для passh %s нужна текущая парольная фраза, введённая в терминале; ключа агента недостаточно, чтобы сменить парольную фразу или ключ хранилища (по SSH: `ssh -t host passh %s`)",
		"Current passphrase: ": "Текущая парольная фраза: ",
		"Open the vault with the paper recovery key and set a new passphrase":                                                  "Открыть хранилище бумажным ключом и задать новую парольную фразу",
		"this recovery key doesn't open %s: it belongs to another vault, or the vault was rekeyed after the sheet was printed": "этот ключ восстановления не открывает %s: он от другого хранилища, или ключ хранилища сменили после печати листа",
		"The recovery key opens the vault. Choose a new passphrase.\n":                                                         "Ключ восстановления открывает хранилище. Придумайте новую парольную фразу.\n",
		"New passphrase set for %s. The paper recovery key stays valid.":                                                       "Для %s задана новая парольная фраза. Бумажный ключ восстановления остаётся в силе.",
		"Type the recovery key from the paper sheet (AGE-SECRET-KEY-1…); it shows as *.\n" +
			"Spaces, line breaks and letter case don't matter. End with an empty line.\n": "Введите ключ восстановления с бумажного листа (AGE-SECRET-KEY-1…); он отображается как *.\n" +
			"Пробелы, переводы строк и регистр букв не важны. Завершите пустой строкой.\n",
		"%v. Type it again.\n": "%v. Введите его ещё раз.\n",

		// internal/cli/printcmd.go
		"the print page needs a terminal (over SSH: use `ssh -t`)":                                                            "для страницы печати нужен терминал (по SSH: используйте `ssh -t`)",
		"PDF output was removed; use --web to print from a browser (it can save as PDF), or omit --format for the text sheet": "вывод в PDF удалён; используйте --web, чтобы печатать из браузера (он умеет сохранять в PDF), или уберите --format для текстового листа",
		"show the sheet on the one-shot print page (§7.4), with a QR code; a browser can print it or save it as PDF":          "показать лист на одноразовой странице печати (§7.4) с QR-кодом; браузер может распечатать его или сохранить в PDF",
		"--output can't be used with --web":                                   "--output нельзя использовать вместе с --web",
		"Print a password sheet (text), or show it on the print page (--web)": "Распечатать лист паролей: текстом или на странице печати (--web)",
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
			"terminal and typing PRINT); the browser prints it, or saves it as PDF.": "Раскладывает выбранные записи в текстовый лист паролей, по папкам, с\n" +
			"выбранными полями (по умолчанию password,username,url; также tags, notes,\n" +
			"fields или ключ дополнительного поля). Неоднозначные символы помечены.\n" +
			"\n" +
			"Лист — открытый текст: он никогда не пишется в терминал и требует\n" +
			"подтверждения, как экспорт в открытом виде (введите EXPORT PLAINTEXT или\n" +
			"--confirm-plaintext без терминала). Используйте -o file (права 0600) или\n" +
			"перенаправьте stdout; распечатайте, затем удалите файл.\n" +
			"\n" +
			"--web вместо этого показывает его на одноразовой странице печати\n" +
			"(print_web.enabled; нужны терминал и ввод PRINT); браузер печатает его или\n" +
			"сохраняет в PDF.",
		"--confirm-plaintext can't be used with --web: the print page needs a terminal": "--confirm-plaintext нельзя использовать вместе с --web: странице печати нужен терминал",
		"printing needs confirmation: without a terminal, add --confirm-plaintext":      "печать требует подтверждения: без терминала добавьте --confirm-plaintext",
		"The sheet holds your passwords unencrypted.\n":                                 "Лист содержит ваши пароли без шифрования.\n",
		"fields to print, comma-separated (default password,username,url)":              "поля для печати через запятую (по умолчанию password,username,url)",
		"confirm a plaintext sheet when there is no terminal":                           "подтвердить лист в открытом виде, когда нет терминала",

		// internal/cli/printpage.go
		"not used: %s":            "не используются: %s",
		"certificate SHA-256  %s": "SHA-256 сертификата  %s",
		"Compare it with the fingerprint your browser shows before you accept the certificate.": "Сравните его с отпечатком, который показывает браузер, прежде чем принять сертификат.",
		"c copies the URL · Esc stops":       "c копирует URL · Esc останавливает",
		"Done: %s.":                          "Готово: %s.",
		"stops after one load or in %d:%02d": "остановится после одной загрузки или через %d:%02d",
		"no clipboard":                       "нет буфера обмена",
		"copy failed":                        "копирование не удалось",
		"URL copied":                         "URL скопирован",

		// internal/cli/recoverykey.go
		"The paper recovery key":                                                        "Бумажный ключ восстановления",
		"say what to do, e.g. `passh recovery-key print`":                               "укажите действие, например `passh recovery-key print`",
		"Print the paper recovery key (needs a terminal and typing PRINT RECOVERY KEY)": "Распечатать бумажный ключ восстановления (нужны терминал и ввод PRINT RECOVERY KEY)",
		"Print the paper recovery key as a text sheet: the vault key in groups of four\n" +
			"characters, the vault_id, the print date, a warning and the manual recovery\n" +
			"steps. Whoever has the sheet and a copy of the vault can read everything: keep\n" +
			"it offline, and print a new one after `passh rekey`.\n" +
			"\n" +
			"It needs a terminal and typing PRINT RECOVERY KEY. The sheet is never written\n" +
			"to a terminal: use -o file (mode 0600) or redirect stdout, print it, then delete\n" +
			"the file. --web shows it on the one-shot print page instead, with the key as a\n" +
			"QR code; the browser prints it, or saves it as PDF.": "Печатает бумажный ключ восстановления как текстовый лист: ключ хранилища\n" +
			"группами по четыре символа, vault_id, дата печати, предупреждение и шаги\n" +
			"ручного восстановления. У кого есть лист и копия хранилища, тот может прочитать\n" +
			"всё: храните лист офлайн и печатайте новый после `passh rekey`.\n" +
			"\n" +
			"Нужны терминал и ввод PRINT RECOVERY KEY. Лист никогда не пишется в терминал:\n" +
			"используйте -o file (права 0600) или перенаправьте stdout, распечатайте, затем\n" +
			"удалите файл. --web вместо этого показывает его на одноразовой странице\n" +
			"печати, с ключом в виде QR-кода; браузер печатает его или сохраняет в PDF.",
		"Wrote the paper recovery key to %s.":                           "Бумажный ключ восстановления записан в %s.",
		"print it, keep the sheet offline, then delete the file: rm %s": "распечатайте его, храните лист офлайн, затем удалите файл: rm %s",
		"Print the recovery key now?":                                   "Распечатать ключ восстановления сейчас?",
		"Print the paper recovery key now and keep the sheet offline:\n" +
			"  passh recovery-key print -o <file>   (or --web, with the key as a QR code)\n" +
			"Without it, a forgotten passphrase means the data is lost.": "Распечатайте бумажный ключ восстановления сейчас и храните лист офлайн:\n" +
			"  passh recovery-key print -o <file>   (или --web, с ключом в виде QR-кода)\n" +
			"Без него забытая парольная фраза означает потерю данных.",
		"Write the text sheet to [%s]: ":                                          "Файл для текстового листа [%s]: ",
		"For a version with the key as a QR code: passh recovery-key print --web": "Версия с ключом в виде QR-кода: passh recovery-key print --web",

		// internal/cli/sys_darwin.go
		"can't read the memory size: %v":                  "не удаётся прочитать объём памяти: %v",
		"can't read vm.swapusage: %v":                     "не удаётся прочитать vm.swapusage: %v",
		"no swap is in use":                               "swap не используется",
		"swap is active (%s used) and encrypted by macOS": "swap включён (занято %s) и зашифрован macOS",
		"swap is active (%s used) and not encrypted: process memory, decrypted secrets included, may be written to disk": "swap включён (занято %s) и не зашифрован: память процессов, включая расшифрованные секреты, может попасть на диск",

		// internal/cli/sys_linux.go
		"can't read the available memory: %v": "не удаётся прочитать объём доступной памяти: %v",
		"can't read /proc/swaps: %v":          "не удаётся прочитать /proc/swaps: %v",
		"no swap is active":                   "swap не включён",

		// internal/cli/sys_other.go
		"not checked on this system": "в этой системе не проверяется",

		// internal/cli/tuicmd.go
		"the TUI needs a terminal: run passh in one (over SSH: `ssh -t host passh`); without a terminal, use the commands (passh --help) after `passh unlock`": "для TUI нужен терминал: запустите passh в терминале (по SSH: `ssh -t host passh`); без терминала используйте команды (passh --help) после `passh unlock`",
		"the TUI was stopped (%w); it locked first": "TUI остановлен (%w); перед этим он заблокировался",
	},
	plurals: map[pluralKey][3]string{
		// internal/cli/doctor.go
		{"%d error", "%d errors"}:                                    {"%d ошибка", "%d ошибки", "%d ошибок"},
		{"%d warning", "%d warnings"}:                                {"%d предупреждение", "%d предупреждения", "%d предупреждений"},
		{"%s: structure OK, %d bytes", "%s: structure OK, %d bytes"}: {"%s: структура в порядке, %d байт", "%s: структура в порядке, %d байта", "%s: структура в порядке, %d байт"},
		{"%d file left by an interrupted save (%s); the next save removes them", "%d files left by an interrupted save (%s); the next save removes them"}: {"%d файл остался от прерванного сохранения (%s); следующее сохранение удалит его", "%d файла остались от прерванного сохранения (%s); следующее сохранение удалит их", "%d файлов осталось от прерванного сохранения (%s); следующее сохранение удалит их"},
		{"%d byte", "%d bytes"}: {"%d байт", "%d байта", "%d байт"},
		// internal/cli/edit.go
		{"Generated a %d-character password.", "Generated a %d-character password."}: {"Сгенерирован пароль из %d символа.", "Сгенерирован пароль из %d символов.", "Сгенерирован пароль из %d символов."},
		{"%s, %d bits", "%s, %d bits"}: {"%s, %d бит", "%s, %d бита", "%s, %d бит"},
		{"Replaced the password of %s: a new %d-character password (%s).\nShow it with: passh show %s --field password", "Replaced the password of %s: a new %d-character password (%s).\nShow it with: passh show %s --field password"}: {"Пароль записи %s заменён: новый пароль из %d символа (%s).\nПоказать его: passh show %s --field password", "Пароль записи %s заменён: новый пароль из %d символов (%s).\nПоказать его: passh show %s --field password", "Пароль записи %s заменён: новый пароль из %d символов (%s).\nПоказать его: passh show %s --field password"},
		{"Stored %s: a new %d-character password (%s).\nShow it with: passh show %s --field password", "Stored %s: a new %d-character password (%s).\nShow it with: passh show %s --field password"}:                                     {"Запись %s сохранена: новый пароль из %d символа (%s).\nПоказать его: passh show %s --field password", "Запись %s сохранена: новый пароль из %d символов (%s).\nПоказать его: passh show %s --field password", "Запись %s сохранена: новый пароль из %d символов (%s).\nПоказать его: passh show %s --field password"},
		{"Moved the folder %s/ to %s/ (%d entry).", "Moved the folder %s/ to %s/ (%d entries)."}:                                                                                                                                         {"Папка %s/ перемещена в %s/ (%d запись).", "Папка %s/ перемещена в %s/ (%d записи).", "Папка %s/ перемещена в %s/ (%d записей)."},
		// internal/cli/exportcmd.go
		{"exported %d entry (%s, encrypted with age) to %s", "exported %d entries (%s, encrypted with age) to %s"}: {"экспортирована %d запись (%s, зашифровано age) в %s", "экспортированы %d записи (%s, зашифровано age) в %s", "экспортировано %d записей (%s, зашифровано age) в %s"},
		{"exported %d entry (%s, plaintext) to %s", "exported %d entries (%s, plaintext) to %s"}:                   {"экспортирована %d запись (%s, в открытом виде) в %s", "экспортированы %d записи (%s, в открытом виде) в %s", "экспортировано %d записей (%s, в открытом виде) в %s"},
		{"CSV has no column for custom fields: %d field was left out (otp fields included); use --format json or bitwarden-json to keep them", "CSV has no column for custom fields: %d fields were left out (otp fields included); use --format json or bitwarden-json to keep them"}: {"в CSV нет столбца для дополнительных полей: %d поле не попало в экспорт (включая поля otp); чтобы сохранить их, используйте --format json или bitwarden-json", "в CSV нет столбца для дополнительных полей: %d поля не попали в экспорт (включая поля otp); чтобы сохранить их, используйте --format json или bitwarden-json", "в CSV нет столбца для дополнительных полей: %d полей не попало в экспорт (включая поля otp); чтобы сохранить их, используйте --format json или bitwarden-json"},
		// internal/cli/importcmd.go
		{"Would import %d entry:", "Would import %d entries:"}:                                           {"Будет импортирована %d запись:", "Будут импортированы %d записи:", "Будет импортировано %d записей:"},
		{" (%d replacing entries already in the vault)", " (%d replacing entries already in the vault)"}: {" (%d из них заменяет запись, уже имеющуюся в хранилище)", " (%d из них заменяют записи, уже имеющиеся в хранилище)", " (%d из них заменяют записи, уже имеющиеся в хранилище)"},
		{"Would import %d entry%s.", "Would import %d entries%s."}:                                       {"Будет импортирована %d запись%s.", "Будут импортированы %d записи%s.", "Будет импортировано %d записей%s."},
		{"Imported %d entry%s from %s.", "Imported %d entries%s from %s."}:                               {"Импортирована %d запись%s из %s.", "Импортированы %d записи%s из %s.", "Импортировано %d записей%s из %s."},
		{"Would skip %d: %s.", "Would skip %d: %s."}:                                                     {"Будет пропущен %d файл (%s).", "Будут пропущены %d файла (%s).", "Будет пропущено %d файлов (%s)."},
		{"Skipped %d: %s.", "Skipped %d: %s."}:                                                           {"Пропущен %d файл (%s).", "Пропущены %d файла (%s).", "Пропущено %d файлов (%s)."},
		// internal/cli/printcmd.go
		{"printed %d entry (text sheet) to %s; print it, then delete the file", "printed %d entries (text sheet) to %s; print it, then delete the file"}: {"в %[2]s записан текстовый лист: %[1]d запись; распечатайте его, затем удалите файл", "в %[2]s записан текстовый лист: %[1]d записи; распечатайте его, затем удалите файл", "в %[2]s записан текстовый лист: %[1]d записей; распечатайте его, затем удалите файл"},
		// internal/cli/sys_linux.go
		{"%d swap area is active (%s): process memory, decrypted secrets included, may be written to disk. passh doesn't change this; turn swap off or encrypt it if that matters to you", "%d swap areas are active (%s): process memory, decrypted secrets included, may be written to disk. passh doesn't change this; turn swap off or encrypt it if that matters to you"}: {"%d область swap включена (%s): память процессов, включая расшифрованные секреты, может попасть на диск. passh этого не меняет; отключите swap или зашифруйте его, если это для вас важно", "%d области swap включены (%s): память процессов, включая расшифрованные секреты, может попасть на диск. passh этого не меняет; отключите swap или зашифруйте его, если это для вас важно", "%d областей swap включено (%s): память процессов, включая расшифрованные секреты, может попасть на диск. passh этого не меняет; отключите swap или зашифруйте его, если это для вас важно"},
	},
}
