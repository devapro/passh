# passh — Specification

> Working name: **passh** ("pass, but nicer").
> Status: Draft v0.5 · Owner: Arsenii · Date: 2026-11-15

---

## Changelog

| Version | Changes |
|---|---|
| v0.5 | **Simplified to a plain CLI tool** (owner decision). One binary and one config file with the store path; run it like any command; it changes nothing outside its own files. **Removed:** restricted SSH server mode, sshd/authorized_keys setup, per-key policy, admin mode, Docker, signed commits and verification, recipient pinning, bundled key backup, `restore`, recovery kit, `config`/`remote` commands, failed-unlock backoff, the secure-memory requirement. **Kept:** pass-compatible store, TUI, tags, clipboard, export, print, and the print page on the LAN/VPN over HTTPS, now with a self-signed certificate instead of a local CA. The v0.4 design is kept in `archive/` |
| v0.4 | Print page, Docker deployment, config/remote admin commands (superseded by v0.5) |
| v0.3 | Second security review: restricted SSH model, signed history, bundled key (superseded by v0.5) |
| v0.2 | First security review |
| v0.1 | Initial draft |

---

## 1. Summary

passh is a single Go binary for managing passwords in a **pass-compatible** store: GPG-encrypted files in a folder, optionally a git repository. You install one file, point a config file at the store, and run `passh` like any other command. It runs wherever the store and your GPG key are: on your laptop, or on a server you reach with a normal `ssh`.

On top of `pass` it adds:

- a TUI for browsing by folder (category) and tag;
- tags, with an encrypted index so listing by tag doesn't decrypt every entry;
- copying to the clipboard, also over SSH (OSC 52), with clearing after a timeout;
- locking after a period of inactivity;
- export (CSV / JSON / Bitwarden JSON / archive) and printing (PDF / text, and a one-shot print page that opens in a browser on the LAN or VPN).

## 2. Goals and non-goals

### Goals

| # | Goal |
|---|------|
| G1 | One static Go binary for `linux/amd64`, `linux/arm64`, `linux/arm/v7`, `darwin/amd64` and `darwin/arm64` |
| G2 | Setup is: copy the binary, write a config file with the store path. No root, no daemon, no changes to the system (§3.2) |
| G3 | Compatibility with `pass`: existing stores open unchanged, and `pass` keeps working on a passh store |
| G4 | Works the same locally and over SSH |
| G5 | Browse and search by folder and by tag in a TUI |
| G6 | Export and printing for migration and paper backup, including printing from a browser without saving a file |

### Non-goals (v1)

- Browser extensions, mobile autofill, native mobile apps
- Multi-user sharing, roles, per-device rights
- Web UI or HTTP API. The only exception is the one-shot print page (§7.4)
- Server or daemon mode, SSH configuration, containers
- Tamper protection beyond what `pass` offers (no signed history, no recipient pinning)
- Protection against an attacker who controls your user account
- Windows

## 3. Installation and configuration

### 3.1 Install

Copy the `passh` binary into a folder on your `PATH`, e.g. `~/.local/bin`.

Runtime requirements, the same as for `pass`:

- `gpg` (GnuPG ≥ 2.2) with its agent and a pinentry;
- `git`, only if the store is a git repository.

### 3.2 System footprint

passh **doesn't change the system**. It writes only to these places:

| Path | What passh writes there |
|---|---|
| The store (`store` in the config) | Entries, `.passh/tags.idx.gpg`, and git commits if the store is a git repository |
| The config file (§3.3) | Created by `passh init` only if it doesn't exist; never rewritten after that |
| `$XDG_STATE_HOME/passh/` (default `~/.local/state/passh/`) | The print page certificate and key (§7.4), and a lock file |
| A temporary folder on tmpfs | Only for `edit --editor` (§5.4); deleted afterwards |

passh never:

- needs root;
- writes system files or other users' files;
- changes `gpg.conf`, `gpg-agent.conf`, the git global config or shell startup files;
- installs services, cron jobs or background processes that outlive the command (the print page server runs inside the passh process);
- touches firewall, swap or SSH settings;
- installs anything into OS or browser certificate stores.

**Runtime effect on gpg-agent:** on lock, passh asks the agent to forget the cached passphrase of the store's keys only (§5.2). Other cached keys are untouched.

**Uninstall:** delete the binary, the config file and `~/.local/state/passh/`. The store stays a plain pass store.

### 3.3 Config file

Location, first match wins:

1. `--config <file>`;
2. `$PASSH_CONFIG`;
3. `$XDG_CONFIG_HOME/passh/config.toml` (default `~/.config/passh/config.toml`).

Only `store` is required:

```toml
store = "~/.password-store"

[session]
idle_ttl    = "5m"      # TUI locks after this much inactivity
clear_agent = true      # on lock, make gpg-agent forget the store key's passphrase

[clipboard]
clear_after = "30s"
osc52       = true      # copy through the terminal (works over SSH)
command     = []        # optional local tool instead, e.g. ["pbcopy"] or ["wl-copy"]

[git]
auto_commit = true      # commit every change if the store is a git repo

[print_web]             # §7.4; off unless enabled
enabled    = false
port       = 8443
interfaces = ["wg0", "eth0"]
allow_from = []         # extra CIDR limit; default = subnets of the bound addresses
hostnames  = []         # optional names for the certificate, e.g. ["pi.local"]
ttl        = "5m"       # 1–15 min

[gpg]
binary = ""             # default: gpg from PATH
```

- `--store <dir>` overrides `store` for one command.
- A missing config file makes passh print how to create one (`passh init`).
- Unknown keys are an error, so typos don't go unnoticed.

## 4. Storage

### 4.1 Layout (pass-compatible)

```
~/.password-store/
├── .gpg-id                 # recipient key(s), as in pass
├── .git/                   # optional
├── .passh/                 # passh-specific data; ignored by pass
│   └── tags.idx.gpg        # encrypted tag index (§4.3)
├── work/
│   ├── jira.gpg
│   └── github.gpg
└── bank/
    └── revolut.gpg
```

- **Folders = categories**, as in pass.
- Recipients come from `.gpg-id` with pass's rules, including `.gpg-id` files in subfolders.
- File names and paths are **not encrypted**, as in pass.

### 4.2 Entry format

Same as the pass convention. Line 1 is the password, followed by `key: value` metadata, then free-form notes.

```
s3cr3t-P@ss
username: arsenii
url: https://github.com
tags: work, dev, 2fa
---
Free-form notes. Recovery codes, etc.
```

- Metadata is the run of `key: value` lines right after line 1. It ends at a `---` line or at the first line that doesn't match. Everything after that is notes.
- Reserved keys: `username`, `url`, `tags`, `otp` (reserved, not implemented in v1). `otp:` values and `otpauth://` lines are masked like passwords.
- Unknown and duplicate keys are preserved in order.
- An entry that passh only reads is never rewritten. An edit rewrites only the changed lines.

### 4.3 Tags

- passh keeps `.passh/tags.idx.gpg`, an encrypted map `{path → [tags]}`, encrypted to the store's recipients.
- It is decrypted once after unlock and held in memory.
- passh updates it on every add, edit, move or delete.
- `passh reindex` rebuilds it after edits made with plain `pass`.
- The index stores a hash over the list of entry paths and file hashes. If that no longer matches, the TUI shows "tag index stale — run reindex".

### 4.4 Git

- If the store is a git repository and `git.auto_commit` is on, every change is committed. The message holds only the action and the path.
- passh runs git with the store repository's own settings. When no author identity is configured, it passes `passh <passh@localhost>` for that commit only, so it never changes git config.
- `passh sync` runs `git pull --ff-only`, then `git push`, against the repository's configured upstream.
- Commits are not signed or verified. The history is as trustworthy as the remote (§9).
- There is no git pass-through; run `git -C <store> …` yourself.

### 4.5 Path rules

Every path from the user or from disk goes through one validator:

- relative to the store root, with no `..` segments and no absolute paths;
- no segment starts with `-` or `.`;
- no control characters.

Files are opened through `os.Root` (Go ≥ 1.24), so symlinks can't lead outside the store.

## 5. Session and safety

### 5.1 Unlock

- Decryption uses `gpg` and the user's gpg-agent and pinentry, exactly as `pass` does (ADR-1).
- passh sets `GPG_TTY` for its gpg calls so pinentry prompts on the current terminal, including over SSH.
- passh doesn't change agent settings. `doctor` reports long agent cache TTLs as a warning, without changing anything.

### 5.2 Lock

The TUI locks when:

- the user presses `L` or runs `passh lock`;
- the TUI exits;
- the TUI has been idle for `session.idle_ttl`;
- passh receives SIGHUP, SIGTERM or SIGINT, e.g. when the SSH connection drops.

On lock passh:

- wipes decrypted entries and the tag index from its memory;
- if `session.clear_agent` is on, asks gpg-agent to forget the cached passphrase of the store's keys only (`CLEAR_PASSPHRASE --mode=normal <keygrip>`).

Commands outside the TUI rely on the agent's own cache TTLs.

### 5.3 Built-in safety rules

These cost no setup and don't touch the system:

| Rule | Detail |
|---|---|
| S1 | Plaintext is never written to persistent disk by passh. `edit --editor` uses a temporary file on tmpfs (`$XDG_RUNTIME_DIR` or `/dev/shm`), mode 0600, deleted afterwards. Where no tmpfs exists (e.g. macOS), `edit --editor` is refused and the built-in form is used |
| S2 | Plaintext goes to `gpg --encrypt` through stdin, never as an argument or environment variable |
| S3 | Password generation uses `crypto/rand` with rejection sampling (no modulo bias). Default length 24, configurable alphabet |
| S4 | Terminal output escapes control characters and escape sequences from entry content, so an entry can't drive your terminal, e.g. by injecting an OSC 52 clipboard write. `show --raw` prints exact bytes |
| S5 | Passwords are masked in the TUI with a fixed-length mask; revealing one hides it again after 10 s |
| S6 | The clipboard is cleared after `clipboard.clear_after`, if the session is still alive (best effort) |
| S7 | Core dumps are disabled for the passh process (`setrlimit`), which affects only passh itself |
| S8 | External programs (gpg, git, `$EDITOR`, the clipboard command) are started without a shell, with argument lists and `--` before paths. gpg results are read from `--status-fd`, not from human-readable output |

Not provided, by design (ADR-4):

- locked or non-swappable memory: `doctor` warns if swap is active;
- signed history or tamper detection;
- recipient pinning.

### 5.4 Editing

- `passh edit <path>` opens a built-in form: separate fields for password, username, url and tags, and a text area for notes. Single-line fields reject newlines.
- `passh edit --editor <path>` uses `$EDITOR`, split into words without a shell, with a temporary file under S1. It adds leak-safe flags for known editors:
  - vim: `-n -u NONE -i NONE -c "set nobackup nowritebackup noundofile noswapfile"`;
  - neovim: `-n --clean -i NONE -c "set nobackup nowritebackup noundofile noswapfile"`;
  - nano: `--ignorercfiles --nohelp`.

  Other editors get a warning that passh can't control their backup files.

## 6. Interfaces

### 6.1 CLI

Running `passh` with no arguments opens the TUI.

| Command | Description |
|---|---|
| `passh init <gpg-id>… [--store dir] [--git]` | Create a store (as `pass init`) and write the config file if it doesn't exist. For an existing pass store, only the config file is needed |
| `passh ls [folder] [--tag t]` | Print the tree, optionally filtered by tag |
| `passh find <query>` | Fuzzy search on paths, and on tags if unlocked |
| `passh show <path> [--field f] [--raw]` | Print the entry or one field |
| `passh copy <path> [--field f]` | Copy to the clipboard (§6.3) |
| `passh add <path> [--force]` | Interactive add: password (or generate), username, url, tags, notes |
| `passh generate <path> [len] [--symbols] [--force]` | Generate and store a password |
| `passh edit <path> [--editor]` | Built-in form, or `$EDITOR` (§5.4) |
| `passh mv <src> <dst>` / `passh rm <path>` | Move or delete; updates the tag index |
| `passh tag <path> --add a --remove b` / `passh tags` | Edit tags / list tags with counts |
| `passh reindex` | Rebuild the tag index |
| `passh sync` | `git pull --ff-only`, then `git push` |
| `passh export …` / `passh print …` | §7 |
| `passh unlock` | Ask for the passphrase now, so that later commands without a terminal can decrypt. The agent's cache TTL decides for how long |
| `passh lock` | Make gpg-agent forget the store key's passphrase now |
| `passh doctor` | Check gpg, pinentry, agent TTLs, git, swap, terminal clipboard support and the config. Read-only: it reports, never fixes |

Global flags: `--config <file>`, `--store <dir>`.

### 6.2 TUI

Built on Bubble Tea + Bubbles + Lip Gloss (charmbracelet).

```
┌ passh ── 🔓 unlocked · locks in 4:12 ────────────────────────────┐
│ VIEW: [Folders]  Tags                     / search_              │
├──────────────────────┬───────────────────────────────────────────┤
│ ▸ bank          (3)  │ work/github                               │
│ ▾ work          (12) │ username  arsenii                         │
│     github           │ password  ••••••••       [c]opy [r]eveal  │
│     jira             │ url       https://github.com              │
│     confluence       │ tags      work · dev · 2fa                │
│ ▸ homelab       (7)  │ notes     Recovery codes in notes…        │
├──────────────────────┴───────────────────────────────────────────┤
│ c copy pw · u copy user · r reveal · e edit · a add · t tags     │
│ Tab folders/tags · / search · P print · L lock · ? help · q quit │
└──────────────────────────────────────────────────────────────────┘
```

- **Two views**, switched with `Tab`:
  - *Folders*: a collapsible tree that mirrors the directories;
  - *Tags*: a list of tags with counts; selecting tags lists their entries (AND).
- `/` opens fuzzy search across paths and tags.
- The detail pane decrypts only the selected entry, on selection (debounced 150 ms).
- `d` deletes and `P` opens the print page (§7.4). Destructive actions ask for confirmation.
- Narrow terminals (under 80 columns, such as phones) use a single pane: list → Enter → detail → Esc.
- All values are rendered through S4.

### 6.3 Clipboard

- **OSC 52** (`clipboard.osc52`): passh writes the value through the terminal (`ESC ] 52 ; c ; <base64> BEL`). This works locally and over SSH in terminals that support it: iTerm2, kitty, WezTerm, Windows Terminal, Alacritty, tmux with `set-clipboard on`, and Termux with the OSC 52 setting.
- **Local tool** (`clipboard.command`): e.g. `["pbcopy"]`, `["wl-copy"]` or `["xclip", "-selection", "clipboard"]`. passh passes the value through stdin. Useful where the terminal lacks OSC 52, such as macOS Terminal.app.
- **Clearing:** after `clipboard.clear_after`, passh sends an empty value the same way. Non-TUI `copy` waits for the clear before it exits.
- **Neither available:** `copy` fails with a hint (`passh show <path> --field password | pbcopy`). It doesn't print the secret.
- `passh doctor` sends a test string, then clears it, so you can check your terminal.
- Client clipboard history (macOS Universal Clipboard, Android, clipboard managers) may keep copies. The README says to exclude the terminal from those tools.

### 6.4 Over SSH

There is no special server mode; passh is just a command on the remote machine:

```bash
ssh -t pi passh                                       # TUI
ssh pi passh show work/github --field password | pbcopy
```

- The TUI and prompts need a terminal, so use `ssh -t`.
- To pipe a secret from the server, unlock first with `ssh -t pi passh unlock`. Commands run without `-t` then work while gpg-agent keeps the passphrase cached.
- Data exports must not use `-t`: a PTY turns LF into CRLF and mixes stderr into the stream (§7.1).

## 7. Export and print

### 7.1 Export

```
passh export --format <csv|json|bitwarden-json|archive> [--tag t] [--folder f] [-o file]
             [--age <recipient> | --encrypt-to <gpg-id> | --confirm-plaintext] [--spreadsheet-safe]
```

| Format | Content | Encrypted | Use case |
|---|---|---|---|
| `archive` (default) | `tar.gz` of the store folder, entries still GPG-encrypted | Yes | Backup, moving machines |
| `json` | Native schema (§7.3) | With `--age` or `--encrypt-to` | Scripting, migration |
| `csv` | `folder,name,username,password,url,tags,notes`, RFC 4180 quoting | As above | KeePassXC and others |
| `bitwarden-json` | Bitwarden unencrypted export schema | As above | Vaultwarden/Bitwarden |

Rules:

- **Export data is never written to a terminal.** Use `-o file` or redirect stdout.
- **Plaintext** (any format except `archive`, without `--age` or `--encrypt-to`) needs confirmation:
  - when passh has a terminal, the user types `EXPORT PLAINTEXT` on `/dev/tty`;
  - otherwise `--confirm-plaintext` is required.
- **`-o file`** creates the file with mode 0600. If the file isn't on tmpfs, passh warns that plaintext is going to persistent disk.
- **CSV values are exact by default**, because the target is a password manager. `--spreadsheet-safe` prefixes `'` to cells starting with `= + - @`, tab or CR, to prevent formula injection in spreadsheets. That changes values, passwords included, so don't import that file into a password manager.

### 7.2 Print

```
passh print [--tag t] [--folder f] [--fields password,username,url] [--format pdf|txt] [-o file] [--confirm-plaintext]
passh print --web [--tag t] [--folder f] [--fields …]
```

- Same confirmation rules as plaintext export (§7.1).
- `pdf`: pure Go (`go-pdf/fpdf`) with an embedded UTF-8 monospaced font. A4/Letter, grouped by folder, ambiguous characters marked (`0/O`, `1/l/I`), print date and "CONFIDENTIAL" on each page.
- `txt`: paginated monospaced layout.
- `--web`: the print page (§7.4).
- Print, then delete the file; the README notes that PDFs left in Downloads are a leak.

### 7.3 JSON schema (native)

```json
{
  "version": 1,
  "exported_at": "2026-11-15T12:00:00Z",
  "entries": [
    {
      "path": "work/github",
      "password": "…",
      "username": "arsenii",
      "url": "https://github.com",
      "tags": ["work", "dev"],
      "fields": { "custom-key": "value" },
      "notes": "…"
    }
  ]
}
```

### 7.4 Print page (web)

A one-shot HTTPS page with the password sheet. You open it in a browser on another device on the LAN or VPN, print it, and nothing is saved anywhere.

**Starting**

- Needs `print_web.enabled = true`.
- Start it from the TUI with `P`, or with `passh print --web …`. It needs a terminal, and the user types `PRINT` to confirm.
- passh shows:
  - the URL for each bound address, and a QR code of it for phones;
  - the certificate fingerprint and a countdown.

  `c` copies the URL to the clipboard.
- The server runs inside the passh process; there is no daemon.

**Network**

- Listens only on the addresses of `print_web.interfaces`, and only on **private** addresses: RFC 1918, `100.64.0.0/10` (Tailscale) and IPv6 ULA `fc00::/7`.
  - A public address is refused.
  - It never binds to `0.0.0.0` or `::`.
- Connections from outside `allow_from` are closed before TLS. By default that means the subnets of the bound addresses.
- The `Host` header must be a bound address or one of `hostnames`, which defeats DNS rebinding.
- passh doesn't open firewall ports. If a firewall blocks the port, opening it is up to you.

**Certificate**

- **No CA, nothing installed on any device.** On first use passh creates a self-signed certificate (ECDSA P-256, valid 1 year) for the bound addresses and `hostnames`.
- It keeps the certificate in `~/.local/state/passh/print-web/` (key mode 0600) and reuses it, so the fingerprint stays the same.
- If the addresses change or the certificate expires, passh makes a new one and says so.
- **First visit from a device:** the browser warns about the certificate. Compare the SHA-256 fingerprint the browser shows with the one passh shows, then accept. Firefox can remember the exception permanently; after that, any other certificate on that address triggers a warning again. Accepting without comparing leaves you open to an active attacker on the LAN (§9).
- TLS 1.3 only. Plain HTTP is never offered.

**Token and lifetime**

- The URL is `https://<address>:<port>/p/<token>`, with a 128-bit random token (`crypto/rand`, base64url).
- **The page is served once.** The first `GET` with the right token consumes it, and the server stops after the response is written.
- The server also stops at the first of:
  - `print_web.ttl`, default 5 min, maximum 15;
  - a lock (§5.2);
  - passh exiting;
  - `Esc` in the print dialog;
  - 5 requests to `/p/` with a wrong token. Other paths, such as `/favicon.ico`, get 404 and don't count.
- Link previews and browser prefetching can consume the token first. The user then sees "already used" and starts again.

**Page**

- Same content and layout as the PDF sheet (§7.2).
- No JavaScript, external fonts or images. The user prints with Ctrl/Cmd+P.
- Entries are decrypted when the request arrives and streamed. Every value is escaped with `html/template`, plus S4.
- Response headers:
  ```
  Cache-Control: no-store
  Content-Security-Policy: default-src 'none'; style-src 'sha256-…'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
  Referrer-Policy: no-referrer
  X-Content-Type-Options: nosniff
  ```
  The CSP blocks scripts and every outgoing request, so even if escaping failed, the page couldn't send passwords anywhere.
- After printing, close the tab. Browsers may keep the page in session restore, and "Save as PDF" or print spoolers can leave files.

## 8. Backup and recovery

The store and the GPG key are backed up separately, exactly as with `pass`.

| What | How |
|---|---|
| Store | `passh sync` to a git remote, or any file backup of the store folder (entries are encrypted). `passh export --format archive` makes a single file |
| GPG secret key | Not in the store. Back it up yourself, once: `gpg --export-secret-keys --armor <id> > key.asc`, stored offline (it stays protected by the passphrase), or on paper with `paperkey` |
| Config file | Optional; it holds only the store path and preferences |

Restore on a new machine:

1. install `gpg` (and `git`), and copy the `passh` binary;
2. `gpg --import key.asc`;
3. clone or copy the store;
4. write the config file with the store path.

`pass` works on the same store without passh.

## 9. Threat model

| Threat | Mitigation | Residual risk |
|---|---|---|
| Stolen store or backup | Entries GPG-encrypted | Paths and entry count leak |
| Stolen GPG key file | Passphrase protection | Offline guessing: use a strong passphrase (6+ random words) |
| Someone with access to your user account, including a stolen SSH key for it | Out of scope | Full access while the agent is unlocked; can also plant a keylogger |
| Malicious content in entries (e.g. from a shared remote) | S4 output escaping; print page escaping and CSP | — |
| Malicious or compromised git remote | — | Can change entries or `.gpg-id` without detection, so future entries could be encrypted to its key (same as `pass`). Use remotes you trust |
| Plaintext on disk | S1; exports warn when not on tmpfs | Swap may hold process memory (`doctor` warns) |
| Clipboard persistence | Clearing after a timeout | Clipboard history on clients; no clear if the session ends first |
| Print page intercepted on the LAN | HTTPS with fingerprint check, private addresses only, `allow_from`, `Host` check, single-use token, 5-minute limit | If a certificate is accepted without comparing fingerprints, an active LAN attacker can read the page. Copies kept by the browser or print spooler |
| Terminal escape injection | S4 | `show --raw`, by explicit choice |
| Shoulder surfing | Masked by default; reveal times out | — |

## 10. Technical design

### 10.1 Stack

| Concern | Choice |
|---|---|
| Language | Go ≥ 1.24 (`os.Root`), `CGO_ENABLED=0` |
| CLI | `spf13/cobra` |
| TUI | `charmbracelet/bubbletea`, `bubbles`, `lipgloss` |
| Config | TOML (`BurntSushi/toml`), strict: unknown keys are errors |
| Fuzzy search | `sahilm/fuzzy` |
| Crypto | `gpg` subprocess behind a `Crypto` interface (ADR-1); `filippo.io/age` for `--age` exports |
| Git | `git` subprocess |
| PDF / QR | `go-pdf/fpdf` with an embedded UTF-8 TTF; `skip2/go-qrcode` (also renders the print page URL in the terminal) |
| Print page | Standard library: `net/http`, `crypto/tls`, `crypto/x509`, `html/template` |
| Release | GoReleaser; checksums published with each release; `-trimpath` |

### 10.2 Package layout

```
cmd/passh/            main, cobra commands
internal/config/      config file: locate, parse, validate
internal/store/       pass layout: walk, read, write, move; lock file
internal/paths/       path validator, os.Root access
internal/entry/       parse/serialize entry format, preserve unknown fields
internal/crypto/      Crypto interface; gpg implementation; status-fd parser; agent forget
internal/tags/        encrypted index: load, update, reindex, staleness
internal/session/     lock state, idle timer, signals
internal/exec/        the only place that starts processes (S8)
internal/sanitize/    terminal output escaping (S4)
internal/clipboard/   OSC 52, local clipboard command, clearing
internal/gen/         password generator (S3)
internal/editor/      built-in form; external editor launcher
internal/export/      csv, json, bitwarden-json, archive
internal/print/       pdf, txt
internal/printweb/    print page server, self-signed certificate
internal/gitx/        commit, pull, push
internal/doctor/      read-only checks
internal/tui/         bubbletea models: tree, tags, detail, search, form, lock screen, print dialog
```

### 10.3 Key interfaces

```go
type Crypto interface {
    Decrypt(ctx context.Context, path paths.Safe) ([]byte, error)
    Encrypt(ctx context.Context, recipients []string, plaintext []byte) ([]byte, error)
    Forget(ctx context.Context) error // CLEAR_PASSPHRASE for the store's keygrips only
}

type Store interface {
    List(prefix paths.Safe) ([]paths.Safe, error)
    Read(path paths.Safe) (*entry.Entry, error)
    Write(path paths.Safe, e *entry.Entry) error // encrypt → write → index → commit (if git)
    Move(src, dst paths.Safe) error
    Remove(path paths.Safe) error
}
```

`paths.Safe` can only be constructed by the validator.

## 11. Architecture decisions

**ADR-1: Use the system `gpg`.** For compatibility with pass stores and keys, and because gpg-agent already provides passphrase caching and pinentry. Cost: a runtime dependency on GnuPG. An `age` backend through the `Crypto` interface stays possible later; it would remove the dependency but break pass compatibility.

**ADR-2: Folders stay primary; tags are additive**, with an encrypted index (§4.3).

**ADR-3: A plain CLI that doesn't change the system.** Owner decision in v0.5: one binary, one config file, run as a normal command. This replaces the v0.2–v0.4 restricted SSH server model. Trade-off: there are no per-device rights, and anyone who can log in as you can use passh fully.

**ADR-4: Minimal, pass-like protections.** Owner decision in v0.5: no signed history, no recipient pinning, no bundled key backup, no locked memory. passh keeps only the cheap, setup-free rules in §5.3. Trade-off: tampering by a malicious remote isn't detected, as with `pass`.

**ADR-5: Print page on the LAN/VPN over HTTPS with a self-signed certificate.** passh must not change device trust stores, so it uses a persistent self-signed certificate and a fingerprint check instead of a local CA (§7.4).

## 12. Milestones

| M | Scope | Done when |
|---|---|---|
| M1 Core | config, paths, entry, crypto, store, git; `init`, `ls`, `show`, `add`, `generate`, `edit` (form), `mv`, `rm`, `sync`; `doctor` | Round-trips with `pass`; safety tests 1, 2, 4, 8 pass |
| M2 TUI + session | TUI views, search, detail, form, idle lock, agent forget, clipboard | Usable on 80×24 and on a phone over SSH; safety tests 3, 6 pass |
| M3 Tags | tag commands, encrypted index, reindex | `ls --tag` works without decrypting every entry |
| M4 Export | archive, json, csv, bitwarden-json, confirmation rules | Bitwarden export imports into Vaultwarden; safety test 5 passes |
| M5 Print | pdf, txt, print page | Safety test 7 passes |
| M6 Release | GoReleaser builds, README, EXAMPLES | Install on a fresh machine = copy binary + write config |

## 13. Acceptance criteria (v1)

### 13.1 Functional

1. Installing means copying the binary and writing the config file; `passh doctor` reports no errors.
2. An existing pass store works by pointing `store` at it, and `pass` still works on it.
3. The TUI asks for the passphrase once per session. After `session.idle_ttl` idle, the next decrypt asks again.
4. Copy works through OSC 52, locally and over SSH, and through `clipboard.command`; the clipboard is cleared after 30 s.
5. A Bitwarden JSON export imports into Vaultwarden. A CSV export imports into KeePassXC, with passwords starting with `= + - @` intact.
6. The print page, started on the Pi, opens in a laptop browser over the LAN and over the VPN. After the certificate is accepted (fingerprint matches), the page prints and the server stops after the load.
7. On a new machine, `key.asc`, a copy of the store and a config file are enough to use passh.

### 13.2 Safety tests

1. Paths with `..`, absolute paths, a leading `-` or `.` in any segment, control characters, or symlinks leading outside the store are rejected.
2. No plaintext file exists on persistent disk after any command except an explicit `export -o` or `print -o` (filesystem diff test).
3. Escape sequences (including OSC 52) in entry content render inert in the TUI and in `show`.
4. Generated passwords pass a chi-square uniformity test over 10⁶ samples.
5. Plaintext export without confirmation fails. An export with confirmation contains no prompt text. Writing export data to a terminal is refused.
6. A lock makes gpg-agent forget the store key's passphrase, while another cached key stays cached.
7. Print page:
   - it binds only to private addresses;
   - it is served once;
   - a wrong `Host` header or a client outside `allow_from` is rejected;
   - it stops at the TTL and on lock;
   - the response headers match §7.4, and a headless browser makes no outgoing request;
   - `<script>` or `<img>` in entry content renders as text.
8. A full session (init, add, edit, export, print page, lock) writes nothing outside the store, the config file, `~/.local/state/passh/` and its temporary folder (filesystem diff of `$HOME` and `/etc`, plus a syscall trace).

## 14. Open questions

1. TOTP (`otp:` field + `passh otp <path>`) in v1 or v1.1?
2. Should the tag index be optional, for users who want no extra files in the store?
3. Should passh warn when `.gpg-id` changes after `sync`? It's a cheap guard against a malicious remote.
4. Is an `age` backend worth it later, to drop the GnuPG dependency at the cost of pass compatibility?
