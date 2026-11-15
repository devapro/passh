# passh — Usage examples

Practical examples for [`spec.md`](spec.md) (v0.5). Command output shown here is illustrative; the spec is authoritative.

passh is one binary plus one config file. It runs as your own user, needs no root, and changes nothing outside the store, its config file and `~/.local/state/passh/`.

---

## 1. Install

Requirements: `gpg` (GnuPG ≥ 2.2) with a pinentry, and `git` if you want history and sync. Most systems that can run `pass` already have them.

```bash
# Debian / Ubuntu / Raspberry Pi OS, if gpg isn't installed yet
sudo apt install gnupg git pinentry-curses
# macOS
brew install gnupg git pinentry-mac

# passh itself: one file, no root needed
install -m 755 passh ~/.local/bin/passh     # any folder on your PATH
passh doctor                                # read-only check of gpg, pinentry, git, clipboard
```

## 2. Configure

`~/.config/passh/config.toml`. Only `store` is required:

```toml
store = "~/.password-store"
```

A fuller example:

```toml
store = "~/.password-store"

[session]
idle_ttl    = "5m"
clear_agent = true

[clipboard]
clear_after = "30s"
osc52       = true
command     = ["pbcopy"]     # macOS Terminal.app has no OSC 52; on Linux e.g. ["wl-copy"]

[git]
auto_commit = true
```

Other places for the config:

```bash
passh --config ~/work/passh.toml ls     # per command
export PASSH_CONFIG=~/work/passh.toml   # per shell
passh --store ~/other-store ls          # different store, same config
```

## 3. Your first store

### 3.1 You already use `pass`

Nothing to convert. Point `store` at it (the default is `~/.password-store`) and run:

```bash
passh ls
```

`pass` keeps working on the same store.

### 3.2 Start from scratch

Create a GPG key if you don't have one. Use a strong passphrase: 6 or more random words.

```bash
gpg --quick-generate-key "Your Name <you@example.com>" ed25519 sign 2y
FPR=$(gpg --list-keys --with-colons you@example.com | awk -F: '/^fpr/ {print $10; exit}')
gpg --quick-add-key "$FPR" cv25519 encr 2y

passh init "$FPR" --git      # creates ~/.password-store as a git repo, and the config if missing
```

---

## 4. Everyday commands

```bash
passh ls                                   # whole tree
passh ls work
passh ls --tag 2fa
passh find github
passh tags                                 # tags with counts

passh show work/github
passh show work/github --field username
passh copy work/github                     # password to clipboard, cleared after 30 s

passh add work/gitlab                      # form: password (or generate), username, url, tags, notes
passh generate work/new-site 32 --symbols
passh generate work/new-site 32 --force    # replace an existing password
passh edit work/github                     # built-in form
passh edit work/github --editor            # $EDITOR, temp file on tmpfs (Linux)
passh mv work/jira work/atlassian/jira
passh rm work/old-site                     # asks for confirmation
passh tag work/github --add rotate-soon --remove dev
passh reindex                              # after editing with plain pass

passh lock                                 # make gpg-agent forget the store key now
```

Paths with spaces need quotes, as with any command: `passh show "bank/My Bank"`.

---

## 5. The TUI

```bash
passh
```

| Key | Action |
|---|---|
| ↑ ↓, Enter | Move, open folder or entry |
| `Tab` | Switch between the Folders and Tags views |
| `/` | Fuzzy search over paths and tags |
| `c` / `u` | Copy password / username |
| `r` | Reveal the password for 10 s |
| `e` / `a` / `d` | Edit / add / delete |
| `t` | Edit tags |
| `P` | Print page (§8.2) |
| `L` | Lock now |
| `?` / `q` | Help / quit (quitting also locks) |

The TUI locks after 5 minutes without input (`session.idle_ttl`).

---

## 6. Store on a server (e.g. a Raspberry Pi)

Install passh on the Pi as in §1, as your normal user, and keep the store and GPG key there. Then use it over plain SSH from any device:

```bash
ssh -t pi passh                                  # TUI on the Pi
ssh -t pi passh copy work/github                 # lands in your laptop's clipboard (OSC 52)
```

To pipe a secret into a local tool, unlock once with a terminal, then run commands without `-t` for as long as gpg-agent keeps the passphrase cached:

```bash
ssh -t pi passh unlock
ssh pi passh show work/github --field password | pbcopy        # macOS
ssh pi passh show work/github --field password | wl-copy       # Linux (Wayland)
ssh pi passh show work/github --field password | clip          # Windows
```

A shorter name in `~/.ssh/config` on the laptop helps:

```
Host pi
    HostName 100.101.102.103      # VPN address, or pi.local on the LAN
    User arsenii
```

---

## 7. Sync and backup

### 7.1 Git remote

```bash
git -C ~/.password-store remote add origin ssh://git@nas.lan/srv/git/passwords.git
git -C ~/.password-store push -u origin main
passh sync                                   # later: pull --ff-only, then push
```

Use a remote you trust. Without signed history, whoever controls the remote can change entries unnoticed (spec §9).

### 7.2 The GPG key: back it up once, separately

The key isn't in the store. Without it, the store can't be decrypted.

```bash
gpg --export-secret-keys --armor "$FPR" > key.asc     # still protected by your passphrase
# move key.asc to offline storage (USB stick in a drawer), then:
rm key.asc
```

Or on paper: `gpg --export-secret-keys "$FPR" | paperkey > key-paper.txt`, then print it.

### 7.3 Restore on a new machine

```bash
gpg --import key.asc
git clone ssh://git@nas.lan/srv/git/passwords.git ~/.password-store
install -m 755 passh ~/.local/bin/passh
mkdir -p ~/.config/passh && echo 'store = "~/.password-store"' > ~/.config/passh/config.toml
passh ls
```

---

## 8. Printing

### 8.1 PDF or text

```bash
passh print --format pdf -o /dev/shm/sheet.pdf          # asks you to confirm; prints, then delete it
passh print --folder bank --fields username,password --format txt -o /dev/shm/bank.txt
ssh pi passh print --format pdf --confirm-plaintext > sheet.pdf    # from the Pi to the laptop, no -t
```

### 8.2 Print page in a browser on another device

Enable it in the config on the machine that holds the store:

```toml
[print_web]
enabled    = true
interfaces = ["wg0", "eth0"]   # VPN and LAN; only private addresses are used
hostnames  = ["pi.local"]
```

Then:

1. `ssh -t pi passh`, press `P`, choose all entries, a tag or a folder, and the fields to include.
2. Type `PRINT`. passh shows the URL, a QR code and the certificate fingerprint:
   ```
   https://192.168.1.10:8443/p/kq7Z…        (also https://100.101.102.103:8443/p/kq7Z…)
   certificate SHA-256  4F:A1:9C:…:07:D2
   stops after one load or in 5:00
   ```
3. Open the URL on the laptop. **The first time**, the browser warns about the certificate. Open the certificate details from the warning page, compare the SHA-256 fingerprint with the one passh shows, and only accept if they match. Firefox can remember it permanently.
4. Press Ctrl/Cmd+P, then close the tab.

The server stops after that one load, after 5 minutes, on lock or when you quit. To print again, press `P` again. Don't paste the URL into a chat app: its link preview would use up the page.

passh doesn't change firewall settings. If the Pi runs a firewall, allow the port from the LAN and VPN yourself, e.g. `sudo ufw allow from 192.168.1.0/24 to any port 8443 proto tcp`.

---

## 9. Export

```bash
# whole store, entries stay encrypted
passh export --format archive -o passwords-$(date +%F).tar.gz

# encrypted to an age key, safe to move around
passh export --format bitwarden-json --age age1qy… -o vault.json.age
age -d -i ~/.config/age/key.txt vault.json.age > vault.json     # import into Vaultwarden, then delete

# plaintext CSV for KeePassXC (asks you to type EXPORT PLAINTEXT)
passh export --format csv -o /dev/shm/vault.csv

# from the Pi over SSH: no -t (a terminal would corrupt the file)
ssh pi passh export --format csv --confirm-plaintext > vault.csv
```

`--spreadsheet-safe` protects against formulas when you open the CSV in Excel, but it changes values that start with `= + - @`. Don't import that file into a password manager.

---

## 10. Uninstall

```bash
rm ~/.local/bin/passh
rm -r ~/.config/passh ~/.local/state/passh
```

The store stays a normal pass store.

---

## 11. Troubleshooting

| Symptom | Fix |
|---|---|
| `no config file` | `passh init …`, or create `~/.config/passh/config.toml` with `store = "…"` |
| No passphrase prompt over SSH, or `Inappropriate ioctl for device` | Use `ssh -t`, or unlock first with `ssh -t pi passh unlock` |
| Copy doesn't reach the clipboard | Run `passh doctor`. Use a terminal with OSC 52 (or tmux `set-clipboard on`), or set `clipboard.command` |
| `tag index stale — run reindex` | `passh reindex` |
| `refusing to write export data to a terminal` | Add `-o file` or redirect stdout |
| `edit --editor` refused on macOS | There's no tmpfs there; use the built-in form (`passh edit <path>`) |
| Print page certificate warning | Expected on first visit: compare fingerprints. If they **don't** match, don't continue |
| Print page says `already used` | Something loaded the URL first (link preview, prefetch). Press `P` again |
| `doctor` warns about swap or long agent TTLs | Advice only; passh never changes them. Fix them yourself if you want |
