# passh — Usage examples

Practical walkthroughs for the design in [`spec.md`](spec.md) (v0.4). Command output shown here is illustrative; where it differs from the spec, the spec wins.

Throughout, `pi` is the passh host, `vault` is its passh user, and `admin` is your normal sudo account on it.

---

## 1. Server setup (once)

### 1.1 Host preparation (as `admin`, with sudo)

Choose one:

- **Option A: directly on the host.** passh uses the host's sshd and a `vault` user.
- **Option B: Docker.** passh and its own sshd run in a container, and everything worth backing up sits in one folder (spec §3.5).

#### Option A: directly on the host

The installer (M8) does steps 1–4 for you. They're shown here so you know what it changes.

```bash
# 1. Packages: gpg, git, a terminal pinentry, machinectl for the admin path
sudo apt install gnupg git pinentry-curses systemd-container

# 2. Disable disk swap (Raspberry Pi OS ships an SD-card swap file)
sudo dphys-swapfile swapoff
sudo systemctl disable --now dphys-swapfile

# 3. The vault user: no password, /bin/sh, root-owned dotfiles
sudo useradd --create-home --shell /bin/sh vault
sudo passwd -l vault
sudo chown root:root ~vault/.profile ~vault/.bashrc

# 4. Install the binary (the script verifies the release signature first)
curl -fsSLO <release-url>/install.sh
less install.sh        # read it
sudo sh install.sh     # puts /usr/local/bin/passh (root:root 0755)
```

#### Option B: Docker

passh and its own sshd run in one container on port 2222. Your `ssh admin@pi` keeps using the host's sshd on port 22.

The container shares the host's kernel and clock. The host still needs time sync, and either the container's swap limit (below) must work or the host must have no disk swap; `doctor` tells you which applies.

```bash
# 1. Docker Engine with the compose plugin: see docs.docker.com/engine/install/debian

# 2. Folders
sudo install -d -m 700 /srv/passh /srv/passh/backup /srv/passh/local /srv/passh/local/ssh-host-keys
sudo install -d -m 755 /srv/passh/backup/config
sudo install -d -o 10001 -g 10001 -m 700 /srv/passh/backup/store /srv/passh/local/home
```

```
/srv/passh/
├── compose.yaml
├── backup/              ← back up this folder, and only this one
│   ├── config/          policy.toml, authorized_keys           → /etc/passh (read-only)
│   └── store/           the pass store, incl. the wrapped key  → /home/vault/.password-store
└── local/               ← never back up
    ├── home/            GnuPG keyring, pins, state, push key, print CA → /home/vault
    └── ssh-host-keys/   the container's SSH host keys                  → /etc/ssh/keys
```

`backup/` holds only public data and data protected by your passphrase. `local/` stays out of backups for two reasons:

- It holds the GnuPG copy of your key, which is less strongly protected than the wrapped copy in the store.
- It holds the SSH host keys. Someone with your backup *and* those keys could impersonate the server and catch your passphrase.

A restore rebuilds `local/` (§9.2).

`/srv/passh/compose.yaml`:

```yaml
services:
  passh:
    image: <registry>/passh:0.4@sha256:<digest>   # digest from the signed release notes
    container_name: passh
    restart: unless-stopped
    network_mode: host                  # host firewall applies; print page sees real addresses
    environment:
      SSH_LISTEN: "100.101.102.103:2222"   # the Pi's VPN address
    volumes:
      - ./backup/config:/etc/passh:ro
      - ./backup/store:/home/vault/.password-store
      - ./local/home:/home/vault
      - ./local/ssh-host-keys:/etc/ssh/keys
      - /run/systemd/journal/socket:/run/systemd/journal/socket   # audit log → host journal
    read_only: true
    tmpfs:
      - /tmp
      - /run/sshd:mode=0755
    shm_size: 64m                       # /dev/shm: tmpfs for admin-mode temp files
    mem_limit: 512m
    memswap_limit: 512m                 # same as mem_limit: no swap (passh checks)
    ulimits:
      memlock: 67108864                 # 64 MiB for locked secrets
      core: 0
    cap_drop: [ALL]
    cap_add: [CHOWN, SETUID, SETGID, SYS_CHROOT, KILL, AUDIT_WRITE]
    security_opt:
      - no-new-privileges:true
```

Don't switch to `ports:` with bridge networking. Docker's published ports bypass ufw, and the print page wouldn't see the host's addresses.

Start it and check:

```bash
cd /srv/passh
sudo docker compose up -d
sudo docker exec -u vault passh passh doctor
```

If `doctor` says the swap limit isn't enforced (the kernel lacks swap accounting), disable host swap as in Option A, step 2.

**Backing up the folder**, e.g. nightly with restic:

```bash
sudo restic -r sftp:backup@nas.lan:/backups/passh backup /srv/passh/backup
```

A copy taken in the middle of a write is caught and fixed on restore. The store is also pushed to the backup remote after every change (§1.7); the folder backup adds `config/` on top.

**Updating:** put the digest from the signed release notes into `compose.yaml`, then:

```bash
cd /srv/passh && sudo docker compose pull && sudo docker compose up -d   # restarting ends open sessions
```

Continue with §1.2; the Docker differences are marked there.

### 1.2 SSH access for your devices

On each client device, get the key fingerprint:

```bash
ssh-keygen -lf ~/.ssh/id_ed25519.pub
# 256 SHA256:Xq3r…  laptop (ED25519)
```

On the Pi, add the public keys to the root-owned key file:

```bash
sudo install -d -m 755 /etc/ssh/authorized_keys
echo 'restrict,pty ssh-ed25519 AAAA… laptop' | sudo tee -a /etc/ssh/authorized_keys/vault
echo 'restrict,pty ssh-ed25519 AAAA… phone'  | sudo tee -a /etc/ssh/authorized_keys/vault
sudo chmod 644 /etc/ssh/authorized_keys/vault
```

Append the `Match User vault` block from spec §3.2 to the **end** of `/etc/ssh/sshd_config`, then test the config before reloading. A bad config on a headless Pi locks you out.

```bash
sudo sshd -t && sudo systemctl reload ssh
```

**Docker:** the sshd settings are built into the image, so skip the `sshd_config` step. The key file lives in the backup folder:

```bash
echo 'restrict,pty ssh-ed25519 AAAA… laptop' | sudo tee -a /srv/passh/backup/config/authorized_keys
echo 'restrict,pty ssh-ed25519 AAAA… phone'  | sudo tee -a /srv/passh/backup/config/authorized_keys
sudo chmod 644 /srv/passh/backup/config/authorized_keys
```

### 1.3 Per-device rights: `/etc/passh/policy.toml`

```toml
[[key]]
name         = "laptop"
fingerprint  = "SHA256:Xq3r…"
access       = "read-write"
batch        = true          # allow scripting: ssh pi show … | pbcopy
export       = "plaintext"   # needed for print, the print page and plaintext CSV;
                             # use "encrypted" if you never print
fresh_unlock = false         # may use the unlock of your own open TUI

[[key]]
name         = "phone"
fingerprint  = "SHA256:Lm9k…"
# defaults: read-only, interactive only, no export,
# and a fresh passphrase prompt in every new session

[print_web]
enabled    = true
port       = 8443
interfaces = ["wg0", "eth0"]  # VPN and LAN; public addresses are refused
hostnames  = ["pi.local"]
ttl        = "5m"
```

```bash
sudo install -d -m 755 /etc/passh
sudo install -m 644 policy.toml /etc/passh/policy.toml   # root:root
```

**Docker:** `sudo install -m 644 policy.toml /srv/passh/backup/config/policy.toml` instead.

Changes to `policy.toml` and `authorized_keys` apply from the next session; no restart is needed.

> With `fresh_unlock` on the phone, opening a session on the phone locks the laptop's session too. That's intended: the phone never rides your laptop's unlock.

### 1.4 The admin shell

Everything marked *admin* below runs inside this shell:

```bash
ssh admin@pi
sudo machinectl shell vault@      # gives vault its own session and TTY, so pinentry works
export GPG_TTY=$(tty)             # for gpg commands you run yourself
passh --admin doctor
```

**Docker:**

```bash
ssh admin@pi
sudo docker exec -it -u vault passh sh
export GPG_TTY=$(tty)
passh --admin doctor
```

Anyone who can run `docker` on the host is effectively root, and therefore a passh admin.

Don't use `sudo -u vault`: pinentry can't open a TTY that belongs to `admin`.

### 1.5 Create a new store (admin)

Create a GPG key. Use a strong passphrase: **6 or more random words**. Anyone with a backup can try to guess it offline (spec §8.2).

```bash
gpg --quick-generate-key "passh vault" ed25519 sign 2y
FPR=$(gpg --list-keys --with-colons "passh vault" | awk -F: '/^fpr/ {print $10; exit}')
gpg --quick-add-key "$FPR" cv25519 encr 2y

passh --admin init "$FPR"
```

`init` does the following:

- writes `gpg-agent.conf` (TTLs, system pinentry, no loopback);
- creates the store with a signed `.gpg-id`;
- pins the fingerprints in `~/.config/passh/pins.toml`;
- writes `.passh/pubkey.asc`;
- asks for the passphrase again to create the key backup `.passh/secret-key.asc.age`;
- makes the first signed commit.

If you accept the 6-word passphrase `init` offers, also set it on the key (`gpg --passwd "$FPR"`), so both layers use the same one.

### 1.6 Or adopt an existing `pass` store (admin)

```bash
# copy your existing store into vault's home first
# (Docker: into /srv/passh/backup/store, owned by UID 10001), then:
passh --admin init --adopt
```

`--adopt` shows the current `.gpg-id` for confirmation. It then rewrites emails or short IDs to full fingerprints and refuses a store with a `.gpg-id` in a subfolder. It signs `.gpg-id`, writes the pins and key backup, and makes a signed adoption commit, which vouches for the store's old, unsigned history.

Plain `pass` keeps working on the store. To make it check the signature too, add this to vault's environment:

```bash
export PASSWORD_STORE_SIGNING_KEY=<FPR>
```

### 1.7 Backup remote (append-only)

On the backup machine (a NAS, another server), as the user that will receive pushes:

```bash
git init --bare /srv/git/passh-backup.git
git -C /srv/git/passh-backup.git config receive.denyNonFastForwards true
git -C /srv/git/passh-backup.git config receive.denyDeletes true
```

On a git host (Gitea, GitHub, GitLab), use a private repo with a deploy key that has write access, and protect the branch (no force push, no deletion).

Then, in the admin shell on the Pi:

```bash
passh --admin remote add nas ssh://backup@nas.lan/srv/git/passh-backup.git
# → prints the public key of ~/.ssh/passh_backup: register it on the remote
# → shows the remote's host key fingerprint: confirm it
passh --admin remote list
```

From then on, every change is pushed automatically after its commit.

### 1.8 Settings (admin)

Settings live in the signed `.passh/config.toml`. Never edit it by hand: that leaves the working tree dirty, and passh blocks writes until it's resolved.

```bash
passh --admin config get session.idle_ttl
passh --admin config set session.idle_ttl 3m
passh --admin config set session.max_ttl 10m
passh --admin config set clipboard.clear_after 20s
```

---

## 2. Client setup

`~/.ssh/config` on the laptop:

```
Host pi
    HostName 100.101.102.103      # the Pi's VPN address (or pi.local on the LAN)
    User vault
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
```

**Docker:** add `Port 2222`. passh's sshd listens there; port 22 stays the host's sshd for your admin account.

Check that clipboard copying (OSC 52) works in your terminal:

```bash
ssh pi doctor     # sends a test string to your clipboard, then clears it
```

If you use tmux on the laptop, add `set -g set-clipboard on` to `~/.tmux.conf`. In Termux, enable OSC 52 in the settings.

---

## 3. Everyday use: the TUI

```bash
ssh pi
```

The first action that needs a secret asks for your passphrase (pinentry, in the same terminal).

| Key | Action |
|---|---|
| ↑ ↓, Enter | Move, open folder or entry |
| `Tab` | Switch between the Folders and Tags views |
| `/` | Fuzzy search over paths and tags |
| `c` / `u` | Copy password / username to your clipboard (cleared after 30 s) |
| `r` | Reveal the password for 10 s |
| `e` / `a` / `d` | Edit / add / delete an entry (read-write keys only) |
| `t` | Edit tags |
| `P` | Open the print page (§6) |
| `L` | Lock now |
| `?` / `q` | Help / quit (quitting also locks) |

The header shows lock state and countdown, `✔ verified` or a red integrity banner, the device name, and the other open sessions. On a phone (under 80 columns) the TUI uses one pane: list → Enter → detail → Esc.

---

## 4. Everyday use: commands over SSH

Commands that decrypt something need an unlocked agent. If the store is locked, a command without a terminal can't ask for the passphrase. So keep `ssh pi` (the TUI) open and unlocked in another window, and run commands from a second window. The laptop key allows this (`batch = true`); the phone key doesn't.

### 4.1 Browse and read

```bash
ssh pi ls                         # whole tree (no unlock needed)
ssh pi ls work
ssh pi ls --tag 2fa               # needs unlock (tags are encrypted)
ssh pi find github
ssh pi tags                       # tags with counts

ssh pi show work/github
ssh pi show work/github --field username
```

### 4.2 Copy a password

```bash
# straight into the clipboard via your terminal (OSC 52); waits 30 s, then clears
ssh pi copy work/github

# or pipe it into a local clipboard tool
ssh pi show work/github --field password | pbcopy                        # macOS
ssh pi show work/github --field password | wl-copy                       # Linux (Wayland)
ssh pi show work/github --field password | xclip -selection clipboard    # Linux (X11)
ssh pi show work/github --field password | clip                          # Windows
ssh pi show work/github --field password | termux-clipboard-set          # Termux

# --raw gives exact bytes; normal output escapes control characters
ssh pi show work/github --field password --raw | pbcopy
```

### 4.3 Add and change entries

Interactive forms need a terminal, so use `-t`:

```bash
ssh -t pi add work/gitlab          # form: password (or generate), username, url, tags, notes
ssh -t pi edit work/github
ssh -t pi rm work/old-site         # asks for confirmation
```

These work without a terminal:

```bash
ssh pi generate work/new-site 32 --symbols
ssh pi generate work/new-site 32 --force        # replace an existing password
ssh pi mv work/jira work/atlassian/jira
ssh pi tag work/github --add rotate-soon --remove dev
ssh pi reindex                                   # after edits made with plain pass
```

Each change is a signed commit, pushed to the backup remote right away.

### 4.4 Paths with spaces or special characters

Your local shell strips one level of quotes, so quote twice:

```bash
ssh pi "show 'bank/My Bank'"
ssh pi "show 'shops/H&M'"
```

### 4.5 History, integrity, backup, lock

```bash
ssh pi log                    # store history (sanitised)
ssh pi log work/github        # one entry's history
ssh pi verify                 # signatures, pins, working tree
ssh pi sync                   # verify, then push to the backup remotes
ssh pi lock                   # flush the agent now (locks all sessions)
```

---

## 5. On the phone

```bash
ssh pi                        # TUI in single-pane mode; asks for the passphrase each new session
```

The phone key is read-only and interactive-only:

```bash
ssh pi show work/github --field password
# error: key "phone" may only read secrets in an interactive session
ssh pi rm work/github
# error: key "phone" is read-only
```

---

## 6. Printing

### 6.1 Print page in the browser (recommended)

**One-time setup (admin):**

```bash
passh --admin print-web init        # creates the local CA, limited to the Pi's addresses and names
passh --admin print-web ca          # prints the CA certificate (PEM) and its fingerprint
```

Copy the PEM block from your terminal into `passh-print-ca.pem` on each device you print from, and install it:

| Device | Install |
|---|---|
| macOS | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain passh-print-ca.pem` |
| Windows | `certutil -addstore -user Root passh-print-ca.pem` |
| Linux | Import it in the browser: Chrome → Settings → Privacy and security → Security → Manage certificates → Authorities. Firefox → Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import, then trust it for websites |
| iOS | Send the file to the phone and install the profile, then enable it under Settings → General → About → Certificate Trust Settings |
| Android | Settings → Security → Encryption & credentials → Install a certificate → CA certificate |

Open the port only for the LAN and the VPN, e.g. with ufw:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 8443 proto tcp
sudo ufw allow in on wg0 to any port 8443 proto tcp
```

The Docker deployment uses host networking, so these rules apply to it too.

**Each time you print:**

1. `ssh pi`, unlock, press `P`. Choose all entries, a tag or a folder, and the fields to include.
2. Type `PRINT` to confirm. passh shows the URL (and a QR code), e.g. `https://192.168.1.10:8443/p/kq7Z…`, with a countdown. Press `c` to copy the URL to your clipboard.
3. Open the URL in the browser and press Ctrl/Cmd+P.
4. Close the tab.

The server stops after that one page load, after 5 minutes, on lock or when you quit. To print again, press `P` again. Don't paste the URL into a chat app: its link preview would load the page first, and you'd see "already used".

From the command line, in a terminal session:

```bash
ssh -t pi print --web --tag shared-with-family --fields username,password,url
```

### 6.2 PDF or text file

```bash
ssh pi print --format pdf --confirm-plaintext > sheet.pdf
ssh pi print --folder bank --fields username,password --format txt --confirm-plaintext > bank.txt
```

Print it, then delete it: a PDF left in Downloads is a leak.

---

## 7. Export

### 7.1 Encrypted export (safe to run from scripts)

Once, on the laptop, create an age key for receiving exports:

```bash
age-keygen -o ~/.config/passh-export.key
# Public key: age1qy…
```

Pin it on the Pi (admin): add it to `~/.config/passh/pins.toml`.

```toml
[export.recipients]
laptop = "age1qy…"
```

Export, then decrypt locally:

```bash
ssh pi export --format bitwarden-json --to laptop > vault.json.age
age -d -i ~/.config/passh-export.key vault.json.age > vault.json   # import into Vaultwarden, then delete
rm vault.json
```

Only pinned recipients are accepted, so a stolen SSH key can't export to its own key.

### 7.2 Encrypted archive (whole store, entries stay GPG-encrypted)

```bash
ssh pi export --format archive > passh-$(date +%F).tar.gz
```

### 7.3 Plaintext export (keys with `export = "plaintext"` only)

```bash
ssh pi export --format csv --confirm-plaintext > vault.csv           # for KeePassXC: values are exact
ssh pi export --format csv --spreadsheet-safe --confirm-plaintext > vault-for-excel.csv
```

`--spreadsheet-safe` changes values that start with `= + - @`, passwords included, so don't import that file into a password manager.

Never use `ssh -t` for exports. A terminal turns line endings into CRLF and mixes error messages into the file. passh also refuses to write export data to a terminal.

---

## 8. Admin tasks

All of these run in the admin shell (§1.4).

### 8.1 Unsigned commits after using plain `pass` on the server

Adoption turns on commit signing, so plain `pass` normally signs too. If an unsigned commit gets in anyway, the TUI shows a red banner and writes are blocked:

```bash
passh --admin verify                                   # lists the commits and changed paths
git -C ~/.password-store rev-parse HEAD                # full id of HEAD
passh --admin verify --accept 3f9c2a…e81b              # review the diff, unlock, signed accept commit
```

### 8.2 Uncommitted changes in the store

```bash
passh --admin verify --discard     # shows what would be lost, then resets to HEAD
```

### 8.3 Add or revoke a device

- **Add:** append its line to `/etc/ssh/authorized_keys/vault` and a `[[key]]` block to `/etc/passh/policy.toml` (both as root). Docker: the same files are in `/srv/passh/backup/config/`.
- **Revoke:** delete both lines. Nothing on the device needs to be wiped: no secrets are stored there.

### 8.4 Change the passphrase

```bash
gpg --passwd "$FPR"
passh --admin key backup        # re-wrap the key backup with the new passphrase
```

Old key backups stay in git history with the **old** passphrase. If the old one was weak or leaked, create a new key instead (§8.6).

### 8.5 Extend key expiry

```bash
gpg --quick-set-expire "$FPR" 2y
gpg --quick-set-expire "$FPR" 2y '*'    # subkeys
passh --admin key backup                # refresh pubkey.asc and the backup
```

### 8.6 Key compromise

```bash
passh --admin recipients set <NEW_FPR>   # re-sign .gpg-id, re-encrypt everything, new key backup
```

Old ciphertexts remain readable in git history and on the backup remote, so **change every password** afterwards.

### 8.7 Recovery kit

The kit holds the fingerprint, the backup URLs and the restore steps. With `--with-key` it also includes the wrapped key as QR codes. It holds no passwords and no passphrase.

```bash
passh --admin print --recovery-kit --with-key > /dev/shm/passh-kit.pdf
passh --admin print --recovery-kit --with-key --lp office-printer       # if CUPS runs on the Pi
```

To get the file to your laptop: as `admin` on the Pi, run `sudo install -o admin -m 600 /dev/shm/passh-kit.pdf ~/passh-kit.pdf && sudo rm /dev/shm/passh-kit.pdf`. Then on the laptop, run `scp admin@pi:passh-kit.pdf . && ssh admin@pi rm passh-kit.pdf`.

**Docker:** copy it out on the Pi as `admin`, without `-t` so the PDF isn't mangled, then `scp` it as above:

```bash
(umask 077; sudo docker exec -u vault passh cat /dev/shm/passh-kit.pdf > ~/passh-kit.pdf)
sudo docker exec -u vault passh rm /dev/shm/passh-kit.pdf
```

Store the kit offline, and keep the passphrase somewhere else.

---

## 9. Restore

### 9.1 On a new host, with passh

Set the host up as in §1.1–1.4, then in the admin shell:

```bash
passh --admin restore ssh://backup@nas.lan/srv/git/passh-backup.git --fingerprint 0123456789ABCDEF0123456789ABCDEF01234567
```

Take the fingerprint from the recovery kit or your notes, not from the backup. `restore` then:

- creates `~/.ssh/passh_backup` and prints its public key. Register it on the remote (read access is enough to restore) and confirm the remote's host key;
- clones without checking out and checks every signature against that fingerprint;
- shows the date of the latest commit and the entry count, so you can spot an older copy;
- asks for your passphrase and imports the key;
- checks out the store and rebuilds the tag index.

From an archive instead: `passh --admin restore /path/passh-2026-11-15.tar.gz --fingerprint …`

### 9.2 Docker, from a folder backup

On the new host, follow §1.1 Option B. Put your copy of `backup/` back in `/srv/passh/backup` and leave `local/` empty:

```bash
sudo restic -r sftp:backup@nas.lan:/backups/passh restore latest --target /
cd /srv/passh && sudo docker compose up -d
sudo docker exec -it -u vault passh passh --admin restore --in-place --fingerprint 0123456789ABCDEF0123456789ABCDEF01234567
```

`--in-place` verifies the store that's already there instead of cloning it, then asks for your passphrase and rebuilds `local/`. Afterwards:

- register the push key it prints on the backup remote again;
- run `passh --admin print-web init` and install the new CA on your devices (§6.1);
- check the container's new SSH host key, then make each client forget the old one:

  ```bash
  sudo docker exec passh ssh-keygen -lf /etc/ssh/keys/ssh_host_ed25519_key.pub   # on the Pi
  ssh-keygen -R '[100.101.102.103]:2222'                                         # on each client
  ```

### 9.3 Emergency, without passh

Any machine with `git`, `age`, `gpg` and `pass`:

```bash
git clone ssh://backup@nas.lan/srv/git/passh-backup.git ~/.password-store
age -d ~/.password-store/.passh/secret-key.asc.age | gpg --import    # passphrase for age, then for gpg
gpg --import-ownertrust <<< "0123456789ABCDEF0123456789ABCDEF01234567:6:"
pass show bank/revolut       # or: gpg -d ~/.password-store/bank/revolut.gpg
```

This skips signature checks; prefer `passh restore` when you can.

---

## 10. Troubleshooting

| Symptom | Meaning | Fix |
|---|---|---|
| `unlock in an interactive session first` | The agent is locked, and a command without a terminal can't ask for the passphrase | Open `ssh pi`, unlock, keep it open, retry in another window |
| `key "phone" may only read secrets in an interactive session` | The key has no `batch` right | Use the TUI, or change `policy.toml` |
| Red `⚠ integrity` banner | Unsigned commits, a dirty working tree or a changed `.gpg-id` | Admin: `passh --admin verify`, then `--accept` or `--discard` (§8.1–8.2) |
| `tag index stale — run reindex` | Entries changed outside passh | `ssh pi reindex` |
| `last push 3 days ago ⚠` | The backup remote is unreachable or rejected the push | `ssh pi sync`; admin: `passh --admin remote list` |
| passh refuses to decrypt: `gpg-agent.conf …` | Agent config is too lax (TTLs, pinentry, loopback) | `ssh pi doctor` names the line to fix |
| passh refuses to decrypt: `disk swap active` | Swap on the SD card or disk | Disable it (§1.1) |
| `unlock refused for 4 min` | Too many wrong passphrases (backoff) | Wait; check the journal if it wasn't you |
| Copy doesn't reach the clipboard | The terminal doesn't support OSC 52 | `ssh pi doctor`; tmux `set-clipboard on`; Termux setting |
| Exported file is corrupt (CRLF) | Exported with `ssh -t` | Export without `-t` |
| Certificate warning on the print page | The CA isn't installed on this device | Install it (§6.1). Don't click through on a LAN |
| Print page says `already used` | Something loaded the URL first (link preview, prefetch) | Press `P` again |
