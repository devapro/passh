# passh — Specification

> Working name: **passh** ("pass over SSH").
> Status: Draft v0.4 · Owner: Arsenii · Date: 2026-11-15

---

## Changelog

| Version | Changes |
|---|---|
| v0.4 | **Print page** (§7.4): a one-shot HTTPS page with the password sheet, for printing from a browser on the LAN or VPN. Off by default; needs the plaintext-export right; private addresses only; local CA with name constraints; single-use token; stops after one load, 5 min or lock. `keys.toml` renamed to `policy.toml`, since it now also holds host settings. Admin commands `config get/set` and `remote add/list/remove`, so settings and backup remotes change through signed commits instead of hand edits. Docker deployment (§3.5) with a single folder to back up; `restore --in-place` |
| v0.3 | Second security review (independent review + owner decisions). **Per-key rights** from sshd (`ExposeAuthInfo`) and a root-owned `/etc/passh/policy.toml`; v0.2's per-key `command=` was silently overridden by `ForceCommand`. sshd template fixed (`PermitUserEnvironment` is not allowed in `Match`). Restricted by default; explicit admin mode, reached with `machinectl`, refused over SSH. **Push-only sync**; restore clones without checkout and verifies first. Trust rule "signed tip vouches for its ancestors", with signed adoption and accept commits, so adopted stores can be restored. Working tree must equal HEAD. **Secret key bundled in the store** (age scrypt + OpenPGP), so backup + passphrase restores; public key in the store. All output sanitised, including pipes. Strict `.git/config` allowlist, pinned `ssh`, minimum tool versions. gpg: `--no-options`, status on fd 3, `--pinentry-mode error` without a TTY, commits signed by passh via git plumbing. `no-allow-loopback-pinentry` required. Pinentry/TUI terminal handoff. Command × key permission matrix. Store lock, atomic writes, signal handling. Exports only to pinned recipients unless the key has plaintext export. Recovery kit admin-only. Failed-unlock backoff. Minimal path denylist (adopted stores open unchanged), nested `.gpg-id` and dot-segments rejected, `os.Root`. CSV exact by default. Extended tests |
| v0.2 | Security review fixes. Restricted mode (no shell escapes through editor, pager or git). Signed `.gpg-id` and pinned recipients. Signed git commits verified on start and restore. Path and argument injection rules. `--status-fd` parsing. Sanitised terminal output. `SSH_ORIGINAL_COMMAND` allowlist. Pinentry TTY handling. Swap and mlock. Editor leak prevention. Non-interactive export confirmation. Append-only backup remote. Corrected clipboard rule R6. `crypto/rand` generation. Environment sanitisation. Extended threat model and acceptance tests |
| v0.1 | Initial draft |

---

## 1. Summary

passh is a single Go binary for managing passwords on a self-hosted machine (Raspberry Pi or VPS). Users reach it over SSH from any device on the LAN or VPN. It reads and writes a **pass-compatible** store: GPG-encrypted files in a git repository. On top of that it adds:

- a session model: unlock once, then use for N minutes; locked automatically on timeout or exit;
- per-SSH-key rights: e.g. the laptop can write and script, the phone can only read interactively;
- a TUI for browsing by folder (category) and tag;
- copying to the *client* clipboard over SSH (OSC 52), with best-effort clearing;
- export (CSV / JSON / encrypted archive), a printable sheet (PDF / text), and a one-shot print page that opens in a browser on the LAN or VPN;
- integrity protection: signed recipient list and signed history;
- a self-contained backup: the store carries its own passphrase-protected key, so **backup + passphrase** is enough to restore anywhere.

All data lives on one host, so there is one place to back up.

## 2. Goals and non-goals

### Goals

| # | Goal |
|---|------|
| G1 | One static Go binary (`linux/arm64`, `linux/amd64`, `linux/arm/v7`), no runtime besides `gpg`, `git` and `ssh` |
| G2 | Compatibility with the `pass` store layout. Existing stores open unchanged (signing is added on adoption, §4.4), and `pass` keeps working on a passh store |
| G3 | Usable entirely over SSH from macOS, Linux, Windows, Android (Termux) and iOS SSH clients |
| G4 | Unlock once per session. Secrets are forgotten after a TTL or on session end |
| G5 | Browse and search by folder and by tag in a TUI |
| G6 | Export and printing for migration and offline emergency backup, including printing straight from a browser without saving a file |
| G7 | Every change committed and signed in git. Backup = push of one repository. Backup + passphrase restore everything |
| G8 | A user restricted to passh over SSH can't get a shell or run arbitrary commands through passh, and each SSH key gets only the rights listed for it |

### Non-goals (v1)

- Browser extensions, mobile autofill, native mobile apps
- Multi-user sharing, roles, permissions (per-key rights are for one owner's devices)
- Web UI or HTTP API. The only exception is the one-shot, read-only print page (§7.4)
- Sync across several servers. Git remotes are **push-only** backups
- Windows/macOS *server* support (clients only need SSH)
- Protection against an attacker who already controls the `vault` user or root (§9)

## 3. Deployment model

```
 ┌──────────────┐   WireGuard / Tailscale   ┌───────────────────────────────┐
 │ Laptop/Phone │ ─────────── SSH ────────▶ │ Raspberry Pi / VPS             │
 │ (any SSH     │                           │  user: vault                   │
 │  client)     │ ◀── OSC 52 clipboard ──── │  ~/.password-store  (git)      │
 └──────────────┘ ◀── HTTPS print page ──── │  ~/.gnupg           (key)      │
       (browser, on demand, LAN or VPN)     │                                │
                                            │  /usr/local/bin/passh (root:root 0755)
                                            │  /etc/passh/policy.toml (root:root 0644)
                                            └──────────┬────────────────────┘
                                                       │ git push only (append-only remote)
                                                       ▼
                                                 Backup target(s)
```

Decryption happens **on the server** (model "A"). This is the chosen trade-off: zero client setup, in exchange for the server being a high-value target. See §9.

passh runs either directly on the host (§3.1–3.4) or in a Docker container (§3.5).

### 3.1 Host requirements

- **OS:** Debian 12 / Raspberry Pi OS bookworm or newer. Minimum versions, checked by `doctor` and at start: git ≥ 2.32 (`GIT_CONFIG_GLOBAL`; bullseye's 2.30 silently ignores it), GnuPG ≥ 2.2.8 (missing MDC is fatal), OpenSSH ≥ 7.6 (`ExposeAuthInfo`).
- **`vault` user:** used only for passh, no other services. Password locked (`passwd -l`). Login shell `/bin/sh`. Dotfiles in `~vault` (`.profile`, `.bashrc`, …) owned by root, because sshd runs `ForceCommand` through the login shell.
- **Binary:** `passh` owned by root and not writable by `vault`.
- **Swap disabled, or zram without writeback.** Raspberry Pi OS enables an SD-card swap file by default (`dphys-swapfile`), which can persist decrypted data. passh reads `/proc/swaps` **at every start** and refuses to decrypt if disk-backed swap is active. No hibernation. In a container, a cgroup swap limit of 0 also satisfies this rule (§3.5).
- **Time sync** (`systemd-timesyncd`). A Pi has no RTC; a wrong clock makes gpg report signatures from the future, which shows as a false integrity failure.
- **`systemd-container`** installed, for the admin path (`machinectl`, §3.4).
- **Firewall:** if the print page is enabled (§7.4), its port accepts connections only from the LAN and VPN subnets.
- Full-disk or home-directory encryption is recommended but not required (entries are already encrypted; it protects metadata).

### 3.2 SSH configuration

`sshd_config`. The installer writes this and runs `sshd -t` before reloading, so a bad template can't lock the owner out of a headless host:

```
# global scope (not allowed inside Match)
PermitUserEnvironment no

Match User vault
    AuthenticationMethods publickey
    AuthorizedKeysFile /etc/ssh/authorized_keys/%u
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    DisableForwarding yes
    PermitTunnel no
    PermitUserRC no
    PermitTTY yes
    ExposeAuthInfo yes
    ForceCommand /usr/local/bin/passh
```

`/etc/ssh/authorized_keys/vault` (root:root 0644, so neither `vault` nor a passh bug can add keys):

```
restrict,pty ssh-ed25519 AAAA… laptop
restrict,pty ssh-ed25519 AAAA… phone
```

- `restrict` turns off all forwarding and user rc files; `pty` re-enables only the terminal.
- **No per-key `command=`.** A `ForceCommand` in `sshd_config` overrides it. Per-key rights come from §3.3 instead.
- `ExposeAuthInfo` makes sshd write the authenticating public key to a file named by `$SSH_USER_AUTH`. The client can't set or change this variable (`PermitUserEnvironment no`; it's never in `AcceptEnv`).
- passh ignores all inherited environment except the `SSH_*` variables it reads and `TERM`, which it validates. Distribution defaults such as `AcceptEnv LANG LC_*` are therefore harmless.
- `sshd` binds only to the VPN interface (`ListenAddress`), or the firewall drops port 22 on all other interfaces.

### 3.3 Host policy (`/etc/passh/policy.toml`)

Root-owned (root:root 0644). It holds per-key rights and host-level features such as the print page (§7.4). passh maps the key in `$SSH_USER_AUTH` to its rights. **Unknown keys are refused.**

```toml
[[key]]
name         = "laptop"
fingerprint  = "SHA256:…"      # as printed by ssh-keygen -lf
access       = "read-write"
batch        = true
export       = "encrypted"
fresh_unlock = false

[[key]]
name         = "phone"
fingerprint  = "SHA256:…"
# defaults: read-only, no batch, no export, fresh_unlock

[print_web]                     # §7.4; off unless enabled here
enabled    = false
port       = 8443
interfaces = ["wg0", "eth0"]    # only private addresses on these are used
allow_from = []                 # extra CIDR limit; default = subnets of the bound addresses
hostnames  = ["pi.local"]       # optional names for the certificate
ttl        = "5m"               # 1–15 min
```

| Field | Values | Default | Meaning |
|---|---|---|---|
| `name` | text | required | Shown in the TUI header and in the audit log |
| `fingerprint` | `SHA256:…` | required | Key fingerprint |
| `access` | `read-only` / `read-write` | `read-only` | Whether write commands are allowed (§6.1) |
| `batch` | bool | `false` | Whether non-interactive commands (no PTY) may decrypt or sign, e.g. `ssh pi show x \| pbcopy` |
| `export` | `none` / `encrypted` / `plaintext` | `none` | Bulk export, print and print page rights (§7) |
| `fresh_unlock` | bool | `true` | A new interactive session from this key flushes the agent before its first decrypt, so it never rides another device's unlock (§5.1). This also locks other open sessions |

- Non-interactive commands can't prompt. A key with `fresh_unlock = true` therefore can't use `batch` or decrypting exports; passh rejects such combinations when it loads the file.
- A missing, unreadable, non-root-owned or malformed `policy.toml`, or a `$SSH_USER_AUTH` that doesn't name exactly one `publickey`, refuses the session.

### 3.4 Modes

| Mode | How entered | Allowed |
|---|---|---|
| **SSH** (restricted) | Any session started by sshd, detected by any `SSH_*` variable (`SSH_CONNECTION`, `SSH_CLIENT`, `SSH_TTY`, `SSH_ORIGINAL_COMMAND`, `SSH_USER_AUTH`) | Commands in §6.1 allowed for the key's policy (§3.3). Built-in editor only. passh directly runs only `gpg`, `gpg-connect-agent` and `git` with fixed arguments, and opens no network listener except the print page (§7.4) |
| **Console** (restricted) | `passh` run as `vault` locally, without `--admin` | Same command set as SSH, with read-write rights and all capabilities |
| **Admin** | `passh --admin …` | All commands, including `init`, `restore`, `recipients set`, `key backup`, `verify --accept`, `print --recovery-kit`, export to a file, and an external `$EDITOR` (§5.4) |

- Restricted is the default; there is no flag to turn it off, only `--admin` to opt in.
- `--admin` is refused when any `SSH_*` variable is set, or when stdin is not a TTY. No flag in `SSH_ORIGINAL_COMMAND` can change the mode or the policy (§6.4).
- **Admin path:** log in over SSH as your normal sudo user, then run `sudo machinectl shell vault@`. That gives `vault` its own login session and TTY, so pinentry can open the terminal. `sudo -u vault` does not work: the TTY stays owned by the admin user and pinentry can't open it. In a container, use `docker exec` instead (§3.5).

### 3.5 Container deployment (Docker)

passh can run in a Docker container instead of directly on the host. §3.1–3.4 apply, with these differences.

**Image and container**

- One container runs sshd and passh. The host keeps its own sshd for the admin.
- Image: Debian bookworm-slim with `gnupg`, `git`, `openssh-server`, `openssh-client` and `pinentry-curses`, plus passh owned by root. It is pulled by digest; the digest is listed in the signed release notes (§10.1).
- **Host networking.** The host firewall applies, and the print page sees the host's real addresses (§7.4). sshd listens on the addresses in `SSH_LISTEN`, port 2222 by default; the entrypoint passes them to sshd with `-o ListenAddress=…`.
- **Bridge networking is not supported in v1.** Docker's port publishing bypasses host firewalls such as ufw, and the print page would see container addresses instead of the host's.
- sshd uses the settings of §3.2, plus `AllowUsers vault`, `PermitRootLogin no`, `AuthorizedKeysFile /etc/passh/authorized_keys` and host keys in `/etc/ssh/keys`. The entrypoint creates any missing host keys.
- `vault` has UID 10001 and the login shell `/bin/sh`. Its home folder is owned by root and its subfolders by `vault`; the entrypoint enforces this at every start.

**Hardening**

- Read-only root filesystem. tmpfs for `/tmp`, and for `/run/sshd` with mode 0755 (sshd refuses a world-writable privilege-separation directory). `/dev/shm` is tmpfs (R1).
- `cap_drop: ALL`, adding back only what sshd needs: `CHOWN`, `SETUID`, `SETGID`, `SYS_CHROOT`, `KILL`, `AUDIT_WRITE`. `no-new-privileges`. CI checks that login works with exactly this set.
- **Swap:** `memswap_limit` equal to `mem_limit`, so the container can't swap. passh verifies this by reading the cgroup's `memory.swap.max`, because Docker silently ignores the limit on kernels without swap accounting. If the value isn't 0, the host rule of §3.1 applies: no disk swap.
- `memlock` ulimit 64 MiB for locked secrets (R3); `core` ulimit 0 (R2).
- The clock comes from the host, so time sync runs on the host (§3.1).
- **Audit log:** the host's journal socket is mounted into the container. Without it passh appends to `<state>/audit.log`, and `doctor` warns.

**Admin path**

- `docker exec -it -u vault passh …` replaces `machinectl` (§3.4). It sets no `SSH_*` variables and gives a TTY, so `--admin` works and pinentry can open the terminal.
- Anyone who can run `docker` on the host is root-equivalent, and therefore an admin of passh.

**Folders** (host paths are examples)

| Host folder | In the container | Holds | Back up? |
|---|---|---|---|
| `/srv/passh/backup/config/` | `/etc/passh` (read-only) | `policy.toml`, `authorized_keys` | **Yes** |
| `/srv/passh/backup/store/` | `/home/vault/.password-store` | The store, including the wrapped key (§8.2) | **Yes** |
| `/srv/passh/local/home/` | `/home/vault` | GnuPG keyring and agent sockets, `pins.toml`, state, push key, print page CA | **No** |
| `/srv/passh/local/ssh-host-keys/` | `/etc/ssh/keys` | The container's SSH host keys | **No** |

- `backup/` holds only data that is public or protected by the passphrase. Backing up that one folder is enough to restore (§8.4).
- `local/` is never backed up. It holds:
  - the GnuPG copy of the key, which is less strongly protected than the age-wrapped copy;
  - the SSH host keys. With a backup plus those keys, an attacker could impersonate the server and catch the passphrase;
  - the push key and the print page CA key.

  A restore rebuilds `local/`. Clients then see a new host key, and the print page CA must be created and installed again.
- `backup/` can be copied while passh runs. A copy taken in the middle of a write fails verification on restore and is fixed with `verify --discard` (§4.5).

## 4. Storage format and integrity

### 4.1 Layout (pass-compatible)

```
~/.password-store/
├── .gpg-id                   # recipient key fingerprint(s), root of the store only
├── .gpg-id.sig               # detached signature of .gpg-id (pass-compatible)
├── .git/
├── .passh/                   # passh-specific data; ignored by pass
│   ├── config.toml
│   ├── tags.idx.gpg          # encrypted tag index (§4.3)
│   ├── pubkey.asc            # public key, armored
│   └── secret-key.asc.age    # passphrase-protected secret key (§8.2)
├── work/
│   ├── jira.gpg
│   └── github.gpg
└── bank/
    └── revolut.gpg
```

Local state outside the repo (never pushed):

- `~/.config/passh/pins.toml`: pinned recipients, signing key and export recipients (§4.4, §7.1). Written in admin mode only.
- `~/.local/state/passh/`: `verified-head` (§4.5), the store `lock` (§4.7), the failed-unlock counter (§5.1), last push status (§8.3) and `known_hosts` for backup remotes.

`.passh/config.toml` holds settings such as `session.*`, `clipboard.*` and `backup.remotes`. Change it only with `passh --admin config set` or `remote add/remove`, which validate the value and make a signed commit. Editing the file by hand leaves the working tree dirty, which fails verification (§4.5).

- **Folders = categories.** This is pass's native model and is kept as the primary hierarchy.
- File names and paths are **not encrypted**. Git history also keeps the names of deleted entries and their old ciphertexts forever. Both are accepted risks (§9).

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

- Metadata is the run of `key: value` lines (key matches `[a-z0-9_-]+`) right after line 1. It ends at a `---` line or the first line that doesn't match. Everything after that is notes. `---` is a passh convention; pass treats the whole file as free-form.
- Reserved keys: `username`, `url`, `tags`, `otp` (reserved for a future version, not implemented in v1).
- `otp:` values and `otpauth://` lines (pass-otp format) are treated as secrets: masked, never indexed, exported as their own field.
- Unknown and duplicate keys are preserved in order; the first one is shown.
- An entry that passh only reads is never rewritten. An edit rewrites only the changed lines.
- Form fields other than notes reject newlines. Otherwise a username could inject `tags:` or `url:` lines.

### 4.3 Tags

Tags live inside the encrypted entry, so listing by tag would mean decrypting every file. To avoid that:

- passh keeps `.passh/tags.idx.gpg`, an encrypted map `{path → [tags]}`, encrypted to the same pinned recipients as the store.
- It is decrypted once after unlock and held in memory for the session.
- It is updated in the same commit as every add, edit, move or delete done through passh.
- `passh reindex` rebuilds it by decrypting all entries, one at a time. Use it after edits made with plain `pass` or by hand, or when the file is missing.
- The index stores a hash over the sorted `(path, git blob id)` list of all entries. If that differs from the current store, the TUI shows "tag index stale — run reindex". A commit hash can't be used, because the index is committed inside the commit it would have to name.

Decision: tags are **in addition to** folders, not instead of them. Folders stay for pass compatibility. Tags serve cross-cutting views such as `2fa`, `shared-with-family` or `rotate-soon`.

### 4.4 Recipient pinning (`.gpg-id` protection)

Threat: anyone who can write to the store could replace `.gpg-id`, so that new entries get encrypted to an attacker's key.

- `~/.config/passh/pins.toml` (outside the repo, written in admin mode only) pins the expected fingerprints. Fingerprints are always full 40-character values, never short key IDs:
  ```toml
  [crypto]
  recipients  = ["0123456789ABCDEF0123456789ABCDEF01234567"]
  signing_key = "0123456789ABCDEF0123456789ABCDEF01234567"
  ```
  `.passh/config.toml` holds a copy, so the pins travel with backups. Both copies must agree. On restore, the trust anchor is the fingerprint the user types (§8.4), never the cloned `config.toml`.
- `.gpg-id.sig` is a detached signature by `signing_key`, the same mechanism as pass's `PASSWORD_STORE_SIGNING_KEY`. pass only checks it when that variable is set, so the README tells admins to set it for plain `pass`.
- **Before every encrypt**, passh verifies `.gpg-id.sig` and checks that `.gpg-id` matches the pinned recipients exactly. On any mismatch it refuses to write and shows an integrity error.
- **Only the root `.gpg-id` is allowed.** pass honours `.gpg-id` files in subfolders and would encrypt that folder to other keys. Any `.gpg-id` below the root is an integrity error, and `init --adopt` refuses a store that has one, telling the admin how to merge.
- `.gpg-id` must list full fingerprints. If an adopted store's `.gpg-id` holds emails or short IDs, `init --adopt` rewrites it after confirmation.
- Changing recipients requires `passh recipients set …` in admin mode. It re-signs `.gpg-id`, re-encrypts all entries and the index, refreshes `.passh/pubkey.asc` and `secret-key.asc.age`, and commits.
- **Re-encryption doesn't revoke access.** Old ciphertexts stay in git history and on the append-only remote, readable by the old key. After a key compromise, rotate every password. passh prints this after `recipients set`.
- When adopting an existing pass store, `init --adopt` shows the current `.gpg-id` for confirmation, then creates the signature, the pins, the key backup (§8.2) and a signed adoption commit (§4.5).

### 4.5 History integrity (signed commits)

Threat: GPG encryption doesn't authenticate the writer. An attacker could plant a correctly encrypted entry, for example replacing a bank URL with a phishing URL.

**Signing.** Every commit made by passh is signed with `signing_key`. passh builds commits with git plumbing, so it runs gpg itself under the rules in §5.5 and never relies on `gpg.program`:

1. stage with `git update-index`;
2. `git write-tree`;
3. sign the commit payload with gpg, as a detached signature;
4. `git hash-object -t commit -w --stdin`;
5. `git update-ref HEAD <new> <old>`; the compare-and-swap fails loudly if HEAD moved.

Signing needs the unlocked key, so writes only happen inside an unlocked session.

**Verification.** passh verifies signatures itself:

- It reads the commit with `git cat-file commit`, splits the `gpgsig` header from the signed payload, and runs `gpg --verify` with status on fd 3.
- A commit is **signed** when there is exactly one signature and its `VALIDSIG` *primary-key* fingerprint (the last field; the first is the subkey) equals the pinned `signing_key`.
- Signatures from an expired key (`EXPKEYSIG`) are accepted with a warning, and writes are blocked until the key's expiry is extended. `REVKEYSIG`, `BADSIG`, `ERRSIG`, any other key and multiple signatures count as not signed.

**Trust rule.** A signed commit vouches for its tree and, through git's hash chain, for all its ancestors. passh **never creates a signed commit unless the store is verified**, and that is what makes the rule sound. The store is **verified** when all of these hold:

1. HEAD is signed;
2. `verified-head`, if present, is an ancestor of HEAD, so history was not rewritten;
3. working tree, index and HEAD are identical: `git status --porcelain --untracked-files=all --ignored` prints nothing.

The check runs at start and before every write. On success `verified-head` advances to HEAD. If `verified-head` is missing (new host, lost state), rules 1 and 3 apply, and the TUI shows the tip date and entry count once for confirmation.

**On failure:**

- writes are refused;
- reads continue, but the TUI shows a red integrity banner listing the commits since the last signed one and the paths they changed (sanitised, R8);
- unsigned commits on top (e.g. made by plain `pass`): the admin reviews them with `passh --admin verify --accept <commit>`. The `<commit>` must be HEAD, given as a full hex id. It requires unlock and creates a **signed empty commit** "passh: accept <ids>", which vouches for them in every clone, including restores;
- a dirty working tree: the admin resolves it with `passh --admin verify --discard`, which resets to HEAD after showing what would be lost, or by committing through passh.

**Making plain `pass` sign too.** Adoption sets repo-local `commit.gpgsign = true` and `user.signingkey = <fpr>` (both allowlisted, §5.5). Plain `pass` used by the admin on the server then produces signed commits, and `verify --accept` is rarely needed.

**Adoption and rotation.** The adoption commit is signed, so it vouches for the store's unsigned pre-adoption history. After a key change, new commits are signed by the new key and a restore uses the new fingerprint; older signatures don't matter under the trust rule.

passh doesn't sign individual entries; commit signatures cover them.

### 4.6 Path rules

Every user-supplied or on-disk path goes through one validator, which produces a `paths.Safe` (§10.3). The rules reject only what is dangerous, so existing pass stores open unchanged:

- relative to the store root, cleaned (`filepath.Clean`), no empty, `.` or `..` segments, no absolute paths, no `\`;
- **no segment starts with `.`** (covers `.git`, `.passh`, `.gpg-id`, `.gitattributes`, `.gitmodules` and pass's `.extensions` at any depth);
- **no segment starts with `-`**;
- no control characters (C0, C1, DEL), no NUL, no Unicode format characters (category Cf: bidi overrides, zero-width characters);
- everything else is allowed, including spaces, `& ' ( ) , : # =` and combining marks. This is safe because nothing runs a shell, `--` precedes every path argument, and git runs with `GIT_LITERAL_PATHSPECS=1` (§5.5);
- lookups are NFC-insensitive; new names are written in NFC.

Opening files:

- All file access goes through `os.Root` (Go ≥ 1.24) anchored at the store root, plus a per-component `Lstat` that **refuses symlinks**.
- git runs with `core.symlinks=false`, so git itself never creates a symlink in the working tree; a committed symlink checks out as a plain file.

An on-disk name that fails the rules is listed (sanitised) with a warning, and can't be opened until an admin renames it.

### 4.7 Concurrency and atomic writes

- Every write sequence (verify → encrypt → write → index → commit) holds an exclusive `flock` on `~/.local/state/passh/lock`. Readers don't take the lock.
- Files are written to a temporary file in the same directory, `fsync`ed and renamed. The commit is made before the lock is released, so a normal run never leaves a dirty tree. After a crash, the dirty tree fails rule 3 (§4.5) and the admin resolves it.
- Sessions holding an in-memory tag index re-check its hash before each write and reload if another session changed the store.

## 5. Session and security model

### 5.1 Unlock

- Decryption is delegated to the system `gpg` binary (see ADR-1).
- **Pinentry:** the first operation that needs a secret triggers a prompt via a root-owned system `pinentry-curses` or `pinentry-tty`. passh passes its own `GPG_TTY` and a validated `TERM` to every gpg call; gpg forwards both to the agent for that request. `updatestartuptty` is not needed: it only affects the agent's ssh support.
- **Unlock primes both keys.** It decrypts the tag index and makes a throwaway detached signature, so any prompts for the decryption and signing keys happen at unlock, not in the middle of a write.
- **No TTY** (non-interactive command): every gpg call gets `--pinentry-mode error`. If the key isn't cached, the command fails with "unlock in an interactive session first" instead of prompting somewhere else. Before signing, passh probes the signing keygrip with `KEYINFO`.
- **Terminal handoff:** before any gpg call that may prompt, the TUI releases the terminal (leaves the alternate screen, restores cooked mode, stops reading input) and takes it back afterwards. passh never reads keystrokes while a pinentry may be active, so passphrase keystrokes can't leak into the search box or trigger actions.
- **Fresh unlock:** when a key's policy has `fresh_unlock = true`, a new interactive session from that key flushes the agent cache before its first decrypt (§3.3).
- **Failed-unlock backoff:** passh counts gpg calls that fail with a bad-passphrase error, across all sessions, in its state directory. After 3 failures within 15 minutes, unlock is refused for an exponentially growing delay (1, 2, 4 … up to 60 minutes). Every failure is logged with the key name.
- The unlocked key is cached by **gpg-agent** with these TTLs:

| Setting | Default | Config key |
|---|---|---|
| Idle TTL (since last use) | 5 min | `session.idle_ttl` |
| Max TTL (since unlock) | 15 min | `session.max_ttl` |

**`gpg-agent.conf` check.** `passh init` writes the file, and passh checks it on **every start**, refusing to decrypt if it fails. Because the `vault` user can rewrite this file, the check is not a defence against that user (§9). The file is checked against an allowlist of directives:

- `default-cache-ttl` and `max-cache-ttl` no higher than the configured TTLs. A missing line means gpg's defaults (600 s / 7200 s), which fails the check;
- `pinentry-program` set to a root-owned system pinentry;
- `no-allow-loopback-pinentry` and `no-allow-external-cache` present. Loopback is **allowed by default** in gpg-agent, so the absence of `allow-loopback-pinentry` proves nothing;
- `allow-preset-passphrase`, or any directive not on the allowlist, fails.

If the file changed since the agent started, passh runs `gpg-connect-agent reloadagent /bye` before use.

### 5.2 Lock and signals

The agent cache is flushed (`gpg-connect-agent reloadagent /bye`), the in-memory tag index and any decrypted entry are wiped, and the TUI shows a lock screen when any of these happens:

- the user presses `L` in the TUI or runs `passh lock`;
- the TUI exits normally;
- SIGHUP, SIGTERM, SIGINT or SIGQUIT is received (SSH disconnect);
- the TUI has been idle for `session.idle_ttl`.

Locking also stops the print page server (§7.4).

Signals and crashes:

- SIGPIPE is ignored, so writes to a closed pipe fail with EPIPE and passh exits through normal cleanup. By default Go would exit immediately on fd 1 or 2.
- `GOTRACEBACK=none` is set at startup. A top-level recover wipes secrets before exiting.
- At start passh removes stale temporary directories left by a crashed run.
- Non-interactive commands don't lock on exit; they rely on an unlock made elsewhere.

Known limitation: gpg-agent is per Unix user, not per SSH session. A lock in one session locks all of them, which is intended. The TUI header shows the key name and the number of other live passh sessions, so an unexpected session is visible. If passh is killed with SIGKILL, it can't flush; the agent's own TTLs are the backstop.

### 5.3 Secret handling rules

| Rule | Detail |
|---|---|
| R1 | Never write plaintext to persistent disk. umask 077 at startup. Temporary files only in admin mode (`$EDITOR`, `export -o`), only on tmpfs (checked with `statfs`, not by path), mode 0600, in a 0700 directory, deleted on exit and on signal. Restricted modes create no plaintext temporary files |
| R2 | Core dumps disabled at startup (`setrlimit RLIMIT_CORE 0`), `prctl(PR_SET_DUMPABLE, 0)` set (not inherited across exec), `GOTRACEBACK=none` |
| R3 | Secrets held in `[]byte` buffers allocated outside the Go heap and locked with `mlock` (`awnumar/memguard`), zeroed after use. Bulk operations (reindex, export) stream one entry at a time to stay within `RLIMIT_MEMLOCK`; `doctor` checks the limit. Data that passes through Go strings (TUI rendering, JSON/CSV/PDF encoders) is a documented limitation; the swap requirement (§3.1) is the backstop |
| R4 | Passwords masked in the TUI by default, with a fixed-length mask that doesn't reveal the length. Revealed only on explicit action, and hidden again after 10 s |
| R5 | No secrets in logs, error messages or git commit messages. Commit messages contain only the action and the path |
| R6 | Clipboard: passh sends a clearing OSC 52 sequence after `clipboard.clear_after` (default 30 s). It **can't verify** what the clipboard holds, and the clear never happens if the session ends first. Both are documented limitations shown in `passh help copy` |
| R7 | Plaintext export, print and the print page require an explicit capability and confirmation (§7) |
| R8 | **Output sanitisation.** Everything passh writes for humans (TUI, stdout and stderr, in every mode, **including pipes**) is sanitised. C0 controls other than newline and tab, C1, DEL, escape sequences and Unicode format characters (bidi, zero-width) are shown as `\x1b`/`\u202e`-style escapes. The server can't tell whether a pipe ends at the client's terminal, so pipes are not exempt. `show --raw` writes exact bytes; it is refused when stdout is a terminal and needs the key's `batch`. Output from git and gpg is never forwarded; passh prints its own messages. Export and print data streams follow §7 instead. The print page HTML-escapes every value and applies the same escapes (§7.4) |
| R9 | **Password generation** uses `crypto/rand` with rejection sampling (no modulo bias). Default length 24, from a configurable alphabet. Generation fails rather than falling back to a weaker source. The same generator makes the 6-word passphrase offered at `init` (§8.2) |
| R10 | Plaintext is passed to `gpg --encrypt` via stdin, never as a command-line argument or environment variable |

### 5.4 Editing

- **Restricted modes:** editing uses a built-in form in the TUI (`bubbles/textarea` for notes, separate single-line fields for password, username, url and tags). No external editor is ever launched. `passh edit <path>` opens the same form.
- **Admin mode:** `passh --admin edit --editor <path>` uses `$EDITOR`, with the temporary file on tmpfs (R1). `$EDITOR` is split into words without a shell. Leak prevention, with each flag passed as a separate argument:
  - vim: `-n -u NONE -i NONE -c "set nobackup nowritebackup noundofile noswapfile"`;
  - neovim: `-n --clean -i NONE -c "set nobackup nowritebackup noundofile noswapfile"`;
  - nano: `--ignorercfiles --nohelp` (nano makes no backups unless asked);
  - any other editor: passh warns that it can't control backup or swap files and asks for confirmation.
- No pager is ever used. Long output is scrolled inside the TUI.

### 5.5 Subprocess rules

All external commands go through one `internal/exec` package.

**Fixed binaries, no shell:**

- Binaries are called by absolute path, configured once and checked by `doctor`, never resolved through `$PATH`:
  - restricted modes: `/usr/bin/gpg`, `/usr/bin/gpg-connect-agent`, `/usr/bin/git`;
  - admin mode adds `$EDITOR` and `/usr/bin/lp`.
- These start their own helpers, which are pinned below: gpg starts gpg-agent and the pinned pinentry; git starts `/bin/sh` and `/usr/bin/ssh` for push, through the fixed `GIT_SSH_COMMAND`. Tests check direct children plus these pins.
- No shell. `exec.Command` with an argument list only.
- `--` before every path argument, in addition to the path rules (§4.6).

**Clean environment, in every mode.** Subprocesses get only:

- `PATH=/usr/bin:/bin`;
- `HOME` and `GNUPGHOME`, taken from the passwd entry and config, never inherited;
- `GPG_TTY`, and `TERM` validated against `^[A-Za-z0-9._+-]{1,64}$`;
- `LANG=C.UTF-8`;
- `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_TERMINAL_PROMPT=0`, `GIT_LITERAL_PATHSPECS=1`;
- `GIT_SSH_COMMAND=/usr/bin/ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=<state>/known_hosts -i <push key>`. git runs this through `/bin/sh`, so passh builds it only from fixed, validated paths with no spaces or shell characters.

**git hardening.** Every call gets:

```
--no-pager -c core.hooksPath=/dev/null -c core.pager=cat -c core.fsmonitor=false
-c core.symlinks=false -c protocol.allow=never -c protocol.ssh.allow=always
-c transfer.fsckObjects=true -c submodule.recurse=false -c gc.auto=0
```

- **Repo `.git/config` allowlist**, checked at every start, not only by `doctor`. Allowed keys:
  - `core.repositoryformatversion`, `core.filemode`, `core.bare` (false), `core.logallrefupdates`;
  - `remote.<name>.url` and `remote.<name>.fetch`, `branch.<name>.remote` and `branch.<name>.merge`;
  - `commit.gpgsign`, and `user.signingkey` (must equal the pin);
  - `diff.gpg.binary` and `diff.gpg.textconv`, only with the exact values `pass git init` writes.

  Any other key, such as `gpg.program`, `core.sshCommand`, `core.editor`, `filter.*`, `include*`, `url.*.insteadOf`, `remote.*.uploadpack` or `diff.external`, is an integrity error, and passh runs no git command until an admin removes it. passh never runs git commands that use textconv or external diff.
- **Remote URLs:** only `ssh://…` or `user@host:path`, with no host or path starting with `-`. Checked before every push.
- **Commit ids** from users (e.g. `verify --accept`) must be full hex ids.

**gpg calls:**

- Every call gets `--no-options --homedir <GNUPGHOME> --batch --no-tty --status-fd 3`, plus `--pinentry-mode error` when there is no TTY. `--no-options` skips `gpg.conf`, so `encrypt-to`, `group`, `default-recipient` or key auto-retrieval there can't change behaviour.
- Output is parsed only from the machine-readable status lines on **fd 3**, a dedicated pipe. Never from human-readable stderr, and never from fd 1 or 2, where plaintext or stderr could forge `[GNUPG:]` lines. This avoids the class of bug behind pass's CVE-2018-12356.
- **Encrypt:** `--encrypt --trust-model always --no-encrypt-to`, with one `--recipient <full fpr>` per pinned recipient.
- **Decrypt:** requires `DECRYPTION_OKAY` and `END_DECRYPTION`, and no `DECRYPTION_FAILED` or `BADMDC`. A file that isn't encrypted (literal or signed-only data) is refused. `--max-output` caps the plaintext size (1 MiB per entry, 64 MiB for the index).
- **Verify:** see §4.5.

## 6. Interfaces

### 6.1 CLI

Running `passh` with no arguments opens the TUI.

| Command | Class | SSH, `read-only` key | SSH, `read-write` key | Admin |
|---|---|---|---|---|
| `passh` (TUI) | — | ✓ browse and read | ✓ | ✓ |
| `ls [folder]`, `find <query>` on paths | meta | ✓ | ✓ | ✓ |
| `ls --tag t`, `find` including tags, `tags` | read | ✓ | ✓ | ✓ |
| `show <path> [--field f] [--raw]` | read | ✓ | ✓ | ✓ |
| `copy <path> [--field f]` | read | ✓ | ✓ | ✓ |
| `add <path> [--force]`, `generate <path> [len] [--symbols] [--force]` | write | ✗ | ✓ | ✓ |
| `edit <path>` (built-in form) | write | ✗ | ✓ | ✓ |
| `mv <src> <dst>`, `rm <path>` | write | ✗ | ✓ | ✓ |
| `tag <path> --add a --remove b`, `reindex` | write | ✗ | ✓ | ✓ |
| `sync` (verify, then push to backup remotes) | write | ✗ | ✓ | ✓ |
| `log [path]`, `verify` (check only), `lock` | meta | ✓ | ✓ | ✓ |
| `export …`, `print …` to stdout | bulk | per `export` (§7) | per `export` (§7) | ✓ |
| `print --web [--tag t] [--folder f] [--fields …]`, TUI key `P` (interactive only) | bulk | only with `export = "plaintext"` | only with `export = "plaintext"` | ✓ |
| `doctor` | meta | summary only | summary only | ✓ full |
| `init <fpr>`, `init --adopt`, `restore`, `recipients set <fpr>…`, `key backup` | admin | ✗ | ✗ | ✓ |
| `config get <key>`, `config set <key> <value>`, `remote add <name> <ssh-url>`, `remote list`, `remote remove <name>` | admin | ✗ | ✗ | ✓ |
| `verify --accept <commit>`, `verify --discard` | admin | ✗ | ✗ | ✓ |
| `print --recovery-kit`, `export -o <file>`, `print --lp <printer>`, `edit --editor` | admin | ✗ | ✗ | ✓ |
| `print-web init`, `print-web ca` (print page CA, §7.4) | admin | ✗ | ✗ | ✓ |

Rules:

- **Non-interactive** (no PTY) `read`, `write` and decrypting `bulk` commands need the key's `batch = true`. `meta` commands don't.
- **Default deny.** Commands, subcommands and flags not in this table are rejected. Cobra's `completion` command and command-prefix matching are disabled. A test walks the cobra command tree and checks every command and flag against the table.
- TUI keys follow the same matrix: a read-only key doesn't see `e`, `a`, `t` or `d`.
- `add` and `generate` onto an existing path are refused without `--force`; the TUI asks for confirmation instead.
- `show` output is sanitised (R8); `--raw` is for piping exact bytes.

There is **no git pass-through**. Arbitrary git commands are run by an admin with plain `git`.

### 6.2 TUI

Built on Bubble Tea + Bubbles + Lip Gloss (charmbracelet).

```
┌ passh ── 🔓 unlocked · locks in 4:12 · ✔ verified · laptop +1 ───┐
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
│ Tab folders/tags · / search · L lock · ? help · q quit           │
└──────────────────────────────────────────────────────────────────┘
```

Requirements:

- **Two views**, switched with `Tab`:
  - *Folders*: a collapsible tree that mirrors the directories;
  - *Tags*: a list of tags with counts; selecting a tag lists its entries. Multiple tags can be selected (AND).
- `/` opens fuzzy search across path and tags (from the index). Usernames and URLs aren't indexed, so searching them would mean decrypting every entry.
- The detail pane decrypts only the selected entry, on selection (debounced 150 ms), and only when unlocked. When locked it shows the path only (tags come from the encrypted index).
- **Header:** lock state and countdown; integrity state (`✔ verified`, or a red `⚠ integrity` banner, §4.5); the current key's name; the number of other live sessions; a warning when the last push failed or is older than a day (§8.3); and `🖨 print page 4:12` while the print page is running (§7.4).
- `P` opens the print page dialog (§7.4) for keys allowed to use it.
- All rendered values are sanitised (R8). Gpg prompts use the terminal handoff (§5.1).
- Narrow terminals (under 80 columns, such as phones) use a single-pane mode: list → Enter → detail → Esc.
- Destructive actions (`rm`, overwrite) ask for confirmation.
- No mouse support required in v1.

### 6.3 Clipboard over SSH

- Primary: OSC 52 (`ESC ] 52 ; c ; <base64> BEL`). Client-side tmux and screen handle OSC 52 themselves (tmux needs `set-clipboard on`). passh wraps the sequence for tmux or screen only in admin mode, when `$TMUX` or `$STY` is set on the server.
- Clearing: after the timeout passh sends an OSC 52 with an empty payload, only if the session is still alive (R6 limitations). Non-interactive `copy` stays connected for `clipboard.clear_after`, then clears and exits.
- `passh doctor` sends a test string, then a clear, so the user can confirm their terminal supports both (iTerm2, kitty, WezTerm, Windows Terminal, Alacritty and tmux with `set-clipboard on` support setting; Termux needs the OSC 52 setting).
- Fallback: if OSC 52 is unsupported or disabled (`clipboard.osc52 = false`), `copy` fails with a hint (`show --field password | pbcopy`). It doesn't print the secret into the terminal scrollback.
- Client-side clipboard history (macOS Universal Clipboard, Android clipboard history, clipboard managers) may keep copies. The README tells users to exclude their terminal app from those tools.

### 6.4 Non-interactive commands over SSH

With `ForceCommand`, sshd ignores the command the client types and passes it in `SSH_ORIGINAL_COMMAND`. passh:

1. Resolves the key: reads `$SSH_USER_AUTH`, requires exactly one `publickey` line, computes its SHA256 fingerprint and loads that key's policy from `policy.toml` (§3.3). Unknown key, missing variable or a bad file → refused and logged.
2. If `SSH_ORIGINAL_COMMAND` is empty, starts the TUI (a PTY is required; otherwise it prints usage).
3. Otherwise splits the command with passh's own parser: words separated by spaces, with single or double quotes for grouping. Outside quotes, ``; | & $ ` < > ( ) { } [ ] * ? ~ # \ !`` are rejected, because the user probably expected shell behaviour; nothing ever runs a shell. Inside quotes, any character the path rules allow is accepted. Control characters are always rejected.
4. Accepts only the commands and flags allowed for this key by §6.1. The first word may be `passh` or omitted. **Global flags (`--admin` and anything that would change mode or policy) are never accepted from `SSH_ORIGINAL_COMMAND`.**
5. Logs to the systemd journal (native journal protocol, no extra binary): key name and fingerprint, command name and path, never values. Rejected commands are logged too.

Example from a client whose key has `batch = true`: `ssh vault@pi show work/github --field password | pbcopy`. This requires the key to be already unlocked by an interactive session (§5.1). Paths with shell characters need inner quotes, because the client's own shell strips the outer ones: `ssh vault@pi "show 'work/a&b'"`.

## 7. Export and print

### 7.1 Export

```
passh export --format <archive|json|csv|bitwarden-json> [--tag t] [--folder f]
             [--to <name> | --confirm-plaintext] [--spreadsheet-safe] [-o file]
```

| Format | Content | Encrypted | Use case |
|---|---|---|---|
| `archive` (default) | `tar.gz` of the whole repository **including `.git`**, entries, signatures, `.passh/` (with the wrapped key) and a manifest | Yes, entries stay GPG-encrypted | Backup, moving hosts. Imported like a clone: verified before use (§8.4) |
| `json` | Native passh schema (§7.3) | With `--to` | Scripting, migration |
| `csv` | `folder,name,username,password,url,tags,notes`, RFC 4180 quoting | With `--to` | Import into KeePassXC and others |
| `bitwarden-json` | Bitwarden unencrypted export schema | With `--to` | Migration to Vaultwarden/Bitwarden |

Rules:

- **Export data is never written to a terminal.** Redirect stdout and use `ssh` **without `-t`**: a PTY merges stderr into the stream and converts LF to CRLF, which corrupts files. No prompt is ever written to stdout.
- **Rights by the key's `export` value (§3.3):**
  - `none`: nothing;
  - `encrypted`: `archive`, and other formats with `--to`;
  - `plaintext`: also plaintext with `--confirm-plaintext`.
  - Admin mode can do everything.
- **`--to <name>`** encrypts to a recipient pinned in `pins.toml` (`[export.recipients]`, an age recipient or a GPG fingerprint; written in admin mode only). Arbitrary recipients are not accepted: otherwise a stolen SSH key could export to its own key, which is the same as plaintext. Example: `ssh vault@pi export --format bitwarden-json --to laptop > vault.json.age`.
- **Plaintext over SSH:** a key with `export = "plaintext"` plus `--confirm-plaintext`. Grant this only to a device you'd trust with the whole vault (§9).
- **Admin mode with `-o file`:** plaintext asks the user to type `EXPORT PLAINTEXT` on `/dev/tty`. The file is created 0600 on tmpfs (checked with `statfs`); other locations are refused unless `--allow-disk` is given.
- Every format except `archive` decrypts entries, so it needs an unlocked agent and, over a pipe, the key's `batch`.
- **CSV values are exact by default**, because the target is a password manager. `--spreadsheet-safe` prefixes `'` to cells starting with `= + - @`, tab or CR, to prevent formula injection when the file is opened in a spreadsheet. passh warns that this changes values, passwords included, so that file must not be imported into a password manager.
- Every export is logged (key, format, filters, never values).

### 7.2 Print

The purpose is a paper emergency sheet that survives loss of the server and its backups.

```
passh print [--tag t] [--folder f] [--fields password,username,url] [--format pdf|txt] [--confirm-plaintext]
passh --admin print --recovery-kit [--with-key]
```

- **The password sheet is plaintext output.** It follows the plaintext export rules (§7.1): a key with `export = "plaintext"` and `--confirm-plaintext`, or admin mode. Output goes to stdout only, never to a terminal, for printing on the client. If CUPS is configured on the server, `--lp <printer>` sends the job directly (admin mode only).
- `pdf`: generated in pure Go (`go-pdf/fpdf`, no cgo) with an embedded UTF-8 monospaced TTF (e.g. DejaVu Sans Mono), so non-Latin characters print correctly. A4/Letter, grouped by folder, monospaced passwords with ambiguous characters marked (`0/O`, `1/l/I`), a print date in the footer, and "CONFIDENTIAL" on each page.
- `txt`: a paginated, monospaced layout for `lp` or quick viewing.
- **`--recovery-kit`** is **admin mode only**. It prints the key fingerprint, the backup remote URL(s) and the restore steps (§8.4–8.5). **No passwords.**
  - `--with-key` adds `.passh/secret-key.asc.age` as text and as QR codes (several for large RSA keys). Scanning is the intended way back; typing it is a last resort. This second copy is for when the copy in the backup is damaged. It is still protected by the passphrase.
  - The kit says on the page: **the passphrase is not on this sheet**; store it separately (memorised, or in a different physical location).
- Clients should print and then delete the file; the README notes that PDFs left in Downloads are a leak.

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
      "otp": null,
      "fields": { "custom-key": "value" },
      "notes": "…"
    }
  ]
}
```

On import (future), every `path` goes through the path rules (§4.6) and every value through R8 before display.

### 7.4 Print page (web)

A one-shot HTTPS page with the password sheet. You open it in a browser on the LAN or VPN and print it, without saving a file anywhere.

**Starting**

- Started from the TUI with `P`, or with `passh print --web [--tag t] [--folder f] [--fields …]`.
- Only in an interactive session (a PTY), with the store unlocked and verified (§4.5).
- Rights: `print_web.enabled = true` in `policy.toml` (§3.3), plus a key with `export = "plaintext"`, or console or admin mode.
- The user types `PRINT` to confirm.
- passh then shows, with a countdown:
  - the URL for each bound address, and a QR code of it for phones;
  - the certificate fingerprint.

  `c` copies the URL to the client clipboard (OSC 52).
- One print page per host at a time. The server runs inside the passh process, not as a daemon.

**Network**

- Listens only on the addresses of `print_web.interfaces`, and only on **private** addresses: RFC 1918, `100.64.0.0/10` (Tailscale) and IPv6 ULA `fc00::/7`.
  - A public address is refused, so on a VPS only the VPN is used.
  - It never binds to `0.0.0.0` or `::`.
- Connections from outside `allow_from` are closed before TLS. By default that means the subnets of the bound addresses.
- The `Host` header must be one of the bound addresses or `hostnames`. This defeats DNS rebinding.
- HTTPS only, TLS 1.3. A LAN is not encrypted the way a VPN is, so plain HTTP is never offered.

**Certificate**

- **Local CA.** `passh --admin print-web init` creates it (ECDSA P-256).
  - Critical X.509 **name constraints** limit it to the configured private subnets and `hostnames`. Even a stolen CA key can't impersonate any other site.
  - Its key lives in `~/.config/passh/print-ca.key` (0600). `doctor` warns before the CA expires.
- **Installing it.** `passh --admin print-web ca` prints the CA certificate and its fingerprint. Install it on the devices you print from; the README has steps for macOS, Windows, iOS and Android.
- **Per-run certificate.** Each run issues a leaf certificate for the bound addresses and `hostnames`, valid for the TTL plus one minute. Its key is generated in memory and never written.
- **Without the CA installed,** the browser shows a warning and the TUI shows the leaf fingerprint to compare. Clicking through the warning on a LAN leaves you open to an active attacker on that LAN (§9).

**Token and lifetime**

- The URL is `https://<address>:<port>/p/<token>`, with a 128-bit random token (`crypto/rand`, base64url).
- **The page is served once.** The first `GET` with the right token consumes it, and the server stops after the response is written. Other methods get 405 without consuming the token.
- The server also stops at the first of:
  - `print_web.ttl`, default 5 min, maximum 15;
  - any lock (§5.2), including a lock from another session, detected by an agent probe every 5 s;
  - the TUI or command exiting, or the session ending;
  - `Esc` in the print dialog;
  - 5 requests to `/p/` with a wrong token, logged as possible scanning. Requests to other paths, such as `/favicon.ico`, get 404 and don't count.
- Link previews and browser prefetching can consume the token first. The user then sees "already used" and starts again. The README says not to paste the URL into chats.

**Page**

- Same content and layout as the PDF sheet (§7.2): grouped by folder, selected fields only, ambiguous characters marked, a print date and "CONFIDENTIAL". Print CSS for A4/Letter with page breaks between folders.
- No JavaScript and no external fonts or images. The user prints with Ctrl/Cmd+P.
- Entries are decrypted when the request arrives, one at a time, rendered, streamed and wiped. The R3 limitations apply.
- Every value goes through `html/template` escaping plus the R8 escapes, so entry content can't inject HTML.
- Response headers:
  ```
  Cache-Control: no-store
  Content-Security-Policy: default-src 'none'; style-src 'sha256-…'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
  Referrer-Policy: no-referrer
  X-Content-Type-Options: nosniff
  Cross-Origin-Opener-Policy: same-origin
  ```
  The CSP blocks scripts and every outgoing request. Even if escaping failed, the page couldn't send passwords anywhere.
- **Logging:** start (key, filters, addresses), the page load (client address), and the stop with its reason. Never values.
- **After printing,** close the tab. The browser may keep the page in memory and in session restore, and "Save as PDF" or the print spooler can leave files on the client. The README covers this.

## 8. Backup and recovery

### 8.1 What is backed up

| What | How | Frequency |
|---|---|---|
| Store: encrypted entries, signed history, pins, public key, wrapped secret key | Every change is a signed commit. After each commit passh pushes to `backup.remotes` (§8.3) | On change |
| Store snapshot | `passh export --format archive`, or restic on `~/.password-store` (systemd timer example in README, not built in) | Daily |
| Recovery kit (paper) | `passh --admin print --recovery-kit [--with-key]`, stored offline | Once, and on key change |

**Backup + passphrase are enough to restore.** This is a deliberate choice (ADR-8): it means anyone holding a backup can try to guess the passphrase offline. Section 8.2 makes that as expensive as practical.

### 8.2 Bundled secret key

- **`.passh/secret-key.asc.age`** holds the secret key in two layers:
  - inside: the output of `gpg --export-secret-keys --armor <fpr>`, which stays protected by the key's passphrase (OpenPGP S2K);
  - outside: age passphrase encryption (`filippo.io/age`, scrypt, work factor ≥ 2¹⁸, about 256 MiB of memory per guess).

  Both layers use **the same passphrase**. scrypt is memory-hard, so guessing on GPUs is far slower than against OpenPGP's S2K alone.
- **`.passh/pubkey.asc`** holds the public key. Restore checks its fingerprint against the one the user types.
- **Creation:** `init`, `init --adopt` and `passh --admin key backup` create both files. gpg asks for the passphrase through pinentry for the export. passh then asks for it twice on `/dev/tty` for the age layer, holds it in secure memory (R3), and wipes it. passh can't check that the two are the same; it says so.
- **Passphrase strength.** The security of every backup equals the strength of the passphrase:
  - `init` offers a generated 6-word passphrase (EFF large wordlist, `crypto/rand`, about 77 bits; R9);
  - for the age layer, a self-chosen passphrase shorter than 20 characters is refused;
  - the README explains the trade-off.
- **After changing the passphrase** (`gpg --passwd`), run `passh --admin key backup`. Old wrapped copies stay in git history and on the append-only remote, still protected by the **old** passphrase. Changing a weak or leaked passphrase therefore does not protect existing backups; generate a new key with `recipients set` instead. `doctor` reminds the user when `pubkey.asc` and the keyring disagree.

### 8.3 Backup remote

- **Setup:** `passh --admin remote add <name> <ssh-url>`:
  1. validates the URL (§5.5);
  2. creates the push key `~/.ssh/passh_backup` (ed25519) if it's missing, and prints its public key to register on the remote as a deploy key with write access;
  3. connects once, shows the remote's host key fingerprint for confirmation, and pins it in `<state>/known_hosts`;
  4. records the remote in `backup.remotes` with a signed commit.

  `remote list` shows each remote with its last push; `remote remove` drops one.
- **Push only.** passh never pulls or fetches from a backup remote. `sync` = verify (§4.5), then push. Remote content is read only by `restore`, on a fresh host.
- **When:** after each commit passh pushes synchronously with a 10 s timeout. The result goes to the state directory and appears in the TUI header and in `doctor` ("last push 3 days ago ⚠"). `sync` retries.
- **Append-only:** the remote rejects force-push and branch deletion (e.g. `receive.denyNonFastForwards = true`, `receive.denyDeletes = true` on a bare repo, or branch protection on a git host). This defends against a compromised **server** rewriting backups. It does not defend against a compromised **remote** (§9).
- **Access:**
  - the server's push key has write access to that one repository only;
  - the remote's host key is pinned in `<state>/known_hosts`;
  - the remote holds the wrapped secret key, so keep it private.
- **Optional:** a second machine mirrors the backup remote, pulling from the remote rather than from the Pi. A copy then exists that the Pi can't write to.

### 8.4 Restore

This is also an acceptance test.

1. Install the binary on a clean host and set up the `vault` user and sshd (§3).
2. Run `passh --admin restore <remote-url | archive> --fingerprint <fpr>`. The fingerprint comes from the recovery kit or your notes, never from the cloned repository. passh then:
   1. clones with `--no-checkout` and the hardened git settings (§5.5), or unpacks the archive the same way. For an ssh URL it first sets up access as `remote add` does (§8.3): it uses `~/.ssh/passh_backup` or creates it and prints the public key to register on the remote (read access is enough for the restore), and it confirms and pins the remote's host key;
   2. checks that `.passh/pubkey.asc` has the given fingerprint and imports it;
   3. checks that HEAD is signed by that key and that `.gpg-id` and `.gpg-id.sig` are valid (§4.4, §4.5). Any failure stops the restore and lists the problem;
   4. shows the tip commit date and the entry count for confirmation. A remote can serve an older, validly signed state (rollback, §9);
   5. asks for the passphrase, unwraps `.passh/secret-key.asc.age`, imports the key into gpg, and sets its ownertrust to ultimate so plain `pass` works too;
   6. checks out, writes `pins.toml`, `verified-head` and `gpg-agent.conf`, then runs `reindex`.
3. `passh show` works.

**From a folder backup** (§3.5): put `backup/` back in place, start the container with an empty `local/`, and run `passh --admin restore --in-place --fingerprint <fpr>`. It runs checks 2–6 on the existing `~/.password-store` instead of cloning. It also sets up remote access as in step 2.1, so register the printed push key on the remote again.

### 8.5 Emergency restore without passh

The store stays usable with standard tools:

```bash
git clone <backup-remote> ~/.password-store
age -d ~/.password-store/.passh/secret-key.asc.age | gpg --import   # passphrase for age, then for gpg
gpg --import-ownertrust <<< "<FPR>:6:"
pass show bank/revolut              # or: gpg -d ~/.password-store/bank/revolut.gpg
```

This path skips signature verification. The README says to prefer `passh restore` when the backup's integrity matters.

## 9. Threat model

| Threat | Mitigation | Residual risk |
|---|---|---|
| Stolen backup or disk image | Entries GPG-encrypted. The bundled key is wrapped in age scrypt and OpenPGP S2K. A generated 6-word passphrase is offered | **Offline passphrase guessing**: backup security = passphrase strength. Old wrapped keys in history keep old passphrases. Paths and index size leak metadata |
| Network attacker | Reachable only over VPN; SSH key auth; `sshd` on the VPN interface only | — |
| Lost or stolen client device | No secrets stored on clients. Per-key policy: phones read-only, no `batch`, no export, `fresh_unlock`. Revoke by removing the key from `authorized_keys` and `policy.toml` | While **any** device is unlocked, a stolen key with `batch` can read entries without the passphrase, and one with `export = "plaintext"` can dump everything |
| Online passphrase guessing with a stolen key | Failed-unlock backoff (§5.1); journal log with the key name | Slow guessing remains possible |
| Per-key rights bypass | Rights from sshd (`ExposeAuthInfo`) and root-owned `policy.toml`. Nothing in `SSH_ORIGINAL_COMMAND` changes mode or policy. Unknown keys refused | — |
| Shell escape from restricted mode | No external editor, pager or git pass-through; `SSH_ORIGINAL_COMMAND` allowlist; `restrict`; clean environment; restricted by default; `--admin` refused over SSH | Bugs in passh itself |
| `.gpg-id` replaced or nested `.gpg-id` added | Signed `.gpg-id`, pinned fingerprints, check before every encrypt; nested `.gpg-id` rejected | — |
| Forged or modified entries | Signed commits; HEAD must be signed; working tree must equal HEAD; push-only sync, so the server never takes input from remotes | Commits accepted manually with `verify --accept` |
| Malicious repository config (`.git/config` keys that run commands) | Strict allowlist checked at every start; hardening `-c` flags; commits signed by passh itself | — |
| Path traversal, symlinks, argument injection | Path validator (§4.6); `os.Root`; `core.symlinks=false`; `--` before paths; `GIT_LITERAL_PATHSPECS`; absolute binary paths; no shell | — |
| Malicious gpg output, crafted files or `gpg.conf` | Status on a dedicated fd 3; `--no-options`; decrypt requires `DECRYPTION_OKAY`; `--max-output` | gpg vulnerabilities |
| Terminal escape injection via entry content, commit messages or remote output | All human output sanitised, including pipes and stderr; bidi and zero-width characters escaped; git and gpg stderr never forwarded | `show --raw`, by explicit choice |
| Plaintext on disk (swap, editor files, exports) | Swap check at every start; mlock; tmpfs-only temp files (checked with `statfs`); editor flags; export refuses disk paths | Go runtime copies (R3) |
| Print page intercepted or abused | Off by default. Plaintext-export right and typed confirmation. Private addresses only, `allow_from`, `Host` check. TLS with a name-constrained local CA. Single-use 128-bit token. Stops after one load, 5 min or lock. CSP without scripts or outgoing requests; `no-store` | An active attacker on the LAN, if the CA isn't installed and the warning is clicked through. Copies kept by the client's browser, print spooler or "Save as PDF". Whoever loads the URL first gets the page |
| Shoulder surfing / screen sharing | Masked by default with a fixed-length mask; reveal times out | — |
| Clipboard persistence | Best-effort clear; documentation | Clipboard history on clients; no clear after disconnect |
| Compromised backup remote | The server never pulls from it. Restore verifies signatures against a fingerprint the user types, and shows the tip date and entry count | Can serve an older, validly signed state (rollback) or withhold data. Holds the wrapped key (offline guessing, above) |
| Compromised server rewriting backups | Append-only remote | — |
| Key compromise discovered later | `recipients set` re-encrypts and replaces the bundled key | Old ciphertexts stay in history and on the remote: **rotate every password** |
| Entry names reveal accounts | Accepted. Optional future: LUKS volume or pass-tomb for the store | Visible to anyone with file access; history keeps deleted names |
| **Server compromised (root or `vault` user)** | Short TTLs, dedicated user, root-owned binary, `policy.toml` and `authorized_keys`, `gpg-agent.conf` re-checked on every start | **Full compromise.** The attacker can replace `pinentry-program` or the agent config, wait for the next unlock and capture the passphrase, or read cached keys. This is accepted by model "A"; the start-up config check only catches the unsophisticated case |

## 10. Technical design

### 10.1 Stack

| Concern | Choice |
|---|---|
| Language | Go ≥ 1.24 (`os.Root`), `CGO_ENABLED=0` |
| CLI | `spf13/cobra` (completion command and prefix matching disabled) |
| TUI | `charmbracelet/bubbletea`, `bubbles`, `lipgloss` |
| Fuzzy search | `sahilm/fuzzy` |
| Command parsing (SSH) | Own minimal parser (§6.4). `google/shlex` is not used: it doesn't reject anything and treats `#` as a comment |
| Unicode | `golang.org/x/text/unicode/norm` (NFC) |
| Secure memory | `awnumar/memguard` |
| Crypto | `gpg` subprocess behind a `Crypto` interface (ADR-1); `filippo.io/age` for export recipients and the key wrap |
| Git | `git` subprocess with hardened flags; commits built with plumbing (§4.5, §5.5) |
| PDF / QR | `go-pdf/fpdf` with an embedded UTF-8 TTF, `skip2/go-qrcode` (also renders the print page URL in the terminal) |
| Print page | Standard library only: `net/http`, `crypto/tls`, `crypto/x509` (name constraints), `html/template` |
| Audit log | Native journal protocol (`coreos/go-systemd/journal`) |
| Config | TOML: `.passh/config.toml` in the repo; `~/.config/passh/pins.toml` and `/etc/passh/policy.toml` outside |
| Release | GoReleaser: `linux/arm64`, `linux/amd64`, `linux/arm/v7`. Checksums signed with a release key whose public key is pinned in the install script, which verifies before installing as root. Reproducible builds: pinned toolchain, `-trimpath -buildvcs=false -mod=readonly` |
| Supply chain | `govulncheck` in CI; dependencies pinned in `go.sum`; minimal dependency list reviewed per release |

### 10.2 Package layout

```
cmd/passh/            main, cobra commands, mode selection (§3.4)
internal/policy/      policy.toml, SSH_USER_AUTH, permission matrix (§3.3, §6.1)
internal/store/       pass layout: walk, read, write, move; store lock (§4.7)
internal/paths/       path validator, os.Root access (§4.6)
internal/entry/       parse/serialize entry format, preserve unknown fields
internal/crypto/      Crypto interface; gpg implementation; status-fd parser; agent control
internal/integrity/   .gpg-id signature + pins; commit verification; trust rule; verified-head
internal/keybackup/   age-wrapped secret key, pubkey.asc, passphrase generator (§8.2)
internal/tags/        encrypted index: load, update, reindex, staleness
internal/session/     lock state, timers, signal handling, pinentry TTY, terminal handoff, backoff
internal/secmem/      memguard wrappers, rlimit/prctl/umask setup
internal/exec/        the only place that starts processes (§5.5)
internal/sshcmd/      SSH_ORIGINAL_COMMAND parser and allowlist (§6.4)
internal/sanitize/    output sanitisation (R8)
internal/clipboard/   OSC 52 encoder, tmux/screen wrapping (admin), clearing
internal/gen/         password and passphrase generator (R9)
internal/editor/      built-in form; external editor launcher (admin)
internal/export/      csv, json, bitwarden-json, archive
internal/print/       pdf, txt, recovery kit
internal/printweb/    one-shot HTTPS print page, local CA, leaf certificates (§7.4)
internal/gitx/        plumbing commits (signed), push, log, config allowlist
internal/doctor/      host checks (§3, §5.1, §5.5)
internal/tui/         bubbletea models: tree, tags, detail, search, form, lockscreen
```

A lint rule (e.g. `depguard`) forbids importing `os/exec` outside `internal/exec`.

### 10.3 Key interfaces

```go
type Crypto interface {
    Decrypt(ctx context.Context, path paths.Safe) (*secmem.Buffer, error)
    Encrypt(ctx context.Context, plaintext *secmem.Buffer) ([]byte, error) // recipients from verified pins only
    SignDetached(ctx context.Context, data []byte) ([]byte, error)
    VerifyDetached(ctx context.Context, data, sig []byte) (Signer, error)  // Signer = primary-key fingerprint + status
    Unlock(ctx context.Context) error             // primes decryption and signing keys (§5.1)
    IsUnlocked(ctx context.Context) (bool, error) // probe agent (KEYINFO), never prompts
    Lock(ctx context.Context) error               // flush agent cache
}

type Store interface {
    List(prefix paths.Safe) ([]paths.Safe, error)
    Read(path paths.Safe) (*entry.Entry, error)
    Write(path paths.Safe, e *entry.Entry) error // lock → verify → pins → encrypt → write → index → signed commit
    Move(src, dst paths.Safe) error
    Remove(path paths.Safe) error
}

type Policy interface {
    Key() KeyInfo                         // name, fingerprint, access, batch, export, fresh_unlock
    Allow(cmd Command, interactive bool) error
}
```

`paths.Safe` can only be constructed by the validator, so unvalidated paths can't reach the store or subprocesses.

## 11. Architecture decisions

**ADR-1: Use the system `gpg` rather than native Go OpenPGP**
- *Decision:* shell out to `gpg` for decrypt, encrypt, sign and verify.
- *Why:* compatibility with existing pass stores and keys; gpg-agent provides passphrase caching, pinentry and future YubiKey support; no need to parse GnuPG's private key storage.
- *Cost:* runtime dependency on `gnupg`; the cache is per user, not per process (§5.2); the agent config is writable by the `vault` user (§9); output parsing must be strict (§5.5).
- *Alternative kept open:* an **age** backend (`filippo.io/age`, as gopass does) through the `Crypto` interface. It would give a zero-dependency binary, an in-process per-session cache and no agent-config attack surface, but would break pass compatibility. age is already a dependency for exports and the key wrap.

**ADR-2: Folders stay primary; tags are additive, with an encrypted index** (§4.3)

**ADR-3: Decrypt on the server (model A)**: zero client setup, in exchange for the risk in §9.

**ADR-4: Restricted mode by default.** No external editor, pager or git pass-through, because each is a known shell-escape vector (§5.4, §6.1). Admin mode is explicit and refused over SSH (§3.4).

**ADR-5: Signed history.** Integrity comes from signed commits and a signed `.gpg-id`, because GPG encryption alone doesn't authenticate writers. A signed tip vouches for its ancestors, so adoption and acceptance are signed commits that travel with the backup (§4.4, §4.5).

**ADR-6: Per-key rights from sshd, not from `authorized_keys` `command=`.** `ForceCommand` overrides `command=`, so per-key options there never take effect. `ExposeAuthInfo` tells passh which key authenticated; a root-owned `policy.toml` maps it to rights (§3.3). `ForceCommand` stays as the single choke point.

**ADR-7: Push-only backups.** Remotes are for backup only, so the server never fetches from them. This removes the main path for untrusted git content. Remote content is read only by `restore`, which verifies before checkout (§8.3, §8.4).

**ADR-8: Secret key bundled in the backup.** Owner's decision: backup + passphrase must be enough to restore anywhere. Trade-off: anyone with a backup can guess the passphrase offline. Mitigations: age scrypt outer layer, a generated 6-word passphrase offered at `init`, a 20-character minimum for the age layer, and documentation (§8.2, §9).

**ADR-9: One-shot print page over HTTPS on the LAN and VPN.** Owner's decision: print from any browser without saving a file. Trade-off: the plaintext sheet crosses the network. So the page is off by default, needs the plaintext-export right, binds only to private addresses, uses TLS with a name-constrained local CA, is served once behind a random token, and stops after 5 minutes or on lock (§7.4, §9).

## 12. Milestones

| M | Scope | Done when |
|---|---|---|
| M1 Core + safety base | `exec`, `paths`, `sanitize`, `secmem`, `gen`, `gitx` (plumbing commits, config allowlist), store lock; init/adopt, ls, show, add, generate, mv, rm; pins and `.gpg-id.sig`; doctor | Round-trips with `pass`; security tests 1, 2, 6–9, 11, 19 (§13.2) pass |
| M2 Session + SSH | `policy` and `policy.toml`, `ExposeAuthInfo`, agent config checks, pinentry TTY and terminal handoff, fresh unlock, backoff, lock on exit/signal, restricted/admin modes, `SSH_ORIGINAL_COMMAND` parser, OSC 52 copy | Copy works from macOS iTerm2 and Android Termux; security tests 12–16, 18, 20 pass |
| M3 Integrity | commit verification, trust rule, `verified-head`, banner, `verify --accept/--discard`, push-only `sync` | Tampered commit and dirty tree are detected and block writes; security tests 3–5 pass |
| M4 Tags | tag commands, encrypted index, reindex, staleness | `ls --tag` works without decrypting every entry |
| M5 TUI | folder/tag views, search, detail, built-in edit form, narrow mode, lock screen, header | Usable on 80×24 and on a phone; security test 10 passes |
| M6 Export | archive, json, csv, bitwarden-json, pinned recipients, rights and confirmation rules | Bitwarden export imports into Vaultwarden; security test 17 passes |
| M7 Backup + print | key backup, `restore`, pdf/txt sheets, print page and its CA, recovery kit | Functional tests 7–9 and security tests 21–24 pass |
| M8 Release | GoReleaser, signed install script, sshd/authorized_keys/policy.toml templates, Docker image and compose example, backup-timer example, README | One-line install on a fresh Pi; `doctor` green; functional test 10 and security test 25 pass |
| M9 External review | Hand the spec and code to an independent reviewer | Findings triaged before v1.0 |

## 13. Acceptance criteria (v1)

### 13.1 Functional

1. A fresh Raspberry Pi gets the binary with one command; `passh doctor` is green.
2. An existing `~/.password-store` is adopted with `init --adopt`, after which `pass` still works on it.
3. `ssh vault@pi` opens the TUI; one passphrase prompt per session, including the first write.
4. After `session.idle_ttl` idle, or on disconnect, the next decrypt prompts again.
5. Copy from the TUI lands in the client clipboard and a clear is sent after 30 s.
6. Export to Bitwarden JSON imports into Vaultwarden; CSV imports into KeePassXC with passwords starting with `= + - @` intact.
7. `passh restore` with only the backup remote and the passphrase works on a new host, for a store created by passh, an adopted store, and a store after `recipients set`.
8. The emergency restore without passh (§8.5) works with only `git`, `age`, `gpg` and `pass`.
9. The print page, started from the TUI, opens without a certificate warning on a laptop with the CA installed, over both the LAN and the VPN. It prints, and the server stops after the load.
10. The Docker deployment (§3.5) passes `doctor`. On a new host, a copy of `backup/` alone, plus the passphrase, is enough to restore with `restore --in-place`.

### 13.2 Security tests (automated where possible)

1. Path rules: `..`, absolute paths, a leading `-` or `.` in any segment, control and Cf characters, and symlinks are rejected. A symlink committed to git checks out as a plain file.
2. A modified `.gpg-id`, one with an invalid signature, or a nested `work/.gpg-id` blocks every write.
3. An unsigned HEAD is detected at start and on restore, and blocks writes. After `verify --accept`, a fresh restore of that history succeeds.
4. An uncommitted change to an entry, or an untracked file, is detected and blocks writes.
5. Rewritten history (`verified-head` not an ancestor of HEAD) is detected.
6. A `.git/config` with `gpg.program`, `core.sshCommand`, `filter.*`, `include.path` or an unknown `diff.*` key is refused at start, with nothing executed.
7. Forged `[GNUPG:]` lines in entry plaintext or gpg stderr have no effect. An unencrypted or signed-only "entry" is refused.
8. A `gpg.conf` with `encrypt-to <other key>` adds no recipient (ciphertext checked with `gpg --list-only`).
9. No plaintext file exists on persistent disk after any command (filesystem diff test, run with swap disabled).
10. Escape sequences (including OSC 52) and bidi characters in entry content, commit messages and paths render inert in the TUI, in `show` on a terminal, in `show` over a pipe, in `log` and in error output.
11. Generated passwords pass a chi-square uniformity test over 10⁶ samples.
12. End-to-end with a real sshd (container): the template passes `sshd -t`. The phone key gets read-only rights and an unknown key is refused. `SSH_ORIGINAL_COMMAND` values with unquoted ``; | & $ ` > <``, unknown commands or flags, or `--admin` are rejected without running anything.
13. A walk of the cobra tree finds every command and flag in the §6.1 matrix. With a read-only key every write is rejected; without `batch` every non-interactive read is rejected.
14. In SSH mode passh directly starts only `gpg`, `gpg-connect-agent` and `git` (test hooks on `internal/exec`), and git starts `ssh` only through the pinned `GIT_SSH_COMMAND`.
15. A `gpg-agent.conf` with longer TTLs, missing TTL lines, no `no-allow-loopback-pinentry` or a non-system `pinentry-program` makes passh refuse to decrypt.
16. A non-interactive command with a locked key fails fast, with no pinentry started anywhere, including for signing.
17. Export: output to a terminal is refused. Plaintext without the key's capability or without `--confirm-plaintext` is refused. `--to` with a recipient not pinned is refused. The exported file contains no prompt text.
18. `--admin` is refused when any `SSH_*` variable is set or stdin is not a TTY.
19. Two concurrent writers both land their commits and the index stays consistent. On SIGPIPE (`show … | head -c1`), SIGHUP and SIGTERM, secrets are wiped, temporary directories removed, and the agent flushed where §5.2 says so.
20. Three failed unlocks trigger the backoff, which applies across sessions and is logged.
21. The print page is refused for a key without `export = "plaintext"`, without a PTY, when `print_web.enabled = false`, and on an interface that has only public addresses.
22. The print page is served once over TLS. A second load, a wrong `Host` header and a client outside `allow_from` all fail; 5 wrong tokens stop the server. The server stops at the TTL, on lock (including a lock from another session) and on SIGHUP.
23. Entry content with `<script>`, `<img src=…>` or `</style>` renders as text on the print page. The response headers match §7.4, and a headless browser loading the page makes no outgoing request.
24. Chrome, Firefox and Safari reject a leaf certificate from the print page CA for a name outside its constraints.
25. In the container, passh refuses to decrypt when the cgroup allows swap and the host has disk swap. The container runs with a read-only root filesystem and only the capabilities listed in §3.5, and no private key without passphrase protection is stored under `backup/`.

## 14. Open questions

1. TOTP (`otp:` field + `passh otp <path>`) in v1 or v1.1?
2. Should the tag index be optional for users who prefer zero extra files in the store?
3. Should a key's policy also limit it to a subset of folders or tags (e.g. `folders = ["work"]` in `policy.toml`)? The mechanism now exists; is it v1?
4. Is a future age backend worth the loss of pass compatibility, given that it removes the agent-config attack surface?
5. Should signing use a separate signing subkey on a hardware token (YubiKey), so that a compromised server can't sign without a physical touch?

Resolved in v0.3: per-key rights mechanism (ADR-6), sync model (ADR-7), admin access path (§3.4), key backup model (ADR-8), handling of expired signing keys (§4.5), CSV default (§7.1), path strictness (§4.6), revocation after key change (§4.4).
