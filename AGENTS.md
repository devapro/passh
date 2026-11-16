# AGENTS.md — passh

Read this first. **Rules: see [docs/go-guidelines.md](docs/go-guidelines.md)** (rule IDs such as `INV-8`, `ERR-4`, `TEST-1`).

## What passh is

passh is a password manager for one person: a single static Go binary (CLI and TUI) whose whole vault is one text file holding two age-encrypted blocks, a passphrase-wrapped vault key and the JSON data.
The file can be copied anywhere and checked; it opens with the passphrase, a paper recovery key, or the stock `age` tool.
It runs locally or over plain `ssh` (OSC 52 clipboard, an agent started by `passh unlock`), and changes nothing on the system beyond its own files.

## Source of truth

- `spec.md` is the specification and wins over code, comments and this file. `spec.ru.md` is its Russian translation. `EXAMPLES.md` shows the intended UX.
- If code and spec disagree, the spec wins. If the spec itself needs to change, **report it** (what, why, which section); never change the spec or drift from it silently. Spec changes the owner approved are logged in `IMPLEMENTATION.md`.
- `IMPLEMENTATION.md`: implementation notes, package status, spec changes made so far. `archive/`: old designs (v0.4, v0.5), historical only.
- Code cites the spec: `§4.6` is a section of `spec.md`, `S1`–`S9` are the safety rules of §5.5.

## Layout

```
cmd/passh/            main: S7 hardening, version, cli.Main; black-box CLI tests (build and run the binary)
internal/cli/         cobra commands (§6.1), doctor, opening the vault, output and exit statuses
internal/tui/         Bubble Tea TUI (§6.2): tree, tags, search, detail, form, lock screen, print dialog
internal/session/     TUI lock state, idle timer, signals (§5.2)
internal/vault/       open (strict checks §4.5), save (lock, change check, atomic write, read-back §4.6), backups, rollback record
internal/vaultfile/   the container: lenient parse, canonical write, structure check for verify (§4.1, §4.5, §4.8)
internal/keys/        vault key, scrypt wrapping (2^18), data encryption, recovery key, passphrase strength
internal/model/       data schema (§4.2): entries, fields, tombstones, unknown-field preservation
internal/entrytext/   pass-style text form for show and edit --editor (§4.3)
internal/paths/       entry path validator; paths.Path is only built by it (§4.4)
internal/config/      config file (strict TOML, §3.3), passh's folders (§3.2), agent folder checks
internal/agent/       agent process, socket, peer uid check, TTLs; client and KeySource (§5.3)
internal/tty/         prompts on /dev/tty: passphrases (echo off), lines, yes/no, typed phrases
internal/exec/        the only place that starts processes (S8)
internal/sanitize/    terminal output escaping (S4)
internal/harden/      core dumps off (S7)
internal/gen/         password generator: crypto/rand, rejection sampling (S3)
internal/clipboard/   OSC 52 and clipboard command, timed clearing (§6.3, S6)
internal/editor/      built-in entry form; $EDITOR on tmpfs with leak-safe flags (§5.6, S1)
internal/importpass/  pass store reader: os.Root walk, gpg --decrypt via internal/exec (§4.9)
internal/export/      json, csv, bitwarden-json (§7.1, §7.3)
internal/print/       sheet model, text sheet, recovery key sheet (§7.2, §5.4)
internal/printweb/    one-shot HTTPS print page, self-signed certificate (§7.4)
test/acceptance/      black-box acceptance tests for spec §13 (builds the binary)
```

Not yet: `internal/merge` and TOTP (v1.1). `doctor` lives in `internal/cli/doctor.go`, not in its own package.

## Toolchain

Go lives in `~/.local/go`; shell state doesn't persist, so start every command with:

```bash
export PATH=$HOME/.local/go/bin:$PATH
```

The installed toolchain is Go 1.27.x; `go.mod` says `go 1.26.0` (the floor set by `filippo.io/age` and `golang.org/x/*`), so use nothing newer than Go 1.26. Module path: `github.com/devapro/passh`.

| What | Command | Time |
|---|---|---|
| Build | `go build ./...` | seconds |
| Vet | `go vet ./...` and `GOOS=darwin GOARCH=arm64 go vet ./...` | seconds |
| Format | `gofmt -l cmd internal test` must print nothing (`gofmt -w <files>` to fix) | seconds |
| Unit tests | `go test -count=1 ./internal/...` (or `./internal/<pkg>/...` for one package) | ~15 s |
| Short unit tests | `go test -short ./internal/...` (skips the real-scrypt and stock-age tests) | ~12 s |
| CLI tests | `go test -count=1 ./cmd/...` (builds the binary, runs it in isolated envs and PTYs) | ~15 s |
| Acceptance tests | `go test -count=1 ./test/acceptance/...` (spec §13; skips what the machine can't test) | ~4–5 min |
| Race detector | `go test -race -count=1 ./internal/...` | ~1 min |
| Order check | `go test -count=1 -shuffle=on ./internal/... ./cmd/...` | ~30 s |

Cross-builds for the five release targets (spec §2 G1), static and trimmed like the release:

```bash
for t in linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64; do
  GOOS=${t%/*} GOARCH=${t#*/} GOARM=7 CGO_ENABLED=0 go build -trimpath -o /dev/null ./cmd/passh || echo "FAIL $t"
done
```

`GOARM=7` only affects `linux/arm` (Raspberry Pi, 32-bit OS). Releases are built by GoReleaser from a version tag (`.goreleaser.yaml`, `.github/workflows/release.yml`); don't run or change them unless asked.

### Tools in `.tools/bin`

`.tools/` is gitignored. Install tools there, pinned, never system-wide:

```bash
GOBIN=$PWD/.tools/bin go install filippo.io/age/cmd/...@v1.3.2                                  # stock age, age-keygen: recovery tests
GOBIN=$PWD/.tools/bin go install honnef.co/go/tools/cmd/staticcheck@v0.8.2                       # 2026.2.2
GOBIN=$PWD/.tools/bin go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
GOBIN=$PWD/.tools/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
```

```bash
.tools/bin/staticcheck -checks 'inherit,ST1000,ST1020,ST1021,ST1022' ./...
.tools/bin/govulncheck ./...            # -show verbose for module-level findings
.tools/bin/golangci-lint run ./...      # config: .golangci.yml
```

Tests that need the stock `age` CLI look for `.tools/bin/age` and skip without it. gpg (for `import pass` tests), strace, `/dev/shm`, a private LAN address and Chromium are optional the same way.

## Test isolation (mandatory)

Tests and manual runs never touch the real user's files:

- Set `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, `XDG_RUNTIME_DIR`, `TMPDIR`, `PASSH_CONFIG`, `PASSWORD_STORE_DIR` and `GNUPGHOME` to temporary folders: `t.TempDir()` in tests (reuse the package's `isolate`/`TestMain`/harness helper), the scratchpad for manual runs.
- Never use the real `~/.gnupg`, `~/.password-store`, `~/.config/passh` or `~/.local/state/passh`; never start an agent for a real vault.
- Tests that need a terminal use `github.com/creack/pty`, never the real `/dev/tty`. Tests that change env or package hooks don't call `t.Parallel()`.
- Don't install anything outside the project folder.
- The scrypt work factor is lowered only in tests, through the unexported package variable (`keys.scryptWorkFactor`) set from a `_test.go` file; production always uses 2^18.

The "fake HOME" check in [docs/go-guidelines.md § Checks](docs/go-guidelines.md#checks) proves a run stayed isolated.

## Safety invariants (short form)

Full rules with checks: [docs/go-guidelines.md §1](docs/go-guidelines.md#1-project-invariants-inv).

- **S1** No plaintext on persistent disk; `edit --editor` uses a 0600 file on tmpfs, deleted afterwards (INV-2).
- **S2** Secrets never in arguments or environment; passphrases come from `/dev/tty` (INV-3).
- **S3** `crypto/rand` with rejection sampling; no `math/rand` outside tests (INV-4).
- **S4** Everything printed to a terminal goes through `internal/sanitize` (INV-5).
- **S5/S6** Fixed-length masks, reveal timeout, clipboard clearing (INV-6). **S7** Core dumps off (INV-7).
- **S8** Every process starts through `internal/exec`: no shell, argument lists, `--` before paths (INV-8).
- **S9** The vault's `age1…` recipient is never written or printed (INV-9).
- scrypt stays at 2^18 in production (INV-10); only `internal/vault` writes the vault (INV-11); files 0600, folders 0700 (FILE-1); stdout carries data only, and every status line, confirmation, warning and hint goes to stderr (OUT-1).

## Conventions

- **No commits or pushes unless asked.** When asked: English commit messages, a short imperative subject, a body that says what and why, ending with the trailer used in this repo:

  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  ```

- **Dependencies are frozen.** Don't run `go get`, `go mod tidy`, `go mod edit` or `-mod=mod`, and don't edit `go.mod`/`go.sum` without the owner's approval. If you need a module, stop and say so in your report (TOOL-5). `git diff --exit-code go.mod go.sum` must pass.
- Several agents may work in parallel: edit only what you were asked to, test the packages you touched (`go test ./internal/<pkg>/...`), read anything.
- Before handing work back: `gofmt`, `go vet`, the tests of touched packages, and staticcheck/golangci-lint on them; report any rule you deliberately didn't follow (`// exception RULE-ID: reason` in code).
- Errors: lowercase, wrapped with `%w` and context, matched with `errors.Is/As`, spec wording where the spec gives a message (ERR-*).
- Comments cite the spec section or safety rule they implement.
- TUI: `Update` and `View` never block or do I/O; vault, agent, clipboard and print page work runs in a `tea.Cmd` that returns a message, and `View` changes no state (CONC-9).

## Adding a command

1. Find it in spec §6.1 (and the section it points to). A command the spec doesn't list is a spec change: report it first.
2. Write `func (a *app) cmdFoo() *cobra.Command` in the matching file of `internal/cli` (or a new `foocmd.go`), and add it to `root.AddCommand(…)` in `internal/cli/cli.go`.
3. Use the existing pieces: `exactArgs`/`rangeArgs`/`noArgs` (usage errors, exit 2); `paths.Parse` for entry paths; `a.unlock(cmd.Context())` then `defer v.Close()` for the vault; `internal/tty` for prompts; `writeAll(a.stdout, …)` for data only; confirmations and status ("Saved x.") on stderr, through `a.statusf`/`a.notef`/`a.warnf` (they write via `a.say`) with values passed through `line`/`displayPath` (sanitized); return errors and let `exitStatus` print them.
4. Help text (`Use`, `Short`, `Long`, flags) uses the spec's names and defaults.
5. Tests: a unit test in `internal/cli` where it helps, a black-box test in `cmd/passh` (isolated env from the harness), and an acceptance test in `test/acceptance` if a §13 criterion covers it. Update `README.md`/`EXAMPLES.md` only if asked.

## Adding a package

1. Check spec §10.2 first: most concerns already have a package. A new one needs a reason (cohesion, a dependency to keep out of the core).
2. Put it under `internal/<name>/` with a short lowercase name, one `// Package <name> …` comment citing the spec sections it implements, and doc comments on everything exported.
3. Keep dependencies pointing down (API-2): no imports of `internal/cli` or `internal/tui`; leaves stay leaves. Processes only via `internal/exec`; output escaping via `internal/sanitize`.
4. Add a line for it to the layout above, and to the package table in `IMPLEMENTATION.md`.
5. Give it tests that follow the isolation rules; fuzz any parser of untrusted input (TEST-12).

## Rules

All engineering rules, with how to check each one: **[docs/go-guidelines.md](docs/go-guidelines.md)**.
