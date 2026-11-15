# passh — implementation notes

Working notes for building passh from `spec.md` (v0.6). `spec.md` is the source of truth; `EXAMPLES.md` shows the intended UX. If code and spec disagree, the spec wins, and a needed spec change is reported, not made silently.

## Toolchain

- Go 1.27.4 lives in `~/.local/go`. Every shell command starts with `export PATH=$HOME/.local/go/bin:$PATH` (shell state doesn't persist between commands).
- Module path: `github.com/devapro/passh`. `go.mod` says `go 1.26.0` because `filippo.io/age` v1.3.2 and `golang.org/x/*` need it (spec §10.1 says ≥ 1.24; the real floor is 1.26).
- All dependencies are already in `go.mod`/`go.sum` (marked `// indirect` until imported): `filippo.io/age`, `spf13/cobra`, `BurntSushi/toml`, `sahilm/fuzzy`, `golang.org/x/{term,sys,text,crypto}`, `trustelem/zxcvbn`, `go-pdf/fpdf`, `skip2/go-qrcode`, `charm.land/bubbletea/v2`, `charm.land/bubbles/v2`, `charm.land/lipgloss/v2`, and `creack/pty` (tests only).
- **Do not run `go get`, `go mod tidy` or edit `go.mod`.** Several agents work in parallel. If you need another module, stop and say so in your report.
- The standard `age` CLI (v1.3.2) for tests: `.tools/bin/age`, `.tools/bin/age-keygen`.

## Rules for code

- Edit only the directories you were assigned. Read anything.
- `gofmt` everything; `go vet` must be clean for your packages.
- Test your own packages: `go test ./internal/<pkg>/...` (not `./...`: other packages may be mid-work).
- Production code never offers a lighter scrypt work factor (spec §4.1). Tests may lower it only through an unexported package variable set from a `_test.go` file of the same package, or an `export_test.go`.
- Secrets never go into process arguments or environment variables (S2). Passphrases are read from `/dev/tty`. Tests that need a terminal use `github.com/creack/pty`.
- Every process is started through `internal/exec` (S8).
- Errors are values with clear messages that match the spec's wording where the spec gives one.

## Test isolation (mandatory)

Tests and manual runs must never touch the real user's files:

- set `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, `XDG_RUNTIME_DIR`, `TMPDIR`, `PASSH_CONFIG`, `PASSWORD_STORE_DIR` and `GNUPGHOME` to temporary directories (`t.TempDir()`, or the scratchpad for manual runs);
- never use the real `~/.gnupg`, `~/.password-store`, `~/.config/passh` or `~/.local/state/passh`;
- don't install anything outside the project folder.

## Package plan (spec §10.2)

| Phase | Packages / work | Status |
|---|---|---|
| 1 | `paths`, `model`, `entrytext` | done |
| 1 | `keys`, `vaultfile` | done |
| 1 | `config`, `sanitize`, `gen`, `exec`, `tty`, `harden` | done |
| 2 | `vault` (open, save, backups, rollback record) | done; independent review found 9 issues, all fixed with regression tests |
| 2 | `agent` (process, socket, peer check, TTLs, client); agent folder in `config` | done (key-block hash check added after review) |
| 2 | `clipboard`, `editor` (form, external editor; own input widgets, not bubbles textinput) | done |
| 2 | `importpass`, `export` | done |
| 2 | `print`, `printweb` | done |
| 3 | `cmd/passh` + `internal/cli`: all v1 commands, `doctor`, TUI entry | done |
| 3 | black-box acceptance tests (§13) in `test/acceptance/` | done: all locally testable criteria pass; 2 bugs found and fixed |
| 4 | M2: `tui`, `session` (incl. print page dialog) | done |
| 5 | wire `copy`, `edit`, `print`, `recovery-key print`, TUI into the CLI | done |
| 6 | M6: `.goreleaser.yaml`, `README.md`, `--version` | done (GoReleaser itself not run) |
| v1.1 | TOTP, `merge` | — |

## Spec changes made during implementation

- §5.3, §3.2, §13.2: the agent socket lives in `~/.local/state/passh/agent/` (fallback `/tmp/passh-<uid>/` for long paths), not `$XDG_RUNTIME_DIR`, which systemd removes when the last session ends (owner decision).
- §8: the `awk` extraction stops at the END line, so text after the vault no longer breaks the stock `age` tool; the paper-key steps say which commands to run.
- §5.3: the agent's idle TTL counts key requests only.
