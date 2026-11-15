# passh Go guidelines

The engineering rules for passh's Go code. A reviewer audits the code against them; whoever changes the code follows them. They are written to be checked: each rule says what to do, why, how to check it, and where it comes from.

- **MUST**: a violation is a defect. Fix it, or keep the code and put a comment with the rule ID and the reason next to it: `// exception ERR-10: …` (for a linter finding: `//nolint:<linter> // <reason>`). Find them with `grep -rn 'exception [A-Z]*-[0-9]' --include='*.go' .`.
- **SHOULD**: the default. Deviate when there is a reason, and say it in a comment or in the review.
- `spec.md` wins over these rules, and these rules win over personal style. Where a rule cites §x.y or S1–S9, it means `spec.md`.
- Commands assume the repository root and `export PATH=$HOME/.local/go/bin:$PATH`. Tools live in `.tools/bin` (see [AGENTS.md](../AGENTS.md)). `grep` checks print nothing when the code complies, unless the rule says what to look for in the output.

Sources are cited per rule; abbreviations: **CRC** = [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments), **GSG** = [Google Go Style Guide](https://google.github.io/styleguide/go/) ([decisions](https://google.github.io/styleguide/go/decisions), [best practices](https://google.github.io/styleguide/go/best-practices)), **Uber** = [Uber Go Style Guide](https://github.com/uber-go/guide/blob/master/style.md), **EG** = [Effective Go](https://go.dev/doc/effective_go). The full list is at the end.

Contents: [1 Project invariants](#1-project-invariants-inv) · [2 Security and secrets](#2-security-and-secrets-sec) · [3 Errors](#3-errors-err) · [4 Context and concurrency](#4-context-and-concurrency-conc) · [5 Files and I/O](#5-files-and-io-file) · [6 Output and UX](#6-output-and-ux-out) · [7 API and packages](#7-api-and-packages-api) · [8 Docs and naming](#8-docs-and-naming-doc) · [9 Testing](#9-testing-test) · [10 Tooling and dependencies](#10-tooling-and-dependencies-tool) · [Checks](#checks) · [Baseline](#baseline-before-the-2026-11-15-refactor) · [Sources](#sources)

---

## 1. Project invariants (INV)

What passh promises in `spec.md` and `IMPLEMENTATION.md`. All MUST. The safety rules map as: S1 → INV-2, S2 → INV-3, S3 → INV-4, S4 → INV-5, S5 and S6 → INV-6, S7 → INV-7, S8 → INV-8, S9 → INV-9.

- **INV-1 · MUST · `spec.md` is the source of truth.** Behaviour, messages, formats and defaults follow `spec.md` (`spec.ru.md` is its translation; `EXAMPLES.md` shows the intended UX). If the code must differ, report the needed spec change; never change the spec, or drift from it, silently. Spec-driven code cites its section (`// §4.6 step 5`, `// S4`).
  - Why: the spec is what the owner reviewed; silent drift breaks the safety argument.
  - Check: for each changed behaviour, compare with the cited section; a new spec deviation is listed in the change report and in `IMPLEMENTATION.md` ("Spec changes made during implementation").
  - Source: `IMPLEMENTATION.md`; spec §10.

- **INV-2 · MUST · S1: no plaintext on persistent disk.** The vault, its temporary file and its backups hold only ciphertext. Plaintext reaches a file only (a) for `edit --editor`, in a 0700 folder on tmpfs (`$XDG_RUNTIME_DIR` or `/dev/shm`), mode 0600, removed afterwards, and refused where there is no tmpfs; (b) for an export or print the user asked for, with the confirmations and tmpfs warning of §7.1/§7.2.
  - Why: a stolen disk or backup must reveal nothing.
  - Check: `grep -rnE 'os\.(WriteFile|Create|CreateTemp|OpenFile|MkdirTemp)\(' --include='*.go' internal cmd | grep -v _test.go` — every hit is in `vault`, `editor`, `cli/files.go`, `cli/exportcmd.go`, `config`, `printweb/cert.go`, `tty` (`/dev/tty`), or is reviewed against S1; `test/acceptance/safety_disk_test.go` passes.
  - Source: spec §5.5 S1, §7.1, §7.2.

- **INV-3 · MUST · S2: secrets never in arguments or the environment.** The passphrase is read from `/dev/tty` through `internal/tty`; the vault key reaches the agent through `exec.StartDetached`'s pipe and clients through the socket; `$EDITOR`, the clipboard command and gpg get secrets only on stdin, a pipe or a file under S1. No flag, environment variable or config key accepts a passphrase, key or entry value.
  - Why: argv and environ are readable by other processes (`/proc/<pid>/cmdline`, `ps e`) and end up in shell history.
  - Check: review every `exec.Command{…}` literal (`grep -rn 'exec\.Command{' --include='*.go' internal | grep -v _test.go`) and what flows into its `Args` and `Env`; `grep -rnE 'Flags\(\)\.[A-Za-z]+Var?\(' internal/cli` — no flag carries a secret.
  - Source: spec §5.5 S2, §5.3; [os/exec](https://pkg.go.dev/os/exec).

- **INV-4 · MUST · S3: `crypto/rand` only, no modulo bias.** Passwords, print page tokens, temporary names and IDs come from `crypto/rand`. Picking from an alphabet uses rejection sampling (or `rand.Int`), never `b % n`. `math/rand` and `math/rand/v2` are banned outside tests.
  - Why: predictable or biased passwords are weaker than they look.
  - Check: `golangci-lint run` (depguard `randomness`, gosec G404); `grep -rn 'math/rand' --include='*.go' internal cmd | grep -v _test.go`; review `% ` on random values in `internal/gen`.
  - Source: spec S3; CRC [Crypto Rand](https://go.dev/wiki/CodeReviewComments#crypto-rand); [crypto/rand](https://pkg.go.dev/crypto/rand).

- **INV-5 · MUST · S4: escape everything printed to a terminal.** Any string from the vault, an import, a file name, the environment, or an error that wraps one of those goes through `sanitize.Line` (one line) or `sanitize.Text` (several lines) before it reaches stdout or stderr on a terminal, a TUI view or a `/dev/tty` prompt. Exact bytes only for `show --raw`, and for `show --field` when stdout is not a terminal (§6.1). Reuse the helpers in `internal/cli` (`line`, `displayPath`, `warnf`, `exitStatus`).
  - Why: an entry must not be able to drive the terminal (OSC 52 clipboard writes, hidden text, bidi reordering).
  - TUI: besides the per-value calls, the whole frame passes one choke point in `View()` that escapes everything except passh's own styling sequences (`inertStyled` in `internal/tui/view.go`). A new view path must go through it; per-value `sanitize` calls stay as the first line of defence.
  - Check: CLI: for each new `Fprint*`, `io.WriteString` or `t.Printf`, trace its arguments to a sanitize call. TUI: `View()` returns only text that went through the frame choke point (`grep -n 'inertStyled' internal/tui/view.go`), and no view writes to the terminal outside `View()`. `test/acceptance/safety_input_test.go` passes.
  - Source: spec §5.5 S4, §9.

- **INV-6 · MUST · S5, S6: limit exposure on screen and clipboard.** The TUI masks passwords with a fixed-length mask (never sized from the secret) and hides a revealed one after 10 s. The clipboard is cleared after `clipboard.clear_after`; non-TUI `copy` waits for the clear before it exits; `copy` never prints the secret when no clipboard is available (§6.3).
  - Why: shoulder surfing and clipboard history.
  - Check: secrets are shown as the constant `editor.Mask` (`grep -rn 'editor\.Mask\|= Mask' --include='*.go' internal | grep -v _test.go`), never a mask sized from the value; tui, clipboard and session tests pass.
  - Source: spec §5.5 S5, S6, §6.3.

- **INV-7 · MUST · S7: core dumps off.** `harden.DisableCoreDumps` runs first in `main` and in the agent, before any secret is read; don't move or drop the calls.
  - Why: a core file would hold the vault key.
  - Check: `grep -rn 'DisableCoreDumps' --include='*.go' cmd internal | grep -v _test.go` shows `cmd/passh/main.go` and `internal/agent`.
  - Source: spec §5.5 S7.

- **INV-8 · MUST · S8: `internal/exec` is the only process starter.** No other package imports `os/exec` or calls `os.StartProcess`, `syscall.Exec`/`ForkExec` (tests excepted). Never a shell (`sh -c`): a program name plus an argument list, `--` before paths for programs that accept it, gpg results read from `--status-fd`. `exec.LookPath` refuses programs found through `.` in `$PATH`.
  - Why: one place enforces no-shell, argv lists and S2.
  - Check: `golangci-lint run` (depguard `processes`, forbidigo); `grep -rln '"os/exec"' --include='*.go' internal cmd | grep -v -e _test.go -e internal/exec/`; `grep -rnE '"(ba|z)?sh"|"-c"' --include='*.go' internal | grep -v _test.go`.
  - Source: spec §5.5 S8; [os/exec](https://pkg.go.dev/os/exec) (no shell, `ErrDot`).

- **INV-9 · MUST · S9: the vault recipient never leaves memory.** `X25519Identity.Recipient()` is called only in `internal/keys` to encrypt the data block; its value is never formatted (`String()`, `%s`, `%v`), written, exported, logged, printed or sent over the agent socket.
  - Why: age doesn't authenticate senders; a known recipient lets anyone forge a data block (§4.1).
  - Check: `grep -rn 'Recipient()' --include='*.go' internal cmd | grep -v _test.go` → only `internal/keys/keys.go`; tests assert no `age1` in the vault, backups and exports.
  - Source: spec §5.5 S9, §4.1, ADR-6.

- **INV-10 · MUST · scrypt work factor 2^18 in production.** Only `keys.scryptWorkFactor` sets it; no flag, config key, environment variable or build tag lowers it. Tests lower it only from a `_test.go` file (or `export_test.go`) of the same package, restore it with `t.Cleanup`, and keep `TestProductionWorkFactorIs18` and `TestWrapAtRealWorkFactor`. Unwrapping caps the accepted work factor at 18 (`SetMaxWorkFactor(18)` on the scrypt identity, not age's default 2^22) and refuses a higher one before running scrypt, with a message saying the key block asks for too much work.
  - Why: the passphrase is the main protection of a stolen file (§9); a lighter setting would be a downgrade path. A tampered key block asking for 2^22 would cost 4 GiB per attempt and get passh killed on a Pi.
  - Check: `grep -rn 'SetWorkFactor\|SetMaxWorkFactor\|scryptWorkFactor' --include='*.go' internal cmd | grep -v _test.go` → only `internal/keys/keys.go`; a test feeds a key block with work factor 19 and expects a quick refusal.
  - Source: spec §4.1; `IMPLEMENTATION.md`.

- **INV-11 · MUST · only `internal/vault` writes the vault.** Saving follows §4.6 steps 1–7 (flock in the state folder, change check by SHA-256, temporary file 0600 in the same folder, fsync, read-back and decrypt compare, backup, rename without replacing a file that appeared, fsync of the folder; a symlinked vault writes its target). No other package writes the vault file or its backups.
  - Why: a save interrupted at any point must leave the old file or the new one, each complete.
  - Check: `grep -rn 'os\.Rename\|renameNoReplace\|writeAtomic' --include='*.go' internal | grep -v _test.go` → only `internal/vault`; vault save/crash tests and `test/acceptance/crash_test.go` pass.
  - Source: spec §4.6, §4.7.

- **INV-12 · MUST · agent access rules.** Agent folder: a real directory (not a symlink), owned by the user, mode 0700; socket 0600; peer uid checked on every connection (`SO_PEERCRED`/`getpeereid`); every key request carries the key-block hash and the agent refuses a request without one or with a different one; the key never written to disk; key wiped and socket removed on exit; idle TTL counts key requests only. Only `passh unlock` starts an agent.
  - Why: the agent holds the vault key for every process of the user (§9).
  - Check: `internal/agent` and `internal/config` (agentdir) tests pass, including one that sends a key request without a hash and expects a refusal; review any diff there against §5.3.
  - Source: spec §5.3, ADR-8.

- **INV-13 · MUST · don't change the system.** passh writes only the places of §3.2: the vault (and its temp file), the config file (created once by `init`), `$XDG_STATE_HOME/passh/`, the `passh-<uid>` socket fallback, the tmpfs edit folder, and files the user names (`-o`, `backup <dest>`). No root, no services, no shell rc edits, no certificate stores.
  - Why: ADR-3; uninstall is "delete three things".
  - Check: any new path passh writes is in the §3.2 table; the [fake-HOME check](#checks) stays clean.
  - Source: spec §3.2, ADR-3, ADR-5.

## 2. Security and secrets (SEC)

- **SEC-1 · MUST · keep secrets in `[]byte` and wipe them.** Passphrases, vault key text, decrypted JSON and plaintext export buffers are `[]byte`, cleared with `clear(b)` (or `clear(b[:cap(b)])` for a `bytes.Buffer`'s contents, or `keys.Zero`/`tty.Wipe`) as soon as they're no longer needed, usually `defer clear(b)`. Convert to `string` only where a library demands it (age's parsers) or the data model holds strings (entry fields), never for convenience. In the TUI, passh wipes what it owns (the input widgets' buffers, on submit, cancel and lock); key events arrive from Bubble Tea as strings and the terminal reader keeps its own buffers, so those copies are best effort and out of scope.
  - Why: strings can't be wiped. This is best effort (ADR-4: no locked memory; Go 1.26's `runtime/secret` is an experiment and not used).
  - Check: `grep -rnE 'string\((pass|passphrase|key|secret|plain|pt)[A-Za-z0-9]*\)' --include='*.go' internal | grep -v _test.go` — each hit is a library boundary; every new secret buffer has a `clear`.
  - Source: spec ADR-4, §5.2, §5.3; [golang.org/x/term ReadPassword](https://pkg.go.dev/golang.org/x/term#ReadPassword) returns `[]byte`; [Go 1.26 release notes](https://go.dev/doc/go1.26) (`runtime/secret`).

- **SEC-2 · MUST · compare secrets in constant time.** Passphrase repetition, the print page token and the agent's key-block check use `crypto/subtle.ConstantTimeCompare`; never `==`, `bytes.Equal` or `strings.EqualFold` on a secret.
  - Why: timing differences leak how much of a guess was right.
  - Check: `grep -rnE 'bytes\.Equal|== *(tok|token|pass|key)' --include='*.go' internal | grep -v _test.go` — no hit compares a secret.
  - Source: [crypto/subtle](https://pkg.go.dev/crypto/subtle).

- **SEC-3 · MUST · no secret in a message.** Error strings, warnings, panics, the TUI status line, `%v`/`%+v` of structs and test failure messages never contain a passphrase, vault key, password or other entry value (fixed test fixtures excepted). A type that holds a secret has no `String`, `Error` or `GoString` that prints it.
  - Why: messages end up in scrollback, logs, bug reports and CI output.
  - Check: review the arguments of `fmt.Errorf`, `errors.New`, `warnf`, `setStatus*` in changed code; `grep -rnE 'Errorf\(.*\b(pass|passphrase|secret|password)\b' --include='*.go' internal | grep -v _test.go`.
  - Source: spec S9, §9; GSG [logging](https://google.github.io/styleguide/go/best-practices#logging-errors) (no PII in logs).

- **SEC-4 · MUST · crypto only through age and the standard library.** No home-made ciphers, KDFs, MACs or random generators; no `golang.org/x/crypto/openpgp`; keep age's limits (maximum scrypt work factor on unwrap, armor parsing).
  - Why: age is reviewed and has independent implementations; manual recovery (§8) depends on standard age files.
  - Check: `go list -deps ./cmd/passh | grep -E 'crypto|age'` lists nothing unexpected; review imports in `internal/keys`, `internal/vaultfile`, `internal/printweb`.
  - Source: spec §10.1, ADR-1; [Go security best practices](https://go.dev/doc/security/best-practices).

- **SEC-5 · MUST · keep the print page's protections.** TLS 1.3 minimum with the persistent self-signed certificate and its fingerprint shown; private addresses only; `allow_from`; `Host` check; single-use token compared in constant time; 5-minute limit; CSP; all HTML through `html/template` (a `template.HTML` value only from content escaped with `template.HTMLEscapeString`, with a comment); `http.Server` timeouts and `MaxHeaderBytes` set; no HTTP/2.
  - Why: the page carries every password across the LAN (§9).
  - Check: `golangci-lint run` (gosec G112, G203, G402); `internal/printweb` tests and `test/acceptance/printpage_test.go` pass.
  - Source: spec §7.4, ADR-5; [html/template](https://pkg.go.dev/html/template); [gosec rules](https://github.com/securego/gosec/blob/master/RULES.md).

- **SEC-6 · MUST · untrusted directory trees go through `os.Root`.** Reading a pass store uses `os.OpenRoot`/`Root.Open`; never `filepath.Join(dir, nameFromTheTree)` followed by `os.Open`. Paths the user names on the command line (`--vault`, `-o`, `backup <dest>`) are trusted.
  - Why: `..` and symlinks in a foreign tree must not reach outside it (also against TOCTOU swaps).
  - Check: `grep -n 'OpenRoot\|os\.Root' internal/importpass/*.go`; review any new directory walk.
  - Source: spec §10.1; [Traversal-resistant file APIs](https://go.dev/blog/osroot).

- **SEC-7 · MUST · check security-relevant folders, don't trust them.** Before using the agent folder or the tmpfs edit folder, passh checks it is a real directory (`Lstat`, not a symlink), owned by the user, mode 0700 (fixing a wider mode only on a folder it created); files it creates there use `O_EXCL|O_NOFOLLOW`.
  - Why: another local user could pre-create or redirect those paths.
  - Check: `internal/config/agentdir.go` and `internal/editor/external.go` tests; review changes there.
  - Source: spec §5.3, §5.5 S1.

- **SEC-8 · SHOULD · bound every read of external input.** The vault file, agent messages, `/dev/tty` input (`tty.MaxPassphrase`, `tty.MaxLine`), gpg output, config files and HTTP requests have a size limit (`io.LimitReader`, `http.MaxBytesReader`, explicit maxima); `io.ReadAll` only on a bounded reader.
  - Why: a hostile file or peer must not exhaust memory (256 MiB already go to scrypt on a Pi).
  - Check: `grep -rn 'io\.ReadAll\|os\.ReadFile' --include='*.go' internal | grep -v _test.go` — each source is bounded or written by passh itself.
  - Source: [io.LimitReader](https://pkg.go.dev/io#LimitReader), [http.MaxBytesReader](https://pkg.go.dev/net/http#MaxBytesReader).

- **SEC-9 · MUST · no reachable known vulnerabilities.** `govulncheck ./...` reports no called vulnerability before a release. Module-level findings (in the module graph but not called) go into the review report; the fix is an owner-approved dependency bump (TOOL-5), never an agent editing `go.mod`.
  - Why: known CVEs in reachable code are the cheapest attack.
  - Check: `.tools/bin/govulncheck ./...` ("Your code is affected by 0 vulnerabilities"); `-show verbose` for module-level findings.
  - Source: [Go vulnerability management](https://go.dev/doc/security/vuln/); [Go security best practices](https://go.dev/doc/security/best-practices).

## 3. Errors (ERR)

- **ERR-1 · MUST · never drop an error silently.** Check, return or handle every error. A deliberate discard is explicit, `_ = f()`, with a comment saying why it's safe (best-effort cleanup, a read-only close); `if err != nil { return nil }` needs the same comment.
  - Why: a lost write, close, remove or fsync error turns a failed save or a leftover plaintext file into silence.
  - Check: `golangci-lint run` (errcheck, nilerr); review each `_ =` for a reason.
  - Source: CRC [Handle Errors](https://go.dev/wiki/CodeReviewComments#handle-errors); GSG [handle errors](https://google.github.io/styleguide/go/decisions#handle-errors); EG [errors](https://go.dev/doc/effective_go#errors).

- **ERR-2 · MUST · add context; `%w` at the end, `%v` only on purpose.** Wrap with what the caller doesn't know (operation and object: `fmt.Errorf("reading backup %s: %w", name, err)`), without "failed to"/"error" filler and without repeating what the wrapped error says (`os` errors carry the path). Use `%w` when callers may inspect the cause. Use `%v` only to hide an implementation detail at a package boundary; passh's pattern for that is `fmt.Errorf("%w: %v", ErrSentinel, err)` (sentinel matchable, detail as text).
  - Why: messages read as one chain, and the chain is part of the API.
  - Check: `grep -rnE 'Errorf\(.*%v.*\berr\)' --include='*.go' internal cmd | grep -v _test.go | grep -v '%w'` — each hit hides the cause on purpose; review new wraps for duplicated or empty context.
  - Source: [Working with Errors in Go 1.13](https://go.dev/blog/go1.13-errors); GSG [best practices: error handling](https://google.github.io/styleguide/go/best-practices#error-handling); Uber [error wrapping](https://github.com/uber-go/guide/blob/master/style.md#error-wrapping).

- **ERR-3 · MUST · inspect errors with `errors.Is`/`errors.As`.** Never `err == ErrX`, `err != ErrX` or `err.(*T)` on an error that may be wrapped (tests included); `errors.AsType[*T](err)` (Go 1.26) is fine. `err == nil` and `err != nil` are fine. Exception: a test whose point is that an error passes through *unwrapped* may compare identity, marked `//nolint:errorlint // asserts identity`.
  - Why: wrapping (ERR-2) breaks `==` and type assertions.
  - Check: `golangci-lint run` (errorlint `comparison`, `asserts`); each `//nolint:errorlint` is in a `_test.go` file and says `asserts identity`.
  - Source: [Go 1.13 errors](https://go.dev/blog/go1.13-errors); [errors](https://pkg.go.dev/errors).

- **ERR-4 · MUST · never branch on error text.** No `strings.Contains(err.Error(), …)` or `err.Error() == …` to decide what to do; give the caller a sentinel or a typed error instead. Formatting an error's text for display is fine. Tests may match message text only where it is spec wording (ERR-6).
  - Why: messages change; string matching breaks silently.
  - Check: `grep -rnE '\.Error\(\) *(==|!=)|strings\.(Contains|HasPrefix|HasSuffix|EqualFold)\([^,]*\.Error\(\)' --include='*.go' internal cmd | grep -v _test.go`.
  - Source: GSG [error structure](https://google.github.io/styleguide/go/best-practices#error-structure) ("do not distinguish errors based on their string form").

- **ERR-5 · MUST · error string style.** Lowercase first letter (unless it starts with a proper noun, acronym, identifier, flag or spec phrase: `QR code: …`, `--age: …`), no trailing punctuation or newline, no `error:` prefix; layers joined by `: `. The CLI adds `passh: ` once, in `cli.exitStatus`. Exception: an error may span several lines where the spec asks for a list (the backups after damaged data, §4.5; several config problems, §3.3: `vault.OpenError`, `config.Error`); it has no trailing newline and is printed with `sanitize.Text`, which keeps its line breaks.
  - Why: errors are embedded in other messages.
  - Check: staticcheck ST1005; `grep -rnE '(errors\.New|fmt\.Errorf)\("[A-Z]' --include='*.go' internal cmd | grep -v _test.go` — each hit starts with an acronym or name; `grep -rn '\\n' --include='*.go' internal | grep -E 'Errorf|errors\.New' | grep -v _test.go`, plus the `Error()` methods of `OpenError`/`config.Error` — each multi-line error is a spec list or a spec-worded hint.
  - Source: CRC [Error Strings](https://go.dev/wiki/CodeReviewComments#error-strings); GSG [error strings](https://google.github.io/styleguide/go/decisions#error-strings).

- **ERR-6 · MUST · spec wording for user-facing errors.** Where the spec gives a message (the §4.5 table, §5.1 "vault is locked: run `passh unlock` in a terminal (over SSH: `ssh -t host passh unlock`)", §4.6 changed file, §6.3 hint), the error contains that wording, and a test asserts it.
  - Why: users and the docs rely on those messages.
  - Check: grep the spec phrase in `internal/`; a test in the package or in `test/acceptance` matches it.
  - Source: `IMPLEMENTATION.md` ("messages that match the spec's wording").

- **ERR-7 · MUST · handle an error once.** A function either returns the error or reports it (stderr, TUI status), not both. Only `cli.exitStatus` prints a command's final error; warnings that don't stop the command go through `warnf` or the TUI status line.
  - Why: printed-and-returned errors appear twice or in the wrong stream.
  - Check: review new `Fprint*`/`warnf`/`setStatus*` calls that are followed by `return err`.
  - Source: Uber [handle errors once](https://github.com/uber-go/guide/blob/master/style.md#handle-errors-once); GSG [logging errors](https://google.github.io/styleguide/go/best-practices#logging-errors).

- **ERR-8 · SHOULD · sentinels and typed errors, documented.** Errors callers must tell apart are exported sentinels `ErrXxx` (package-level `errors.New`) or types `XxxError` with `Unwrap` when they wrap; functions return the `error` interface, never a concrete error type (nil-interface trap). The doc comment names the sentinels/types a function returns.
  - Why: callers need a stable way to branch (ERR-4).
  - Check: staticcheck ST1012; review doc comments of exported functions that return sentinels.
  - Source: Uber [error naming](https://github.com/uber-go/guide/blob/master/style.md#error-naming); GSG [returning errors](https://google.github.io/styleguide/go/decisions#returning-errors), [documentation: errors](https://google.github.io/styleguide/go/best-practices#documentation-conventions).

- **ERR-9 · MUST · no panic for expected failures.** User input, files, children, the network and the agent never cause a panic: return an error. `panic` only for programmer errors and impossible states: `Must*` helpers on constants (`paths.MustParse`), embedded assets that must parse (`print/font.go`). No `recover` except to restore the terminal before re-panicking.
  - Why: a panic skips wipes and terminal restoration and prints a stack trace.
  - Check: `grep -rn 'panic(\|recover()' --include='*.go' internal cmd | grep -v _test.go` — each hit has a comment saying why it can't happen at run time.
  - Source: CRC [Don't Panic](https://go.dev/wiki/CodeReviewComments#dont-panic); GSG [must functions](https://google.github.io/styleguide/go/decisions#must-functions); EG [panic](https://go.dev/doc/effective_go#panic).

- **ERR-10 · SHOULD · `os.Exit` only in `main` and `TestMain`.** Other code returns an exit status (`cli.Main` returns `int`) so deferred cleanup runs.
  - Why: `os.Exit` skips defers: terminal restore, wipes, closes.
  - Check: `grep -rn 'os\.Exit(' --include='*.go' internal cmd | grep -v _test.go` → only `cmd/passh/main.go` (see [Baseline](#baseline-before-the-2026-11-15-refactor) for the agent entry).
  - Source: Uber [exit in main](https://github.com/uber-go/guide/blob/master/style.md#exit-in-main).

## 4. Context and concurrency (CONC)

- **CONC-1 · MUST · context first, honoured.** These take `ctx context.Context` as their first parameter and return promptly with `ctx.Err()` (or an error wrapping it) when it is cancelled: waits for a lock (the vault save lock, retries), network waits (the print page server, accepts and reads with deadlines), child processes (`exec.Run`/`Output`), agent requests (client and start), and the timers built on them (clipboard clear, TTLs). Vault mutations get context-taking variants for their lock wait (the spec's §10.3 `Vault` signatures stay as wrappers). Exempt: a blocking read on `/dev/tty` (no portable deadline, e.g. on macOS); there the signal handling of CONC-6 and terminal restoration of OUT-6 are binding. Pure functions take no ctx. Don't store a ctx in a struct, except in an object whose life is one operation (document the field).
  - Why: Ctrl-C, SIGHUP and the TUI lock must stop work promptly (§5.2).
  - Check: for each listed kind of wait, the function takes a ctx and a test cancels it and expects a prompt return; `grep -rn 'time\.Sleep' --include='*.go' internal | grep -v _test.go` — no retry loop sleeps without also selecting on `ctx.Done()`.
  - Source: CRC [Contexts](https://go.dev/wiki/CodeReviewComments#contexts); [context](https://pkg.go.dev/context) ("Do not store Contexts inside a struct type"); GSG [contexts](https://google.github.io/styleguide/go/decisions#contexts).

- **CONC-2 · MUST · no new context roots inside the call tree.** `context.Background()`/`TODO()` only in `cli.Main`, in tests (prefer `t.Context()`), and for work that must outlive a cancelled parent (clearing the clipboard on lock, server shutdown) — with a comment, preferably as `context.WithoutCancel(ctx)` plus a timeout. Elsewhere use the ctx you were given (`cmd.Context()` in cobra commands). Don't pass a nil ctx.
  - Why: a fresh root silently ignores cancellation.
  - Check: `grep -rn 'context\.\(Background\|TODO\)()' --include='*.go' internal cmd | grep -v _test.go` — each hit is an entry point or carries a comment; staticcheck SA1012 (nil ctx).
  - Source: GSG [contexts](https://google.github.io/styleguide/go/decisions#contexts); [context.WithoutCancel](https://pkg.go.dev/context#WithoutCancel).

- **CONC-3 · MUST · every goroutine has an owner and an end.** A comment at the `go` statement (or the function's doc) says what stops it (ctx, a closed channel, process exit), and the owner waits for it (`sync.WaitGroup`, `WaitGroup.Go`, a done channel) before returning or in `Close`/`Stop`. Fire-and-forget only to reap a detached child (`proc.Wait`), with a comment. Exempt: goroutines that run a `tea.Cmd` (started by Bubble Tea, or by passh to deliver one `tea.Msg`) and end when their function returns; they must still honour the job's ctx (CONC-1).
  - Why: leaked goroutines hold secrets and file descriptors and race with shutdown.
  - Check: `grep -rnE 'go func|go [A-Za-z_.]+\(' --include='*.go' internal cmd | grep -v _test.go` — each hit has an exit path and a waiter, or is a `tea.Cmd` runner; `go test -race -count=2` stays clean.
  - Source: CRC [Goroutine Lifetimes](https://go.dev/wiki/CodeReviewComments#goroutine-lifetimes); Uber [don't fire-and-forget goroutines](https://github.com/uber-go/guide/blob/master/style.md#dont-fire-and-forget-goroutines), [wait for goroutines to exit](https://github.com/uber-go/guide/blob/master/style.md#wait-for-goroutines-to-exit).

- **CONC-4 · MUST · channel discipline.** Only the sending side closes a channel, exactly once (guard with `sync.Once` if several paths can close). Buffer size 0 or 1 unless a comment justifies more (`signal.Notify` channels, event queues). A send that could block after the receiver left selects on `ctx.Done()` or a done channel.
  - Why: double close panics; a blocked send leaks a goroutine.
  - Check: review `close(` and `make(chan` in changed code.
  - Source: Uber [channel size is one or none](https://github.com/uber-go/guide/blob/master/style.md#channel-size-is-one-or-none); EG [channels](https://go.dev/doc/effective_go#channels); [os/signal](https://pkg.go.dev/os/signal).

- **CONC-5 · MUST · guard shared state; stay race-free.** State shared between goroutines is guarded by a `sync.Mutex`/`RWMutex` field (not embedded, not a pointer) held on every access, or is a typed `sync/atomic` value (`atomic.Bool`, `atomic.Int64`). Never copy a struct that contains a lock.
  - Why: races in the agent, session and clipboard timers corrupt state or leak keys.
  - Check: `go test -race -count=1 ./internal/... ./cmd/...` passes; `go vet` copylocks.
  - Source: [Data Race Detector](https://go.dev/doc/articles/race_detector); Uber [zero-value mutexes are valid](https://github.com/uber-go/guide/blob/master/style.md#zero-value-mutexes-are-valid); [Go security best practices](https://go.dev/doc/security/best-practices).

- **CONC-6 · MUST · signals end in cleanup, then stop.** A phase that holds something to clean up on SIGINT, SIGTERM or SIGHUP (TUI lock in `internal/session`, the editor's plaintext temp file, the pending clipboard clear, the print page server, the agent) catches all three with `signal.Notify` on a buffered channel, cleans up, and calls `signal.Stop` on the same path (`defer signal.Stop(ch)`). No package-wide or `init` handlers.
  - Why: a dropped SSH session sends SIGHUP; without cleanup a plaintext file or a clipboard value stays behind (S1, S6, §5.2).
  - Check: `grep -rn 'signal\.Notify' --include='*.go' internal cmd | grep -v _test.go` — each hit has a matching `signal.Stop` in the same function (`grep -rn 'signal\.Stop' --include='*.go' internal`).
  - Source: spec §5.2, §5.3, §6.3; [os/signal](https://pkg.go.dev/os/signal).

- **CONC-7 · SHOULD · synchronous APIs.** Functions do their work and return; the caller adds goroutines. A function that starts background work returns its stop (`session.Notify` returns `stop`) and documents it.
  - Why: callers can add concurrency, never remove it.
  - Check: review new exported functions that start goroutines.
  - Source: CRC [Synchronous Functions](https://go.dev/wiki/CodeReviewComments#synchronous-functions); GSG [synchronous functions](https://google.github.io/styleguide/go/decisions#synchronous-functions).

- **CONC-8 · SHOULD · `time.Duration` and an injectable clock.** Periods are `time.Duration` (config TTLs parsed into it), instants `time.Time`; time-dependent code takes a `now func() time.Time` or a clock field so tests don't mutate globals or sleep.
  - Why: integer seconds get mixed up; injected time makes TTL tests exact.
  - Check: review new TTL/timeout fields and their tests.
  - Source: Uber [use "time" to handle time](https://github.com/uber-go/guide/blob/master/style.md#use-time-to-handle-time), [avoid mutable globals](https://github.com/uber-go/guide/blob/master/style.md#avoid-mutable-globals).

- **CONC-9 · MUST · Bubble Tea: no blocking work in `Update` or `View`.** `Update` changes the model and returns quickly; anything that touches a file, socket, process, the agent, the clipboard or scrypt (open, save, reload, copy, print page start/stop) runs in a `tea.Cmd` that returns a message, and `Update` handles that message. `View` is pure: it reads the model and returns a string; it doesn't change state (scroll offsets and cursors are clamped in `Update`, on keys and on `tea.WindowSizeMsg`) and does no I/O.
  - Why: a blocking `Update` freezes input, the idle lock and signal handling; a `View` with side effects depends on render order.
  - Check: in `internal/tui`, every call in `Update` and its key handlers that reaches `vault`, `agent`, `clipboard`, `printweb`, `os` or `exec` is inside a returned `tea.Cmd`; `View` and the functions it calls assign to no model field (review `view.go` for `m.<field> =`).
  - Source: [Bubble Tea](https://pkg.go.dev/charm.land/bubbletea/v2) (commands do I/O and return messages; the Elm architecture's update/view split).

## 5. Files and I/O (FILE)

- **FILE-1 · MUST · modes 0600 and 0700.** Files passh creates are 0600 and folders 0700 (vault, temp files, backups, locks, rollback record, config, agent folder, print certificate, exports, editor temp). Set the mode at creation (`OpenFile`, `Mkdir`, `CreateTemp`) and `Chmod` where an existing file or the umask could leave it wider.
  - Why: other local users must not read anything passh writes (§4.1, §3.2).
  - Check: `grep -rnE '\b0o?(644|640|664|666|755|750|775|777)\b' --include='*.go' internal cmd | grep -v _test.go`; `golangci-lint run` (gosec G301, G302, G306).
  - Source: spec §4.1, §5.3, §7.1; [gosec rules](https://github.com/securego/gosec/blob/master/RULES.md).

- **FILE-2 · MUST · durable writes are atomic.** A file that must be complete or absent after a crash (vault, backups, rollback record, `backup <dest>`) is written to a temporary file in the same folder, fsynced, read back where the spec says so, renamed into place, and the folder fsynced. Never `os.WriteFile` over such a file. All of these writers live in `internal/vault`, so renames stay there (INV-11): `passh backup <dest>` calls a helper in `internal/vault` rather than renaming in `internal/cli`.
  - Why: `os.WriteFile` truncates in place and can leave a partial file.
  - Check: review new writers of these files; the INV-11 grep finds no `os.Rename` outside `internal/vault`; `internal/vault` crash tests pass.
  - Source: spec §4.6, §4.8; [os.WriteFile](https://pkg.go.dev/os#WriteFile).

- **FILE-3 · MUST · check `Close` after writing.** For a file opened for writing: `Sync` where durability matters, then `if err := f.Close(); err != nil { … }`, or a deferred close that joins its error into the named result (`errors.Join`). A bare `defer f.Close()` only for files opened read-only.
  - Why: on some filesystems the write error only shows up at close.
  - Check: errcheck can't tell written from read-only files (`.golangci.yml` excludes `(*os.File).Close`), so list the bare `Close()` calls in functions that open a file for writing — it prints nothing when every such close is checked or is an explicit `_ = f.Close() // <reason>` (e.g. an error path that then removes the file):

    ```bash
    awk '/^func /{w=0;n=0} /O_WRONLY|O_RDWR|os\.Create\(|CreateTemp\(/{w=1} {b[n++]=FILENAME":"FNR":"$0}
         /^}/{if(w)for(i=0;i<n;i++)if(b[i]~/:[[:space:]]*(defer[[:space:]]+)?[A-Za-z_.]+\.[cC]lose\(\)[[:space:]]*(\/\/.*)?$/)print b[i];w=0;n=0}' \
        $(find internal cmd -name '*.go' ! -name '*_test.go')
    ```
  - Source: [os.File.Close](https://pkg.go.dev/os#File.Close), [os.File.Sync](https://pkg.go.dev/os#File.Sync); CRC [Handle Errors](https://go.dev/wiki/CodeReviewComments#handle-errors).

- **FILE-4 · MUST · never overwrite by accident.** Files that must not exist yet (`-o` outputs, the config template, editor temp files) are created with `O_CREATE|O_EXCL` (plus `O_NOFOLLOW` in shared or tmpfs folders). passh overwrites a user file only where the spec says so.
  - Why: a race or a symlink must not redirect a plaintext write (§7.2 output rules).
  - Check: `grep -rn 'OpenFile(' --include='*.go' internal | grep -v _test.go | grep O_CREATE | grep -v O_EXCL` — each hit is reviewed (the vault lock file is one).
  - Source: spec §7.1, §7.2; [os.OpenFile](https://pkg.go.dev/os#OpenFile).

- **FILE-5 · MUST · temporary files are cleaned up on every path.** Create them with `os.CreateTemp`/`os.MkdirTemp` in the right folder (the vault's folder for saves; tmpfs for the editor) and remove them in a `defer` that also runs on errors; check the removal error where the file holds plaintext. Leftovers of interrupted saves are removed under the save lock (§4.6 step 1).
  - Why: a stray temp file is either clutter or, for the editor, plaintext (S1).
  - Check: review each `CreateTemp`/`MkdirTemp` for its removal; `passh doctor` reports leftover vault temp files.
  - Source: [os.CreateTemp](https://pkg.go.dev/os#CreateTemp) (the caller removes the file); spec §4.6, S1.

- **FILE-6 · SHOULD · release resources with `defer` right after acquiring them.** Files, locks, sockets, listeners, timers, raw terminal mode. In a loop, move the body into a function so its defers run each iteration.
  - Why: cleanup then runs on every return path, and sits next to the acquisition.
  - Check: review; `go vet` lostcancel.
  - Source: EG [defer](https://go.dev/doc/effective_go#defer); Uber [defer to clean up](https://github.com/uber-go/guide/blob/master/style.md#defer-to-clean-up).

## 6. Output and UX (OUT)

- **OUT-1 · MUST · stdout is data only.** stdout carries only the data a command produces: entries and fields, listings (`ls`, `find`, `tags`, `backups`, `verify` results), export data, printed sheets, `--version` and help. Everything for a human goes to stderr: status and confirmations ("Saved x.", "Locked: …", "Clipboard cleared."), warnings, progress, hints and errors. Prompts go to `/dev/tty`. A command with no data writes nothing to stdout.
  - Why: `ssh pi passh show … --field password | pbcopy` and exports must get clean bytes, and a script's `$(passh …)` must not capture chatter (§6.4, §7.1).
  - Check: review new writes to `a.stdout` (each is data); black-box tests in `cmd/passh` assert confirmations on stderr and compare stdout exactly, and assert an empty stdout for commands without data.
  - Source: spec §6.4, §7.1.

- **OUT-2 · MUST · prompts only through `internal/tty`.** Passphrases with echo off (`ReadPassphrase`, `NewPassphrase`), lines (`ReadLine`), yes/no (`YesNo`), typed phrases (`Confirm` with the `tty.Phrase*` constants). Never read prompts from stdin or write them to stdout. Without a terminal, return an error wrapping `tty.ErrNoTerminal` and follow the spec's fallback (§5.1 step 3, `--confirm-plaintext`).
  - Why: prompts must work while stdout is piped, and never mix with data.
  - Check: `grep -rn 'os\.Stdin' --include='*.go' internal | grep -v _test.go` — no prompt reads it.
  - Source: spec §5.1, §5.4, §7.1.

- **OUT-3 · MUST · write to the writer you were given.** Packages write to an injected `io.Writer` (`app.stdout`/`stderr`, `cmd.OutOrStdout()`, a `*tty.TTY`); no `fmt.Print*`/`println`, and `os.Stdout`/`os.Stderr` only in `cmd/passh/main.go`, `cli.Main` and the agent child's usage line.
  - Why: tests capture output, and OUT-1 stays visible in the code.
  - Check: `golangci-lint run` (forbidigo); `grep -rn 'os\.Std\(out\|err\)' --include='*.go' internal | grep -v _test.go`.
  - Source: GSG [global state](https://google.github.io/styleguide/go/best-practices#global-state).

- **OUT-4 · MUST · check errors when writing data.** Data written to stdout or an output file is checked (`writeAll`, or the error of `Fprint*`/`Flush`), so a closed pipe or a full disk fails the command. Best-effort messages to stderr or `/dev/tty` may ignore write errors.
  - Why: a silently truncated export looks like a complete one.
  - Check: review `Fprint*` to `a.stdout` and to output files (errcheck excludes `fmt.Fprint*`, see `.golangci.yml`).
  - Source: CRC [Handle Errors](https://go.dev/wiki/CodeReviewComments#handle-errors).

- **OUT-5 · MUST · exit statuses.** 0 success, 1 error, 2 usage (`usageError`), 128 + signal (`exitCodeError`); mapped only in `cli.exitStatus`. New failure kinds reuse these.
  - Why: scripts branch on them.
  - Check: `cmd/passh` tests that assert exit codes.
  - Source: `internal/cli/cli.go` (current contract); spec §6.1.

- **OUT-6 · MUST · restore the terminal on every path.** Raw mode (passphrase prompt, TUI), alternate screen and cursor are restored on return, error, Ctrl-C and signals; Ctrl-C at a passphrase prompt returns `tty.ErrInterrupted` with echo back on.
  - Why: a terminal left without echo looks like a hung session, and the next typed passphrase becomes visible or lost.
  - Check: `internal/tty` and `internal/tui` pty tests; manual: interrupt each prompt, then `stty -a | grep -o ' echo'`.
  - Source: spec §5.1, §5.2; [golang.org/x/term](https://pkg.go.dev/golang.org/x/term) (`MakeRaw`/`Restore`).

- **OUT-7 · MUST · no logging.** passh has no log output: no `log`, no `log/slog`, no debug prints. The only `log` use is the discarding `ErrorLog` that keeps `net/http` quiet in `printweb`.
  - Why: logs are where secrets leak (S9, §9), and passh has no log file in §3.2.
  - Check: `grep -rln '"log"\|"log/slog"' --include='*.go' internal cmd | grep -v _test.go` → only `internal/printweb/server.go`.
  - Source: spec S9, §3.2; GSG [logging](https://google.github.io/styleguide/go/best-practices#logging-errors).

- **OUT-8 · SHOULD · messages are short, specific and say what to do next.** English; the spec's and `EXAMPLES.md`'s wording and command names; the next command to run where there is one ("run `passh unlock` in a terminal"); paths shown with `~` (`displayPath`). Cobra `Use`/`Short`/flag help match §6.1 names and defaults.
  - Why: one person runs this over SSH on a phone; a message is the whole UI.
  - Check: review changed messages against spec §6.1 and `EXAMPLES.md`.
  - Source: spec §6.1; `EXAMPLES.md`.

## 7. API and packages (API)

- **API-1 · MUST · layout.** `cmd/passh` holds only `main` (harden, version, `cli.Main`); everything else is under `internal/`, one package per concern of spec §10.2. A new package or top-level folder is listed in `AGENTS.md` with one line on its purpose.
  - Why: `internal/` keeps every API private, so refactors can't break outside users.
  - Check: `ls internal` matches the package table in `AGENTS.md`.
  - Source: [Organizing a Go module](https://go.dev/doc/modules/layout); spec §10.2.

- **API-2 · MUST · dependencies point down.** No package imports `internal/cli`; only `internal/cli` imports `internal/tui`. Leaves (`paths`, `sanitize`, `exec`, `tty`, `harden`, `gen`, `keys`, `vaultfile`, `config`, `session`) import no other passh package; `model` only `paths`; `vault` only `config`, `keys`, `model`, `paths`, `vaultfile`. A new edge between existing packages needs a reason in the review.
  - Why: the safety-critical core stays small, testable and free of UI concerns.
  - Check: `go list -f '{{.ImportPath}} {{join .Imports " "}}' ./internal/... ./cmd/... | awk '{for(i=2;i<=NF;i++) if ($i ~ /internal\/(cli|tui)$/) print $1" -> "$i}'` → only `cmd/passh -> internal/cli` and `internal/cli -> internal/tui`; `go list -f '{{.ImportPath}}: {{join .Imports " "}}' ./internal/... | grep devapro` for the full graph.
  - Source: spec §10.2; GSG [package size](https://google.github.io/styleguide/go/best-practices#package-size).

- **API-3 · SHOULD · interfaces at the consumer, small, and only when needed.** Define an interface where it is used, with only the methods used, when there are two implementations or a real seam (`keys.KeySource`: agent, passphrase, paper key). Accept interfaces, return concrete types. No interface or exported fake that exists only for tests.
  - Why: premature interfaces hide what code really calls.
  - Check: review new `interface` declarations and their implementations.
  - Source: CRC [Interfaces](https://go.dev/wiki/CodeReviewComments#interfaces); GSG [interfaces](https://google.github.io/styleguide/go/best-practices#interfaces).

- **API-4 · MUST · no mutable package state in production.** Package-level `var`s only for: sentinel errors; read-only tables, compiled regexps and styles (never written after init; an exported slice or map is better returned by a function that copies it); atomic ID counters; and unexported test hooks or tunables that hold the production value in passh and are changed only from `_test.go` files of the same package — either set once in `TestMain` for the whole test binary, or set in a test and restored with `t.Cleanup`. Today's hooks: `vault.testHook`, `vault.syncFile`, `vault.exchangeFiles`, `vault.renameNoReplaceFn`, `vault.lockWait`, `vault.lockPoll`, `vault.closeFile`, `vault.flock`, `keys.scryptWorkFactor`, `config.getuid`, `config.lastTmp`, `editor.shmDir`, `print.compress`, `printweb.minTTL`, `printweb.allowLoopback`, `printweb.interfaceAddrs`, `agent.peerUID`, `agent.startTimeout`. A new hook is added to this list. The one exported var written at run time is `cli.Version`, set once by `main`.
  - Why: global state couples tests and hides inputs.
  - Check: `grep -rnE '^var [A-Za-z_]+|^var \($' --include='*.go' internal | grep -v _test.go` — each is one of the allowed kinds; `grep -rnE '\b(testHook|syncFile|exchangeFiles|renameNoReplaceFn|lockWait|lockPoll|closeFile|flock|scryptWorkFactor|getuid|lastTmp|shmDir|compress|minTTL|allowLoopback|interfaceAddrs|peerUID|startTimeout) *=' --include='*_test.go' internal` shows the tests that change hooks (each is in `TestMain`, or restores the value and isn't parallel, TEST-2).
  - Source: GSG [global state](https://google.github.io/styleguide/go/best-practices#global-state); Uber [avoid mutable globals](https://github.com/uber-go/guide/blob/master/style.md#avoid-mutable-globals).

- **API-5 · MUST · no `init()` in production code.** No goroutines, I/O or environment reads at package initialisation.
  - Why: init order is implicit and runs in every test binary.
  - Check: `grep -rn '^func init()' --include='*.go' internal cmd | grep -v _test.go`.
  - Source: Uber [avoid init()](https://github.com/uber-go/guide/blob/master/style.md#avoid-init).

- **API-6 · MUST · wire formats are explicit and stable.** Structs serialised to the vault JSON (§4.2), exports (§7), the agent protocol and the config carry explicit field tags, or are written by a custom marshaler with explicit key names (`internal/model` does this to keep unknown keys and key order); unknown vault fields survive a save; config parsing rejects unknown keys (§3.3); renaming a Go field never changes a format; a format change bumps the version the spec defines.
  - Why: other passh versions and other tools read these files.
  - Check: `internal/model` round-trip tests with unknown fields; review tags and marshaler key strings in diffs.
  - Source: Uber [use field tags in marshaled structs](https://github.com/uber-go/guide/blob/master/style.md#use-field-tags-in-marshaled-structs); spec §3.3, §4.2.

- **API-7 · SHOULD · copy at boundaries.** Methods that return internal slices or maps (entries, tags, fields) return copies (`slices.Clone`, `maps.Clone`), and constructors copy what they keep.
  - Why: a caller must not change the vault behind its back.
  - Check: review exported getters that return slices or maps.
  - Source: Uber [copy slices and maps at boundaries](https://github.com/uber-go/guide/blob/master/style.md#copy-slices-and-maps-at-boundaries).

- **API-8 · SHOULD · useful zero values or a guarding constructor.** Either the zero value works and the doc says so, or the type can only be built by its constructor (`paths.Path` only through `paths.Parse`). Enums start at 1 unless zero is the intended default. Names don't stutter: `vault.Open`, not `vault.OpenVault`.
  - Why: invalid values should be unrepresentable.
  - Check: review new exported types.
  - Source: EG [allocation with new](https://go.dev/doc/effective_go#allocation_new); Uber [start enums at one](https://github.com/uber-go/guide/blob/master/style.md#start-enums-at-one); GSG [repetition](https://google.github.io/styleguide/go/decisions#repetition); spec §10.3.

- **API-9 · SHOULD · the standard library and current Go first.** Prefer `slices`, `maps`, `min`/`max`, `clear`, `strings.Cut`, `errors.Join`, `errors.AsType`, `os.Root`, `t.Context`/`t.Chdir`, `sync.WaitGroup.Go`, `testing/synctest` over hand-written equivalents or new dependencies. Nothing newer than `go.mod`'s `go 1.26.0`.
  - Why: less code, and no new dependency (TOOL-5).
  - Check: `go fix -diff ./...` lists modernizer suggestions without changing files; review and apply them in a separate change.
  - Source: [Go 1.26 release notes](https://go.dev/doc/go1.26) (`go fix` modernizers, `errors.AsType`).

## 8. Docs and naming (DOC)

- **DOC-1 · MUST · every package has one package comment.** `// Package x …` in exactly one file (`// Command passh …` for `cmd/passh`), saying what the package does and which spec sections or rules it implements.
  - Why: it is the entry point for a reader and for `go doc`.
  - Check: `.tools/bin/staticcheck -checks ST1000 ./...` is clean.
  - Source: [Go Doc Comments](https://go.dev/doc/comment#package); CRC [Package Comments](https://go.dev/wiki/CodeReviewComments#package-comments).

- **DOC-2 · MUST · every exported name has a doc comment.** A full sentence that starts with the name (`ErrDisabled means …`, not `ErrDisabled: …`); non-trivial unexported names too. Inside grouped declarations (`var (…)`, `const (…)`), each documented name gets a proper sentence as well (`// Served means …`), not a `Name: …` label.
  - Why: `go doc` and reviewers read these first.
  - Check: `.tools/bin/staticcheck -checks ST1020,ST1021,ST1022 ./...` is clean. staticcheck accepts `Name: …` and skips grouped declarations, so also run this; it prints each `// Name: …` comment that documents `Name` at top level or in a `var (…)`/`const (…)` group, and prints nothing when the code complies:

    ```bash
    awk 'FNR==1{g=0} /^(var|const) \($/{g=1} /^\)$/{g=0}
         match($0,/^[[:space:]]*\/\/ [A-Z][A-Za-z0-9]*:/){n=substr($0,RSTART,RLENGTH);top=($0~/^\/\//);sub(/^[[:space:]]*\/\/ /,"",n);sub(/:$/,"",n);name=(g||top)?n:"";at=FILENAME":"FNR":"$0;next}
         /^[[:space:]]*\/\//{next} {if(name!=""&&$0~("(^|[^A-Za-z0-9_])"name"([^A-Za-z0-9_]|$)"))print at;name=""}' \
        $(find internal cmd -name '*.go' ! -name '*_test.go')
    ```
  - Source: [Go Doc Comments](https://go.dev/doc/comment); CRC [Doc Comments](https://go.dev/wiki/CodeReviewComments#doc-comments).

- **DOC-3 · SHOULD · doc comment syntax (Go 1.19+).** `[pkg.Name]` doc links, `# Heading`, lists indented with `-`, code blocks indented, `Deprecated:` paragraphs; let gofmt reformat them; no indented prose (it becomes a code block).
  - Why: renders correctly in `go doc` and pkgsite.
  - Check: `gofmt -l` clean; read `go doc ./internal/<pkg>` for changed packages.
  - Source: [Go Doc Comments](https://go.dev/doc/comment).

- **DOC-4 · SHOULD · document what callers must know.** Concurrency safety (when not "one goroutine at a time"), cleanup duties (`Close`, `Stop`, wipe the result), the sentinels and types returned, and context behaviour beyond returning `ctx.Err()`.
  - Why: those are the mistakes a caller can't see from the signature.
  - Check: review doc comments of new exported functions and types.
  - Source: GSG [documentation conventions](https://google.github.io/styleguide/go/best-practices#documentation-conventions); [Go Doc Comments: types](https://go.dev/doc/comment#type).

- **DOC-5 · SHOULD · comments say why and cite the spec.** Code that implements a spec rule references it (`// S4:`, `// §4.6 step 5`); comments explain non-obvious decisions, not what the next line does; no commented-out code.
  - Why: the reviewer traces safety rules from spec to code.
  - Check: `grep -rnE '// *(S[1-9]|§[0-9])' --include='*.go' internal | wc -l` grows with spec-driven code; review.
  - Source: `IMPLEMENTATION.md`; [Go Doc Comments: notes](https://go.dev/doc/comment#notes).

- **DOC-6 · MUST · Go naming.** MixedCaps, no underscores (test function names excepted); initialisms in one case (`ID`, `URL`, `TTY`, `TTL`, `PDF`, `QR`, `JSON`, `OSC`: `vaultID`, `ServeHTTP`); no `Get` prefix on getters; receivers one or two letters, the same for all methods of a type, never `this`/`self`; error variables `ErrX`/`errX`, error types `XError`; short lowercase package names, no `util`/`common`/`helpers`.
  - Why: readers recognise standard Go immediately.
  - Check: `.tools/bin/staticcheck -checks ST1003,ST1006,ST1012,ST1016 ./...` is clean.
  - Source: EG [names](https://go.dev/doc/effective_go#names); CRC [Initialisms](https://go.dev/wiki/CodeReviewComments#initialisms), [Receiver Names](https://go.dev/wiki/CodeReviewComments#receiver-names), [Package Names](https://go.dev/wiki/CodeReviewComments#package-names); GSG [naming](https://google.github.io/styleguide/go/decisions#naming).

## 9. Testing (TEST)

- **TEST-1 · MUST · isolate every test from the user's files.** Any test that runs code which could touch config, vault, state, agent, gpg, pass store, editor or clipboard points `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, `XDG_RUNTIME_DIR`, `TMPDIR`, `PASSH_CONFIG`, `PASSWORD_STORE_DIR` and `GNUPGHOME` into a temporary folder, using the package's existing helper (`isolate`, `TestMain`, the black-box harness env). Never read or write the real `~/.gnupg`, `~/.password-store`, `~/.config/passh`, `~/.local/state/passh`.
  - Why: a test must never touch a real vault, agent or keyring.
  - Check: the [fake-HOME run](#checks) leaves the fake HOME empty; new test files use the package helper.
  - Source: `IMPLEMENTATION.md` ("Test isolation").

- **TEST-2 · MUST · process-wide state and `t.Parallel` don't mix.** Tests that call `t.Setenv`/`t.Chdir` or change package variables (test hooks, `scryptWorkFactor`, `minTTL`) never call `t.Parallel` and have no parallel parent (`t.Setenv` panics there). In test functions use `t.Setenv`, not `os.Setenv` (to unset: `t.Setenv(k, "")` then `os.Unsetenv(k)`); `os.Setenv` only in `TestMain`. Production code never changes its own environment.
  - Why: parallel tests sharing process state are flaky and order-dependent.
  - Check: `golangci-lint run` (usetesting `os-setenv`, forbidigo); `grep -rl 't.Parallel()' --include='*_test.go' . | xargs grep -ln 't.Setenv\|t.Chdir\|testHook =\|WorkFactor =\|minTTL ='` — review each file listed.
  - Source: [testing.T.Setenv](https://pkg.go.dev/testing#T.Setenv), [T.Chdir](https://pkg.go.dev/testing#T.Chdir); GSG [global state](https://google.github.io/styleguide/go/best-practices#global-state).

- **TEST-3 · MUST · temporary files through `t.TempDir()`.** `os.MkdirTemp` only in `TestMain` (no `t`) or where the parent must be a specific filesystem or short path (`/dev/shm` for tmpfs, `/tmp` for socket path limits), with removal in `t.Cleanup` or at the end of `TestMain`.
  - Why: auto-removed and unique per test.
  - Check: `golangci-lint run` (usetesting; the allowed cases are excluded in `.golangci.yml`).
  - Source: [testing.T.TempDir](https://pkg.go.dev/testing#T.TempDir).

- **TEST-4 · MUST · stop and reap what a test starts.** Agents, passh binaries, gpg-agent, HTTP servers, pseudo-terminals and goroutines are stopped and waited for in `t.Cleanup` or `defer`, also when the test fails.
  - Why: a leftover agent holds a key and a socket; leftover processes make later tests flaky.
  - Check: after any test run, `pgrep -af '[_]_agent'` prints nothing.
  - Source: [testing.T.Cleanup](https://pkg.go.dev/testing#T.Cleanup); Uber [wait for goroutines to exit](https://github.com/uber-go/guide/blob/master/style.md#wait-for-goroutines-to-exit).

- **TEST-5 · MUST · helpers and goroutines.** Helpers take `t *testing.T` (or `testing.TB`) first and call `t.Helper()`; setup failures use `t.Fatal`. `t.Fatal`/`FailNow`/`Skip` only from the test's own goroutine: other goroutines use `t.Error` and return, or send the error on a channel.
  - Why: failures then point at the caller, and `FailNow` from another goroutine doesn't stop the test.
  - Check: `go vet` (testinggoroutine); review helpers without `t.Helper()`: `grep -rn 'func [a-z][A-Za-z]*(t \*testing\.T' --include='*_test.go' . | head` and look for `t.Helper()` in each.
  - Source: GSG [mark test helpers](https://google.github.io/styleguide/go/decisions#mark-test-helpers), [don't call t.Fatal from separate goroutines](https://google.github.io/styleguide/go/best-practices#t-fatal-goroutine); [testing](https://pkg.go.dev/testing).

- **TEST-6 · SHOULD · readable tests.** Table-driven tests with named fields and `t.Run(tc.name, …)` when cases differ only in data. Failures say function, input, got and want, in that order: `Parse(%q) = %v, want %v`; `t.Error` to keep going on independent checks, `t.Fatal` when later checks can't run. Compare parsed values, not serialized strings; no assertion libraries.
  - Why: a failure should explain itself without a debugger.
  - Check: review.
  - Source: CRC [Useful Test Failures](https://go.dev/wiki/CodeReviewComments#useful-test-failures); GSG [table-driven tests](https://google.github.io/styleguide/go/decisions#table-driven-tests), [got before want](https://google.github.io/styleguide/go/decisions#got-before-want).

- **TEST-7 · MUST · no sleep as synchronisation.** Never wait for a goroutine or process by sleeping a fixed time and hoping it got there. Allowed: polling a condition with a deadline (the harnesses' `waitFor`; the short sleep inside the loop is fine), channels, and `testing/synctest` for timer logic with no real I/O. Where synctest can't apply (real sockets, pipes, signals, child processes: the agent, clipboard command, editor and black-box tests), make the time-dependent code take an injected clock or short configurable durations (CONC-8) instead of sleeping past real TTLs. A fixed `time.Sleep` outside a polling loop is allowed only to let wall-clock time pass for behaviour under test that can't take a clock, with a comment saying so.
  - Why: sleeps are both slow and flaky under `-race` or on a loaded CI machine.
  - Check: `grep -rn 'time\.Sleep' --include='*_test.go' internal cmd test` — each hit is inside a polling loop with a deadline, or carries the comment.
  - Source: [testing/synctest](https://pkg.go.dev/testing/synctest) (bubbles exclude real I/O, syscalls and external processes).

- **TEST-8 · MUST · terminals are pseudo-terminals.** Tests that need a terminal open one with `github.com/creack/pty`; they never use the developer's `/dev/tty`, and the suite passes with no controlling terminal.
  - Why: prompts read `/dev/tty`; a test using the real one would hang or type into the developer's shell.
  - Check: `setsid -w go test -count=1 ./internal/... ./cmd/... </dev/null` passes.
  - Source: `IMPLEMENTATION.md`.

- **TEST-9 · MUST · external tools are optional.** Tests that need gpg, the stock age CLI (`.tools/bin/age`), strace, `/dev/shm`, a private LAN address or Chromium skip with a message naming what's missing; they never install anything or use the system gpg home.
  - Why: the suite must run on a fresh machine and in CI.
  - Check: `grep -rn 't.Skip' --include='*_test.go' . | head`; run once with `.tools/bin` absent from the environment.
  - Source: `IMPLEMENTATION.md`; [testing.T.Skip](https://pkg.go.dev/testing#T.Skip).

- **TEST-10 · MUST · black-box tests stay black-box.** `cmd/passh` and `test/acceptance` tests drive the built binary and inspect files with `filippo.io/age` or the stock age CLI; `test/acceptance` imports no `internal/` package. A product bug found there stays as `t.Skip("BUG: …")` plus a report, not a deleted test.
  - Why: they check the product as a user sees it, independently of its internals.
  - Check: `go list -f '{{join .TestImports "\n"}}' ./test/acceptance | grep internal/`.
  - Source: `test/acceptance/harness_test.go` package doc; spec §13.

- **TEST-11 · MUST · regression tests and safety coverage.** Every bug fix comes with a test that fails without it. Each of S1–S9 and each §13 acceptance criterion keeps at least one test; don't delete or weaken one without the owner.
  - Why: the safety rules are the product.
  - Check: `grep -rn 'S[1-9]' --include='*_test.go' internal test | cut -d: -f1 | sort -u`; the acceptance tests are named after the criteria (`TestS1_…`, `TestF9_…`).
  - Source: spec §13; `IMPLEMENTATION.md`.

- **TEST-12 · SHOULD · fuzz the parsers.** Untrusted-input parsers have fuzz tests: `vaultfile` (exists), `entrytext`, `paths`, `config`, the agent protocol, `importpass`, `sanitize` (invariants such as `IsSafe(Line(s))`). Seeds via `f.Add` and committed `testdata/fuzz/FuzzX/` files; targets fast, deterministic, with no global state.
  - Why: these parsers face hostile files and peers.
  - Check: `go test -run='^$' -fuzz='^FuzzParse$' -fuzztime=60s ./internal/vaultfile` (one fuzz target per run); `go test` replays the corpus.
  - Source: [Go Fuzzing](https://go.dev/doc/security/fuzz/); [Go security best practices](https://go.dev/doc/security/best-practices).

- **TEST-13 · MUST · hermetic and order-independent.** No test depends on files, environment, agents or package state left by another test.
  - Why: filtering, shuffling and `-count` must not change results.
  - Check: `go test -count=1 -shuffle=on ./internal/... ./cmd/...` passes.
  - Source: GSG [keep setup code scoped](https://google.github.io/styleguide/go/best-practices#t-common-setup-scope).

## 10. Tooling and dependencies (TOOL)

- **TOOL-1 · MUST · gofmt.** All Go files are gofmt-formatted.
  - Check: `test -z "$(gofmt -l cmd internal test)"` (also in `.github/workflows/release.yml`).
  - Source: CRC [Gofmt](https://go.dev/wiki/CodeReviewComments#gofmt); EG [formatting](https://go.dev/doc/effective_go#formatting).

- **TOOL-2 · MUST · `go vet` is clean, on every OS.** `go vet ./...`, plus `GOOS=darwin GOARCH=arm64 go vet ./...` for the `_darwin.go` files.
  - Check: both commands print nothing.
  - Source: [Go security best practices](https://go.dev/doc/security/best-practices).

- **TOOL-3 · MUST · staticcheck is clean.** Default checks plus the doc checks of DOC-1/DOC-2.
  - Check: `.tools/bin/staticcheck -checks 'inherit,ST1000,ST1020,ST1021,ST1022' ./...` prints nothing.
  - Source: [Staticcheck](https://staticcheck.dev/docs/).

- **TOOL-4 · SHOULD · golangci-lint is clean with the repository config.** `.golangci.yml` enables only linters that enforce a rule here (each line names its rule). `//nolint` names the linter and gives a reason (`//nolint:gosec // a magic number, not a size`); nolintlint enforces both. Expected suppressions: gosec G118 on `go s.run(ctx)` in `internal/printweb/server.go` (the server's own ctx is passed; G118 misreads it as request-scoped), gosec G203 where `template.HTML` wraps text already escaped with `template.HTMLEscapeString` (SEC-5), gosec G115 on `statfs` magic-number conversions, errorlint in identity tests (ERR-3).
  - Check: `.tools/bin/golangci-lint run ./...`; `grep -rn 'nolint:' --include='*.go' . | grep -v '// '` prints nothing (every suppression has a reason).
  - Source: [golangci-lint configuration](https://golangci-lint.run/docs/configuration/file/).

- **TOOL-5 · MUST · dependencies are frozen.** No `go get`, `go mod tidy`, `go mod edit`, `-mod=mod`, new modules or version bumps without the owner's approval: report the need instead. A proposed dependency comes with what it does, why the standard library won't do, its size, license, maintenance and `govulncheck` result.
  - Why: several agents share this module, and every dependency is attack surface for a password manager.
  - Check: `git diff --exit-code go.mod go.sum`.
  - Source: `IMPLEMENTATION.md`; [Go security best practices](https://go.dev/doc/security/best-practices) (review every dependency update).

- **TOOL-6 · MUST · static builds for all release targets.** `CGO_ENABLED=0`, `-trimpath`; linux/amd64, linux/arm64, linux/arm (`GOARM=7`), darwin/amd64 and darwin/arm64 all build. Platform code lives in `_linux.go`/`_darwin.go` files plus an `_other.go` with `//go:build !linux && !darwin`, with the same functions on every OS. `.goreleaser.yaml` and the release workflow change only with approval.
  - Why: one static binary per platform is the product (spec §2 G1).
  - Check: the cross-build loop in `AGENTS.md`.
  - Source: spec §2 G1, §10.1; [build constraints](https://pkg.go.dev/cmd/go#hdr-Build_constraints).

- **TOOL-7 · MUST · tools stay in the project.** Developer tools are installed with pinned versions into `.tools/bin` (`GOBIN=$PWD/.tools/bin go install <pkg>@<version>`), never system-wide or with sudo.
  - Why: the machine is shared with the owner's real setup.
  - Check: commands in `AGENTS.md` use `.tools/bin/…`.
  - Source: `IMPLEMENTATION.md`.

---

## Checks

The full set, in rough order of cost (times on the development machine):

```bash
export PATH=$HOME/.local/go/bin:$PATH
test -z "$(gofmt -l cmd internal test)"                          # TOOL-1
go vet ./... && GOOS=darwin GOARCH=arm64 go vet ./...            # TOOL-2
.tools/bin/staticcheck -checks 'inherit,ST1000,ST1020,ST1021,ST1022' ./...   # TOOL-3, DOC-1, DOC-2
.tools/bin/golangci-lint run ./...                               # TOOL-4 and the rules its linters cite
.tools/bin/govulncheck ./...                                     # SEC-9
git diff --exit-code go.mod go.sum                               # TOOL-5
go test -count=1 -shuffle=on ./internal/... ./cmd/...            # TEST-13 (~30 s)
go test -race -count=1 ./internal/... ./cmd/...                  # CONC-5 (~1–2 min)
go test -count=1 ./test/acceptance/...                           # spec §13 (~4–5 min)
pgrep -af '[_]_agent'                                            # TEST-4: prints nothing
```

Fake-HOME run (TEST-1, INV-13): run the tests with the outer locations pointing at an empty folder; a test that forgets to isolate writes there. Go's own telemetry (`.config/go`) is expected.

```bash
H=$(mktemp -d)
env -u XDG_CONFIG_HOME -u XDG_DATA_HOME -u XDG_STATE_HOME -u XDG_RUNTIME_DIR \
    -u PASSH_CONFIG -u PASSWORD_STORE_DIR -u GNUPGHOME \
    HOME=$H GOPATH="$(go env GOPATH)" GOCACHE="$(go env GOCACHE)" GOMODCACHE="$(go env GOMODCACHE)" \
    go test -count=1 ./internal/... ./cmd/...
find $H -mindepth 1 -not -path "$H/.config" -not -path "$H/.config/go*"   # prints nothing
rm -rf $H
```

## Baseline (before the 2026-11-15 refactor)

State when these rules were adopted, before the first refactor, for the first review. Remove this section once the findings are resolved.

- gofmt, `go vet` (linux and darwin), all five cross-builds: clean. Tests: unit, CLI, acceptance, `-race` (internal) and `-shuffle=on` pass; the fake-HOME run is clean; no agent left behind.
- govulncheck v1.9.0: 0 called vulnerabilities. Module-level only (not called): GO-2026-6355 and GO-2026-6354 (`golang.org/x/crypto/ssh` DoS, fixed in x/crypto v0.56.0) and GO-2026-5932 (`x/crypto/openpgp`, unmaintained). Bumping `golang.org/x/crypto` needs the owner (TOOL-5).
- staticcheck v0.8.2 (`-checks 'inherit,ST1000,ST1020,ST1021,ST1022'`): 18 findings. Production: `internal/editor` has no package comment (DOC-1); `ErrDisabled` doc form in `internal/printweb/server.go:63` (DOC-2); unused `joinLines` in `internal/cli/cli.go:295`; S1011 in `internal/tui/view.go:359`. Tests: `runtime.GOROOT` deprecated (`cmd/passh/harness_test.go:109`, `test/acceptance/harness_test.go:96`), unused `splitTags`, an ineffective assignment (`test/acceptance/safety_input_test.go:95`), a nil Context (`internal/session/session_test.go:209`), raw U+200B/U+202E in string literals.
- golangci-lint v2.15.0 with `.golangci.yml`: 41 findings, 26 in production code: errcheck 12 (`os.Remove` best-effort cleanups, `t.close()` in `internal/vault`, `stdin.Close` in `internal/agent/start.go`), nilerr `internal/cli/printcmd.go:371` (a `YesNo` error turned into "no"), gosec G203 ×2 `internal/printweb/page.go` (check the escaping, then `//nolint` with the reason), G118 `internal/printweb/server.go:267` (a false positive: expected `//nolint`, TOOL-4), G115 `internal/editor/tmpfs_linux.go:16` (same case as the existing `//nolint` in `internal/cli/sys_linux.go`), plus the staticcheck items above.
- Known MUST violations found by review: ERR-4 in `internal/cli/copy.go:70` and `internal/cli/doctor.go:371`: `errors.Is(err, clipboard.ErrInterrupted) && !strings.Contains(err.Error(), "failed")` decides whether the clipboard was cleared after Ctrl-C (S6), so a wording change in `internal/clipboard` would make `copy` report "Clipboard cleared." when it wasn't; `internal/clipboard` should expose a sentinel or typed error for "clearing failed". DOC-1 (`internal/editor`); DOC-2 (`ErrDisabled`, and about 40 `// Name: …` comments in grouped declarations that its label check finds). SHOULD deviations: ERR-10 (`os.Exit` in the hidden `__agent` command, `internal/cli/cli.go:263`), CONC-2 (`context.Background()` in `internal/cli/doctor.go:284,369` where `cmd.Context()` is available); TEST-7 needs a pass over the ~70 `time.Sleep` calls in tests.

## Sources

| Short name | URL |
|---|---|
| Effective Go | https://go.dev/doc/effective_go |
| Go Code Review Comments | https://go.dev/wiki/CodeReviewComments |
| Google Go Style Guide (guide, decisions, best practices) | https://google.github.io/styleguide/go/guide · https://google.github.io/styleguide/go/decisions · https://google.github.io/styleguide/go/best-practices |
| Uber Go Style Guide | https://github.com/uber-go/guide/blob/master/style.md |
| Go Security Best Practices | https://go.dev/doc/security/best-practices |
| Go Vulnerability Management | https://go.dev/doc/security/vuln/ |
| Go Fuzzing | https://go.dev/doc/security/fuzz/ |
| Data Race Detector | https://go.dev/doc/articles/race_detector |
| Organizing a Go module | https://go.dev/doc/modules/layout |
| Go Doc Comments | https://go.dev/doc/comment |
| Working with Errors in Go 1.13 | https://go.dev/blog/go1.13-errors |
| Traversal-resistant file APIs (os.Root) | https://go.dev/blog/osroot |
| Go 1.26 release notes | https://go.dev/doc/go1.26 |
| Package docs: testing, testing/synctest, os, os/exec, os/signal, context, errors, crypto/rand, crypto/subtle, html/template | https://pkg.go.dev/testing · https://pkg.go.dev/testing/synctest · https://pkg.go.dev/os · https://pkg.go.dev/os/exec · https://pkg.go.dev/os/signal · https://pkg.go.dev/context · https://pkg.go.dev/errors · https://pkg.go.dev/crypto/rand · https://pkg.go.dev/crypto/subtle · https://pkg.go.dev/html/template |
| Staticcheck | https://staticcheck.dev/docs/ |
| golangci-lint | https://golangci-lint.run/docs/configuration/file/ · https://golangci-lint.run/docs/linters/ |
| gosec rules | https://github.com/securego/gosec/blob/master/RULES.md |
| Project | `spec.md` (§3.2, §4, §5.5 S1–S9, §6, §7, §10, §13), `IMPLEMENTATION.md` |
