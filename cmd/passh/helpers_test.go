package main

// Helper programs: passh runs the test binary as its clipboard command and
// as $EDITOR, with helperEnv saying which.

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const (
	helperEnv = "PASSH_TEST_HELPER" // "clipboard" or "editor"
	// clipLogEnv: the fake clipboard command appends each value it gets,
	// %q-quoted, one per line.
	clipLogEnv = "PASSH_TEST_CLIPLOG"
	// editLogEnv: the fake editor appends what it found in the file, %q,
	// one line per run.
	editLogEnv = "PASSH_TEST_EDITLOG"
	// editTextsEnv: what the fake editor writes into the file, one text
	// per run, separated by textSep; "" (or no text for this run) keeps it.
	editTextsEnv = "PASSH_TEST_EDITTEXTS"
	// editRunEnv: a passh command (words separated by textSep) the fake
	// editor runs before it exits, e.g. to change the vault meanwhile.
	editRunEnv = "PASSH_TEST_EDITRUN"
	// binEnv is the passh binary, for editRunEnv.
	binEnv = "PASSH_TEST_BIN"
)

const textSep = "\x1e"

func runHelper(name string) int {
	switch name {
	case "clipboard":
		return fakeClipboard()
	case "editor":
		return fakeEditor()
	}
	return 99
}

func appendLine(path, s string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%q\n", s)
	return err
}

func fakeClipboard() int {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(os.Stdin); err != nil {
		return 1
	}
	if err := appendLine(os.Getenv(clipLogEnv), buf.String()); err != nil {
		return 2
	}
	return 0
}

func fakeEditor() int {
	if len(os.Args) < 2 {
		return 90
	}
	file := os.Args[len(os.Args)-1]
	before, err := os.ReadFile(file)
	if err != nil {
		return 91
	}
	logPath := os.Getenv(editLogEnv)
	runs := 0
	if b, err := os.ReadFile(logPath); err == nil {
		runs = bytes.Count(b, []byte("\n"))
	}
	if err := appendLine(logPath, string(before)); err != nil {
		return 92
	}
	if texts := strings.Split(os.Getenv(editTextsEnv), textSep); runs < len(texts) && texts[runs] != "" {
		// In place, as an editor with nowritebackup does.
		if err := os.WriteFile(file, []byte(texts[runs]), 0); err != nil {
			return 93
		}
	}
	if run := os.Getenv(editRunEnv); run != "" && runs == 0 {
		cmd := exec.Command(os.Getenv(binEnv), strings.Split(run, textSep)...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // no terminal: the agent's key
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "helper: passh %s: %v: %s", run, err, out)
			return 94
		}
	}
	return 0
}
