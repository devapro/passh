package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// MaxSocketPathLen is the longest Unix socket path passh uses, in bytes.
// sun_path holds 104 bytes on macOS and 108 on Linux, including the
// terminating NUL; passh keeps to the smaller limit everywhere, so the same
// state folder gives the same socket path on both systems.
const MaxSocketPathLen = 103

// getuid is a variable so tests can pretend a folder belongs to someone
// else.
var getuid = os.Getuid

// lastTmp is the last fallback for the agent folder. Tests point it at a
// temporary folder so they never touch the real /tmp.
var lastTmp = "/tmp"

// AgentDir returns the folder that holds the agent's socket named
// socketName (§3.2, §5.3): <StateDir>/agent, or, when the socket's path
// there would be longer than MaxSocketPathLen, passh-<uid> in $TMPDIR (if
// it is set to an absolute path and short enough) or in /tmp. The agent
// folder isn't put in $XDG_RUNTIME_DIR: the system removes that folder when
// the user's last session ends, and the agent must outlive the SSH session
// that started it.
//
// Nothing is created or checked here; EnsureAgentDir does that, and
// CheckAgentDir checks a folder that should already exist.
func AgentDir(socketName string) (string, error) {
	if socketName == "" || socketName == "." || socketName == ".." || strings.ContainsAny(socketName, "/\x00") {
		return "", fmt.Errorf("invalid socket name %q", socketName)
	}
	fits := func(dir string) bool {
		return len(filepath.Join(dir, socketName)) <= MaxSocketPathLen
	}
	state, err := StateDir()
	if err != nil {
		return "", err
	}
	if dir := filepath.Join(state, "agent"); fits(dir) {
		return dir, nil
	}
	sub := fmt.Sprintf("passh-%d", getuid())
	if tmp := os.Getenv("TMPDIR"); tmp != "" && filepath.IsAbs(tmp) {
		if dir := filepath.Join(tmp, sub); fits(dir) {
			return dir, nil
		}
	}
	if dir := filepath.Join(lastTmp, sub); fits(dir) {
		return dir, nil
	}
	return "", fmt.Errorf("the agent's socket path is longer than %d bytes even in %s", MaxSocketPathLen, lastTmp)
}

// EnsureStateDir creates the state folder (StateDir) and its missing
// parents. A state folder it creates gets mode 0700 exactly, whatever the
// umask. An existing one is left as it is. It returns the folder's path.
func EnsureStateDir() (string, error) {
	dir, err := StateDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return "", fmt.Errorf("creating the state folder: %w", err)
	}
	if err := mkdirPrivate(dir); err != nil {
		return "", fmt.Errorf("creating the state folder: %w", err)
	}
	return dir, nil
}

// EnsureAgentDir returns the agent folder for socketName (AgentDir), after
// creating it with mode 0700 if it doesn't exist and checking it with
// CheckAgentDir. For the folder in the state folder, the state folder is
// created too (EnsureStateDir); for the fallback folder, $TMPDIR or /tmp
// must exist.
//
// A folder that fails the checks is refused, not fixed: in a shared /tmp
// someone else may have created passh-<uid> first, and passh can't tell what
// was put in a folder with a wrong mode meanwhile.
func EnsureAgentDir(socketName string) (string, error) {
	dir, err := AgentDir(socketName)
	if err != nil {
		return "", err
	}
	if state, err := StateDir(); err == nil && filepath.Dir(dir) == state {
		if _, err := EnsureStateDir(); err != nil {
			return "", err
		}
	}
	if err := mkdirPrivate(dir); err != nil {
		return "", fmt.Errorf("creating the agent folder: %w", err)
	}
	if err := CheckAgentDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// CheckAgentDir checks that dir is a real directory (not a symlink) that
// belongs to the current user and has mode 0700 exactly. The checks run on a
// handle opened with O_NOFOLLOW. A missing folder gives an error that
// satisfies errors.Is(err, fs.ErrNotExist).
func CheckAgentDir(dir string) error {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return fmt.Errorf("agent folder %s is not a directory (a symlink or a file); refusing to use it", dir)
		}
		return fmt.Errorf("opening the agent folder %s: %w", dir, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("checking the agent folder %s: %w", dir, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("agent folder %s is not a directory; refusing to use it", dir)
	}
	if uid := getuid(); int(st.Uid) != uid {
		return fmt.Errorf("agent folder %s belongs to uid %d, not to you (uid %d); refusing to use it", dir, st.Uid, uid)
	}
	if perm := uint32(st.Mode) & 0o7777; perm != 0o700 {
		return fmt.Errorf("agent folder %s has mode %04o, not 0700; refusing to use it (fix it with chmod 700, or remove it)", dir, perm)
	}
	return nil
}

// mkdirPrivate creates dir with mode 0700 exactly, whatever the umask. An
// existing dir is not an error and is left unchanged.
func mkdirPrivate(dir string) error {
	err := os.Mkdir(dir, 0o700)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	// Mkdir's mode is reduced by the umask; set it exactly. Someone else
	// can't replace the new folder in between (its parent is ours, or a
	// sticky /tmp), and CheckAgentDir checks an O_NOFOLLOW handle anyway.
	return os.Chmod(dir, 0o700)
}
