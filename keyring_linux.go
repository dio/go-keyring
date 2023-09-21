package keyring

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

// PASS_FOLDER contains the directory where credentials are stored.
const PASS_FOLDER = "docker-credential-helpers" //nolint:revive

type linuxPass struct{}

var (
	// initializationMutex is held while initializing so that only one 'pass'
	// round-tripping is done to check pass is functioning.
	initializationMutex sync.Mutex
	passInitialized     bool
)

// CheckInitialized checks whether the password helper can be used. It
// internally caches and so may be safely called multiple times with no impact
// on performance, though the first call may take longer.
func (p linuxPass) CheckInitialized() bool {
	return p.checkInitialized() == nil
}

func (p linuxPass) checkInitialized() error {
	initializationMutex.Lock()
	defer initializationMutex.Unlock()
	if passInitialized {
		return nil
	}
	// We just run a `pass ls`, if it fails then pass is not initialized.
	_, err := p.runPassHelper("", "ls")
	if err != nil {
		return fmt.Errorf("pass not initialized: %v", err)
	}
	passInitialized = true
	return nil
}

func (p linuxPass) runPass(stdinContent string, args ...string) (string, error) {
	if err := p.checkInitialized(); err != nil {
		return "", err
	}
	return p.runPassHelper(stdinContent, args...)
}

func (p linuxPass) runPassHelper(stdinContent string, args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("pass", args...)
	cmd.Stdin = strings.NewReader(stdinContent)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("%s: %s", err, stderr.String())
	}

	// trim newlines; pass v1.7.1+ includes a newline at the end of `show` output
	return strings.TrimRight(stdout.String(), "\n\r"), nil
}

// Get password from macos keyring given service and user name.
func (p linuxPass) Get(service, username string) (string, error) {
	encoded := base64.URLEncoding.EncodeToString([]byte(service))

	if _, err := os.Stat(path.Join(getPassDir(), PASS_FOLDER, encoded)); err != nil {
		if os.IsNotExist(err) {
			return "", errors.New("not found")
		}

		return "", err
	}

	usernames, err := listPassDir(encoded)
	if err != nil {
		return "", err
	}

	if len(usernames) < 1 {
		return "", fmt.Errorf("no usernames for %s", service)
	}

	actual := strings.TrimSuffix(usernames[0].Name(), ".gpg")
	secret, err := p.runPass("", "show", path.Join(PASS_FOLDER, encoded, actual))
	return secret, err
}

// Set stores a secret in the macos keyring given a service name and a user.
func (p linuxPass) Set(service, username, password string) error {
	encoded := base64.URLEncoding.EncodeToString([]byte(service))
	_, err := p.runPass(password, "insert", "-f", "-m", path.Join(PASS_FOLDER, encoded, username))
	return err
}

// Delete deletes a secret, identified by service & user, from the keyring.
func (p linuxPass) Delete(service, username string) error {
	encoded := base64.URLEncoding.EncodeToString([]byte(service))
	_, err := p.runPass("", "rm", "-rf", path.Join(PASS_FOLDER, encoded))
	return err
}

func init() {
	provider = linuxPass{}
}

func getPassDir() string {
	if passDir := os.Getenv("PASSWORD_STORE_DIR"); passDir != "" {
		return passDir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".password-store")
}

func listPassDir(args ...string) ([]os.FileInfo, error) {
	passDir := getPassDir()
	p := path.Join(append([]string{passDir, PASS_FOLDER}, args...)...)
	entries, err := os.ReadDir(p)
	if err != nil {
		if os.IsNotExist(err) {
			return []os.FileInfo{}, nil
		}
		return nil, err
	}
	infos := make([]fs.FileInfo, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}
	return infos, nil
}
