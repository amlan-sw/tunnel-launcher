package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// hostKeyEnforcer implements TOFU against a known_hosts file in the app's
// config directory. Unknown hosts are auto-trusted on first sight; mismatched
// hosts trigger a popup and the connection is aborted.
type hostKeyEnforcer struct {
	mu      sync.Mutex
	path    string
	prompts CredentialPrompts
}

func newHostKeyEnforcer(prompts CredentialPrompts) (*hostKeyEnforcer, error) {
	path := knownHostsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		f.Close()
	}
	return &hostKeyEnforcer{path: path, prompts: prompts}, nil
}

// Callback returns an ssh.HostKeyCallback bound to this enforcer.
func (h *hostKeyEnforcer) Callback() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		h.mu.Lock()
		defer h.mu.Unlock()

		check, err := knownhosts.New(h.path)
		if err != nil {
			return fmt.Errorf("known_hosts: %v", err)
		}
		kerr := check(hostname, remote, key)
		if kerr == nil {
			return nil
		}
		var ke *knownhosts.KeyError
		if !errors.As(kerr, &ke) {
			return kerr
		}
		if len(ke.Want) == 0 {
			return h.appendLine(hostname, remote, key)
		}
		oldFp := ssh.FingerprintSHA256(ke.Want[0].Key)
		newFp := ssh.FingerprintSHA256(key)
		if h.prompts != nil {
			h.prompts.HostKeyMismatch(hostname, oldFp, newFp)
		}
		return &hostKeyMismatchError{host: hostname, oldFp: oldFp, newFp: newFp}
	}
}

type hostKeyMismatchError struct {
	host         string
	oldFp, newFp string
}

func (e *hostKeyMismatchError) Error() string {
	return fmt.Sprintf("host key mismatch for %s (offered %s, trusted %s)",
		e.host, e.newFp, e.oldFp)
}

func isHostKeyMismatch(err error) bool {
	var e *hostKeyMismatchError
	return errors.As(err, &e)
}

func (h *hostKeyEnforcer) appendLine(hostname string, remote net.Addr, key ssh.PublicKey) error {
	addrs := []string{knownhosts.Normalize(hostname)}
	if remote != nil {
		if ra := knownhosts.Normalize(remote.String()); ra != addrs[0] {
			addrs = append(addrs, ra)
		}
	}
	line := knownhosts.Line(addrs, key)
	f, err := os.OpenFile(h.path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		return err
	}
	return nil
}

func knownHostsPath() string {
	if p := os.Getenv("TUNNEL_LAUNCHER_KNOWN_HOSTS"); p != "" {
		return p
	}
	return filepath.Join(filepath.Dir(configPath()), "known_hosts")
}
