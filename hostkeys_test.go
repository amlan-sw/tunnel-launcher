package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// genPubKey returns a fresh ed25519 ssh.PublicKey for use in callback tests.
func genPubKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

// fakeAddr satisfies net.Addr for callback tests.
type fakeAddr struct{ s string }

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return a.s }

func TestKnownHostsPath_EnvOverride(t *testing.T) {
	t.Setenv("TUNNEL_LAUNCHER_KNOWN_HOSTS", "/explicit/path")
	if got := knownHostsPath(); got != "/explicit/path" {
		t.Errorf("got %q", got)
	}
}

func TestKnownHostsPath_Default(t *testing.T) {
	t.Setenv("TUNNEL_LAUNCHER_KNOWN_HOSTS", "")
	t.Setenv("TUNNEL_LAUNCHER_CONFIG", "/some/dir/config.toml")
	if got := knownHostsPath(); got != "/some/dir/known_hosts" {
		t.Errorf("got %q", got)
	}
}

func TestNewHostKeyEnforcer_CreatesEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	t.Setenv("TUNNEL_LAUNCHER_KNOWN_HOSTS", path)

	if _, err := newHostKeyEnforcer(nil); err != nil {
		t.Fatalf("newHostKeyEnforcer: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := st.Mode().Perm(); mode != 0600 {
		t.Errorf("mode = %o, want 0600", mode)
	}
	if st.Size() != 0 {
		t.Errorf("size = %d, want 0", st.Size())
	}
}

func TestHostKeyEnforcer_TOFUPersistsAndAccepts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	t.Setenv("TUNNEL_LAUNCHER_KNOWN_HOSTS", path)

	enf, err := newHostKeyEnforcer(nil)
	if err != nil {
		t.Fatal(err)
	}
	cb := enf.Callback()
	pk := genPubKey(t)
	addr := &fakeAddr{s: "10.0.0.1:22"}

	// First sight: accept.
	if err := cb("example.com:22", addr, pk); err != nil {
		t.Fatalf("first call: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || !strings.Contains(string(data), "example.com") {
		t.Fatalf("known_hosts did not record host: %q", data)
	}

	// Second sight, same key: still accept.
	if err := cb("example.com:22", addr, pk); err != nil {
		t.Errorf("second call: %v", err)
	}
}

func TestHostKeyEnforcer_MismatchRejectedAndPromptsNotified(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	t.Setenv("TUNNEL_LAUNCHER_KNOWN_HOSTS", path)

	prompts := &fakePrompts{}
	enf, err := newHostKeyEnforcer(prompts)
	if err != nil {
		t.Fatal(err)
	}
	cb := enf.Callback()
	addr := &fakeAddr{s: "10.0.0.1:22"}

	original := genPubKey(t)
	if err := cb("example.com:22", addr, original); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rogue := genPubKey(t)
	err = cb("example.com:22", addr, rogue)
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !isHostKeyMismatch(err) {
		t.Errorf("isHostKeyMismatch(err)=false, err=%v", err)
	}
	if len(prompts.mismatchSeen) != 3 {
		t.Errorf("prompts.mismatchSeen = %v, want 3 elements", prompts.mismatchSeen)
	} else if prompts.mismatchSeen[0] != "example.com:22" {
		t.Errorf("mismatch host = %q", prompts.mismatchSeen[0])
	}
}

func TestHostKeyEnforcer_NilPromptsDoesNotPanicOnMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	t.Setenv("TUNNEL_LAUNCHER_KNOWN_HOSTS", path)

	enf, err := newHostKeyEnforcer(nil)
	if err != nil {
		t.Fatal(err)
	}
	cb := enf.Callback()
	addr := &fakeAddr{s: "10.0.0.1:22"}

	if err := cb("example.com:22", addr, genPubKey(t)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	err = cb("example.com:22", addr, genPubKey(t))
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !isHostKeyMismatch(err) {
		t.Errorf("expected hostKeyMismatchError")
	}
}

func TestIsHostKeyMismatch(t *testing.T) {
	if isHostKeyMismatch(nil) {
		t.Error("nil should not be mismatch")
	}
	if isHostKeyMismatch(fmt.Errorf("plain error")) {
		t.Error("plain error should not be mismatch")
	}
	mismatch := &hostKeyMismatchError{host: "h", oldFp: "old", newFp: "new"}
	if !isHostKeyMismatch(mismatch) {
		t.Error("direct value should be mismatch")
	}
	wrapped := fmt.Errorf("ssh dial: %w", mismatch)
	if !isHostKeyMismatch(wrapped) {
		t.Error("wrapped error should still be mismatch (errors.As)")
	}
}

func TestHostKeyMismatchError_Message(t *testing.T) {
	e := &hostKeyMismatchError{host: "example.com:22", oldFp: "SHA256:OLD", newFp: "SHA256:NEW"}
	got := e.Error()
	for _, want := range []string{"example.com:22", "SHA256:OLD", "SHA256:NEW"} {
		if !strings.Contains(got, want) {
			t.Errorf("error %q missing %q", got, want)
		}
	}
}

// Sanity: knownhosts.New errors out if the file is unreadable, but the
// callback wraps it cleanly (does not panic).
func TestHostKeyEnforcer_BrokenKnownHostsFileSurfaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	t.Setenv("TUNNEL_LAUNCHER_KNOWN_HOSTS", path)

	enf, err := newHostKeyEnforcer(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the file so knownhosts.New fails.
	if err := os.WriteFile(path, []byte("\x00not\x00a\x00valid\x00line"), 0600); err != nil {
		t.Fatal(err)
	}
	cb := enf.Callback()
	err = cb("example.com:22", &fakeAddr{s: "10.0.0.1:22"}, genPubKey(t))
	if err == nil {
		t.Fatal("expected error from corrupt known_hosts")
	}
	if isHostKeyMismatch(err) {
		t.Error("corrupt file is not a mismatch")
	}
}

// Ensure the enforcer's mutex actually serialises concurrent first-sight
// inserts so we don't end up with duplicate lines.
func TestHostKeyEnforcer_ConcurrentFirstSightDeduped(t *testing.T) {
	if testing.Short() {
		t.Skip("touches filesystem")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	t.Setenv("TUNNEL_LAUNCHER_KNOWN_HOSTS", path)

	enf, err := newHostKeyEnforcer(nil)
	if err != nil {
		t.Fatal(err)
	}
	cb := enf.Callback()
	pk := genPubKey(t)

	done := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func() { done <- cb("example.com:22", &fakeAddr{s: "10.0.0.1:22"}, pk) }()
	}
	for i := 0; i < 4; i++ {
		if err := <-done; err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("concurrent call: %v", err)
		}
	}

	data, _ := os.ReadFile(path)
	lines := 0
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) != "" {
			lines++
		}
	}
	// One line is the goal. Two would imply a TOCTOU race writing the file
	// twice; the mutex should prevent it.
	if lines != 1 {
		t.Errorf("known_hosts has %d lines, want 1\nfile: %q", lines, data)
	}
}
