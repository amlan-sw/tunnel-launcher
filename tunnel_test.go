package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestParseAddr(t *testing.T) {
	cases := []struct {
		in       string
		wantNet  string
		wantAddr string
	}{
		{"", "tcp", "localhost:0"},
		{"9000", "tcp", "localhost:9000"},
		{"host:9000", "tcp", "host:9000"},
		{"[::1]:9000", "tcp", "[::1]:9000"},
		{"/tmp/socket", "unix", "/tmp/socket"},
		{":9000", "tcp", ":9000"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			a := parseAddr(c.in)
			if a.network != c.wantNet || a.address != c.wantAddr {
				t.Errorf("got (%s,%s), want (%s,%s)", a.network, a.address, c.wantNet, c.wantAddr)
			}
		})
	}
}

func TestParseJump(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
		wantUser string
	}{
		{"host", "host", 22, "tester"},
		{"u@host", "host", 22, "u"},
		{"host:2222", "host", 2222, "tester"},
		{"u@host:2222", "host", 2222, "u"},
		{"u@host:not-a-port", "host:not-a-port", 22, "u"}, // bad port falls back to 22, host keeps colon
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			j := parseJump(c.in)
			if j.host != c.wantHost || j.port != c.wantPort || j.user != c.wantUser {
				t.Errorf("got %+v, want host=%q port=%d user=%q", j, c.wantHost, c.wantPort, c.wantUser)
			}
		})
	}
}

func TestExpandTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"~", home},
		{"~/foo/bar", filepath.Join(home, "foo/bar")},
		{"/abs/path", "/abs/path"},
		{"relative/path", "relative/path"},
		{"~user/foo", "~user/foo"}, // not expanded — only ~/ form supported
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := expandTilde(c.in); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestResolveHost_DefaultsWithEmptyConfig(t *testing.T) {
	// HOME is the tempdir set in TestMain, so kevinburke/ssh_config has
	// no config file to read; everything falls back to library defaults.
	d := Desc{Host: "definitely-not-in-anyones-config-12345.test"}
	r := resolveHost(d)
	if r.host != d.Host {
		t.Errorf("host = %q, want %q", r.host, d.Host)
	}
	if r.user != "tester" {
		t.Errorf("user = %q, want %q", r.user, "tester")
	}
	if r.port != 22 {
		t.Errorf("port = %d, want 22", r.port)
	}
	if r.identity != "" {
		t.Errorf("identity = %q, want empty", r.identity)
	}
	if len(r.jumps) != 0 {
		t.Errorf("jumps = %+v, want none", r.jumps)
	}
}

func TestResolveHost_DescOverridesWin(t *testing.T) {
	d := Desc{Host: "alias", User: "alice", Port: 2222}
	r := resolveHost(d)
	if r.user != "alice" {
		t.Errorf("user = %q, want alice", r.user)
	}
	if r.port != 2222 {
		t.Errorf("port = %d, want 2222", r.port)
	}
}

func TestResolveHost_TildeIdentityIsExpanded(t *testing.T) {
	home, _ := os.UserHomeDir()
	d := Desc{Host: "alias", Identity: "~/keyfile"}
	r := resolveHost(d)
	if want := filepath.Join(home, "keyfile"); r.identity != want {
		t.Errorf("identity = %q, want %q", r.identity, want)
	}
}

// SOCKS5 helpers --------------------------------------------------------

// runHandshake runs socksHandshake on srv in a goroutine, returning a
// channel that delivers (target, error) once the handshake completes.
func runHandshake(srv net.Conn) <-chan struct {
	target string
	err    error
} {
	out := make(chan struct {
		target string
		err    error
	}, 1)
	go func() {
		t, err := socksHandshake(srv)
		out <- struct {
			target string
			err    error
		}{t, err}
	}()
	return out
}

func TestSocksHandshake_IPv4(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	done := runHandshake(srv)

	// Greeting: VER, NMETHODS=1, METHODS=NO_AUTH(0)
	if _, err := cli.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(cli, greet); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(greet, []byte{5, 0}) {
		t.Fatalf("greet = %v", greet)
	}
	// Request: VER CMD=CONNECT RSV ATYP=IPv4 1.2.3.4:80
	if _, err := cli.Write([]byte{5, 1, 0, 1, 1, 2, 3, 4, 0, 80}); err != nil {
		t.Fatal(err)
	}

	res := <-done
	if res.err != nil {
		t.Fatalf("handshake: %v", res.err)
	}
	if res.target != "1.2.3.4:80" {
		t.Fatalf("target = %q", res.target)
	}
}

func TestSocksHandshake_Domain(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	done := runHandshake(srv)

	cli.Write([]byte{5, 1, 0})
	io.ReadFull(cli, make([]byte, 2))

	host := "example.com"
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, 0x1F, 0x90) // 8080
	cli.Write(req)

	res := <-done
	if res.err != nil {
		t.Fatalf("handshake: %v", res.err)
	}
	if res.target != "example.com:8080" {
		t.Fatalf("target = %q", res.target)
	}
}

func TestSocksHandshake_IPv6(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	done := runHandshake(srv)

	cli.Write([]byte{5, 1, 0})
	io.ReadFull(cli, make([]byte, 2))

	addr := net.ParseIP("::1").To16()
	req := []byte{5, 1, 0, 4}
	req = append(req, addr...)
	req = append(req, 0x00, 0x16) // 22
	cli.Write(req)

	res := <-done
	if res.err != nil {
		t.Fatalf("handshake: %v", res.err)
	}
	if res.target != "[::1]:22" {
		t.Fatalf("target = %q", res.target)
	}
}

func TestSocksHandshake_BadVersion(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	done := runHandshake(srv)

	// Write only 2 bytes — the handshake rejects on buf[0]!=5 before
	// reading anything more. net.Pipe Write blocks until consumed, so
	// extra bytes would deadlock the test.
	cli.Write([]byte{4, 0})

	res := <-done
	if res.err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(res.err.Error(), "SOCKS5") {
		t.Fatalf("error = %v", res.err)
	}
}

func TestSocksHandshake_UnsupportedCommand(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	done := runHandshake(srv)

	cli.Write([]byte{5, 1, 0})
	io.ReadFull(cli, make([]byte, 2))
	// CMD=BIND (2) is not supported.
	cli.Write([]byte{5, 2, 0, 1})

	// Server writes a rejection reply.
	rej := make([]byte, 10)
	if _, err := io.ReadFull(cli, rej); err != nil {
		t.Fatal(err)
	}
	if rej[1] != 7 {
		t.Errorf("expected status 7 (CMD not supported), got %d", rej[1])
	}

	res := <-done
	if res.err == nil {
		t.Fatal("expected error")
	}
}

// preferRSASHA2 ----------------------------------------------------------

func TestPreferRSASHA2_NoOpForEd25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	out := preferRSASHA2(signer)
	if out != signer {
		t.Errorf("expected ed25519 signer to be returned unchanged")
	}
}

func TestPreferRSASHA2_ReordersRSA(t *testing.T) {
	if testing.Short() {
		t.Skip("rsa key generation is slow")
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	base, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	out := preferRSASHA2(base)
	ms, ok := out.(ssh.MultiAlgorithmSigner)
	if !ok {
		t.Fatalf("got %T, want MultiAlgorithmSigner", out)
	}
	algos := ms.Algorithms()
	if len(algos) == 0 || algos[0] != ssh.KeyAlgoRSASHA512 {
		t.Errorf("first algo = %v, want %s first", algos, ssh.KeyAlgoRSASHA512)
	}
}

// buildAuth --------------------------------------------------------------

// writeEd25519Key creates an OpenSSH-format private key file at path,
// optionally encrypted with the given passphrase.
func writeEd25519Key(t *testing.T, path, passphrase string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestBuildAuth_NoAgentNoKeysNoPrompts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SSH_AUTH_SOCK", "")

	got := buildAuth(resolved{}, nil, nil, silentLog)
	if len(got) != 0 {
		t.Errorf("methods = %d, want 0", len(got))
	}
}

func TestBuildAuth_LoadsDefaultEd25519(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SSH_AUTH_SOCK", "")

	writeEd25519Key(t, filepath.Join(dir, ".ssh", "id_ed25519"), "")

	got := buildAuth(resolved{}, nil, nil, silentLog)
	if len(got) != 1 {
		t.Errorf("methods = %d, want 1", len(got))
	}
}

func TestBuildAuth_ExplicitIdentitySkipsDefaultLookup(t *testing.T) {
	// Default keys must NOT be tried when explicit is set, otherwise the
	// resulting auth list bloats and may exhaust the server's MaxAuthTries.
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SSH_AUTH_SOCK", "")

	// A bogus default that, if loaded, would succeed and inflate methods.
	writeEd25519Key(t, filepath.Join(dir, ".ssh", "id_ed25519"), "")
	// The explicit key.
	explicit := filepath.Join(dir, "explicit_key")
	writeEd25519Key(t, explicit, "")

	got := buildAuth(resolved{identity: explicit}, nil, nil, silentLog)
	if len(got) != 1 {
		t.Errorf("methods = %d, want exactly 1 (explicit only)", len(got))
	}
}

func TestBuildAuth_ExplicitMissingFileYieldsNoMethods(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SSH_AUTH_SOCK", "")

	got := buildAuth(resolved{identity: filepath.Join(dir, "does-not-exist")}, nil, nil, silentLog)
	if len(got) != 0 {
		t.Errorf("methods = %d, want 0", len(got))
	}
}

func TestBuildAuth_PasswordAppendedWhenPromptsPresent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SSH_AUTH_SOCK", "")
	writeEd25519Key(t, filepath.Join(dir, ".ssh", "id_ed25519"), "")

	got := buildAuth(resolved{user: "u", host: "h"}, &fakePrompts{password: "pw"}, nil, silentLog)
	// 1 (default key) + 1 (password fallback). Order doesn't matter.
	if len(got) != 2 {
		t.Errorf("methods = %d, want 2 (key + password)", len(got))
	}
}

func TestBuildAuth_PasswordOmittedWhenPromptsNil(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SSH_AUTH_SOCK", "")

	got := buildAuth(resolved{user: "u", host: "h"}, nil, nil, silentLog)
	if len(got) != 0 {
		t.Errorf("methods = %d, want 0", len(got))
	}
}

func TestBuildAuth_KeyCacheReusesSigner(t *testing.T) {
	// Second call must hit the cache: the file is deleted between calls,
	// yet auth must still succeed because the signer is cached.
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SSH_AUTH_SOCK", "")
	keyPath := filepath.Join(dir, "k")
	writeEd25519Key(t, keyPath, "")

	cache := newSignerCache()
	first := buildAuth(resolved{identity: keyPath}, nil, cache, silentLog)
	if len(first) != 1 {
		t.Fatalf("first call methods = %d, want 1", len(first))
	}

	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	second := buildAuth(resolved{identity: keyPath}, nil, cache, silentLog)
	if len(second) != 1 {
		t.Errorf("second call methods = %d, want 1 (cache hit)", len(second))
	}
}

// Regression test for the second "ssh works in CLI, fails from this tool"
// symptom: an empty (or just unrelated) ssh-agent must NOT cause the
// file-based key to be skipped. Splitting agent and file keys across two
// ssh.AuthMethod entries with the same method() string ("publickey") makes
// Go's auth loop add "publickey" to its `tried` set after the first method
// returns, so the second is never invoked. Symptom: server lists publickey
// as the only allowed method, agent has no usable key, file key never
// offered, and dial fails with "no supported methods remain". The fix is to
// fold both into a single PublicKeysCallback.
func TestBuildAuth_AgentAndFileKeyProduceSinglePublickeyMethod(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// Stand up a real (in-process) ssh-agent on a unix socket — empty, to
	// reproduce the production scenario where the agent is reachable but
	// holds no keys.
	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "agent.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(agent.NewKeyring(), c)
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sockPath)

	writeEd25519Key(t, filepath.Join(dir, ".ssh", "id_ed25519"), "")

	got := buildAuth(resolved{}, nil, nil, silentLog)
	if len(got) != 1 {
		t.Fatalf("methods = %d, want 1 (one combined publickey method); two would let an empty-agent attempt mark publickey as tried and the file key would never be offered", len(got))
	}
}

// End-to-end regression test for the same bug: actually run the SSH auth
// handshake against an in-process server that allows ONLY publickey, with
// an empty ssh-agent active and the user's key on disk. Pre-fix this
// failed with "no supported methods remain" because the empty-agent
// AuthMethod marked "publickey" as tried before the file key was offered.
// Post-fix the single combined PublicKeysCallback offers both, and the
// file key authenticates successfully.
func TestBuildAuth_EmptyAgentDoesNotMaskFileKey_LiveHandshake(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// User key on disk; capture its fingerprint so the test server can
	// authorize that exact key.
	keyPath := filepath.Join(dir, ".ssh", "id_ed25519")
	writeEd25519Key(t, keyPath, "")
	rawKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	userSigner, err := ssh.ParsePrivateKey(rawKey)
	if err != nil {
		t.Fatal(err)
	}
	authorizedFP := ssh.FingerprintSHA256(userSigner.PublicKey())

	// Empty in-process ssh-agent on a unix socket.
	sockPath := filepath.Join(t.TempDir(), "agent.sock")
	agentLn, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer agentLn.Close()
	go func() {
		for {
			c, err := agentLn.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(agent.NewKeyring(), c)
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sockPath)

	// Minimal SSH server: publickey-only, accepts the user's key.
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	srvCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if ssh.FingerprintSHA256(key) == authorizedFP {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unauthorized key %s", ssh.FingerprintSHA256(key))
		},
	}
	srvCfg.AddHostKey(hostSigner)

	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srvLn.Close()

	srvDone := make(chan error, 1)
	go func() {
		nc, err := srvLn.Accept()
		if err != nil {
			srvDone <- err
			return
		}
		defer nc.Close()
		_, chans, reqs, err := ssh.NewServerConn(nc, srvCfg)
		if err != nil {
			srvDone <- err
			return
		}
		go ssh.DiscardRequests(reqs)
		for newCh := range chans {
			newCh.Reject(ssh.UnknownChannelType, "no channels in test")
		}
		srvDone <- nil
	}()

	methods := buildAuth(resolved{}, nil, nil, silentLog)

	cli, err := ssh.Dial("tcp", srvLn.Addr().String(), &ssh.ClientConfig{
		User:            "tester",
		Auth:            methods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh.Dial: %v (this is the production bug — empty agent masked the file key)", err)
	}
	cli.Close()

	select {
	case err := <-srvDone:
		// EOF after client closes is expected.
		if err != nil && !errors.Is(err, io.EOF) {
			t.Logf("server goroutine: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not finish")
	}
}

// Regression test for the "ssh works in CLI, fails from this tool" symptom.
// Agent signers must round-trip through preferRSASHA2 so RSA keys advertise
// rsa-sha2-512/256 instead of legacy ssh-rsa (SHA-1). We exercise the wrap
// itself; the live integration with a real agent is out of scope here.
func TestBuildAuth_AgentRSAKeysAreWrappedForSHA2(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	base, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := preferRSASHA2(base)
	ms, ok := wrapped.(ssh.MultiAlgorithmSigner)
	if !ok {
		t.Fatalf("agent signers must be wrapped as MultiAlgorithmSigner, got %T", wrapped)
	}
	algos := ms.Algorithms()
	if len(algos) == 0 || algos[0] != ssh.KeyAlgoRSASHA512 {
		t.Errorf("first algo = %v, want %s", algos, ssh.KeyAlgoRSASHA512)
	}
}

// pipe -------------------------------------------------------------------

func TestPipe_BidirectionalAndExitsOnClose(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	defer a1.Close()
	defer a2.Close()
	defer b1.Close()
	defer b2.Close()

	pipeDone := make(chan struct{})
	go func() {
		pipe(a2, b1)
		close(pipeDone)
	}()

	// a1 → a2 → b1 → b2
	go func() { a1.Write([]byte("hello")) }()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(b2, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("got %q", buf)
	}

	// b2 → b1 → a2 → a1
	go func() { b2.Write([]byte("world")) }()
	if _, err := io.ReadFull(a1, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "world" {
		t.Fatalf("got %q", buf)
	}

	// Closing a1 must cause pipe to return.
	a1.Close()
	select {
	case <-pipeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("pipe did not return after close")
	}
}

// loadKeyInteractive -----------------------------------------------------

func TestLoadKeyInteractive_NotExist(t *testing.T) {
	_, err := loadKeyInteractive(filepath.Join(t.TempDir(), "nope"), nil, silentLog)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, want NotExist", err)
	}
}

func TestLoadKeyInteractive_Plain(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k")
	writeEd25519Key(t, p, "")
	s, err := loadKeyInteractive(p, nil, silentLog)
	if err != nil {
		t.Fatalf("loadKeyInteractive: %v", err)
	}
	if s == nil {
		t.Fatal("expected signer")
	}
}

func TestLoadKeyInteractive_EncryptedWithPromptsAccept(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k")
	writeEd25519Key(t, p, "secret")
	prompts := &fakePrompts{passphrase: "secret", passphraseOK: true}
	s, err := loadKeyInteractive(p, prompts, silentLog)
	if err != nil {
		t.Fatalf("loadKeyInteractive: %v", err)
	}
	if s == nil {
		t.Fatal("expected signer")
	}
	if !prompts.passphraseAsked {
		t.Error("passphrase prompt was not invoked")
	}
}

func TestLoadKeyInteractive_EncryptedWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k")
	writeEd25519Key(t, p, "secret")
	prompts := &fakePrompts{passphrase: "wrong", passphraseOK: true}
	if _, err := loadKeyInteractive(p, prompts, silentLog); err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}

func TestLoadKeyInteractive_EncryptedCancelled(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k")
	writeEd25519Key(t, p, "secret")
	prompts := &fakePrompts{passphraseOK: false}
	s, err := loadKeyInteractive(p, prompts, silentLog)
	if err != nil {
		t.Errorf("expected nil error on cancel, got %v", err)
	}
	if s != nil {
		t.Errorf("expected nil signer on cancel, got %v", s)
	}
}

func TestLoadKeyInteractive_EncryptedNoPrompts(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k")
	writeEd25519Key(t, p, "secret")
	if _, err := loadKeyInteractive(p, nil, silentLog); err == nil {
		t.Error("expected error when key needs passphrase but no prompts")
	}
}

// signerCache ------------------------------------------------------------

func TestSignerCache_GetPut(t *testing.T) {
	c := newSignerCache()
	if _, ok := c.get("missing"); ok {
		t.Error("expected miss for empty cache")
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	c.put("k", signer)
	got, ok := c.get("k")
	if !ok || got != signer {
		t.Errorf("get after put: ok=%v signer=%v", ok, got)
	}
}

// fakePrompts is a CredentialPrompts stub that records invocations.
type fakePrompts struct {
	passphrase      string
	passphraseOK    bool
	passphraseAsked bool

	password   string
	passwordOK bool

	mismatchSeen []string // host, oldFp, newFp
}

func (f *fakePrompts) Passphrase(path string) (string, bool) {
	f.passphraseAsked = true
	return f.passphrase, f.passphraseOK
}
func (f *fakePrompts) Password(user, host string) (string, bool) {
	return f.password, f.passwordOK
}
func (f *fakePrompts) HostKeyMismatch(host, oldFp, newFp string) {
	f.mismatchSeen = []string{host, oldFp, newFp}
}

// silentLog satisfies logFn without producing output.
func silentLog(string, ...any) {}
