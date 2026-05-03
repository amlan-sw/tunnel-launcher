package main

import (
	"os"
	"testing"
)

// TestMain isolates the test process from the user's real environment:
// no SSH_AUTH_SOCK leakage, and an empty HOME so kevinburke/ssh_config
// caches an empty user config rather than ~/.ssh/config. Must run before
// any test calls ssh_config.Get / GetStrict, since that package caches.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "tunnel-launcher-test-home-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmp)

	os.Unsetenv("SSH_AUTH_SOCK")
	os.Unsetenv("XDG_CONFIG_HOME")
	os.Unsetenv("TUNNEL_LAUNCHER_CONFIG")
	os.Setenv("HOME", tmp)
	os.Setenv("USER", "tester")

	os.Exit(m.Run())
}
