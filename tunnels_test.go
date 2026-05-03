package main

import (
	"strings"
	"testing"
)

func TestTunnelManager_Empty(t *testing.T) {
	m := newTunnelManager(nil, nil)
	if got := m.snapshot(); len(got) != 0 {
		t.Errorf("snapshot len = %d, want 0", len(got))
	}
}

func TestTunnelManager_CloseUnknown(t *testing.T) {
	m := newTunnelManager(nil, nil)
	err := m.close("does-not-exist")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "not running") {
		t.Errorf("err = %v", err)
	}
}

// closeAll on an empty manager is a no-op and must not panic.
func TestTunnelManager_CloseAllEmpty(t *testing.T) {
	m := newTunnelManager(nil, nil)
	m.closeAll()
}

// open() requires real ssh dialing; we verify the duplicate-name guard
// path by injecting a sentinel into the running map. Synthesises only
// what tunnelManager.open inspects before dialing.
func TestTunnelManager_OpenDuplicateNameGuard(t *testing.T) {
	m := newTunnelManager(nil, nil)
	m.running["dup"] = &Tunnel{Desc: Desc{Name: "dup"}}

	err := m.open(Desc{Name: "dup"})
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
	if !strings.Contains(err.Error(), "already running") {
		t.Errorf("err = %v", err)
	}
}
