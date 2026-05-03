package main

import (
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBuildAppCmd_PosixUsesShellDashC(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix-only test")
	}
	t.Setenv("SHELL", "/usr/local/bin/myshell")
	cmd := buildAppCmd("echo hi")
	if cmd.Path != "/usr/local/bin/myshell" {
		t.Errorf("path = %q", cmd.Path)
	}
	if len(cmd.Args) != 3 || cmd.Args[1] != "-c" || cmd.Args[2] != "echo hi" {
		t.Errorf("args = %#v", cmd.Args)
	}
}

func TestBuildAppCmd_PosixDefaultShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix-only test")
	}
	t.Setenv("SHELL", "")
	cmd := buildAppCmd("echo hi")
	if !strings.HasSuffix(cmd.Path, "/sh") {
		t.Errorf("path = %q, want trailing /sh", cmd.Path)
	}
}

func TestLaunchedApps_StartIsRunningKill(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses posix sleep")
	}
	l := newLaunchedApps()
	exited := make(chan error, 1)

	if err := l.start("t1", "sleep 30", func(err error) { exited <- err }); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !l.isRunning("t1") {
		t.Fatal("expected isRunning=true")
	}
	if names := l.runningNames(); len(names) != 1 || names[0] != "t1" {
		t.Errorf("runningNames = %v", names)
	}

	l.kill("t1")
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("onExit never fired after kill")
	}
	if l.isRunning("t1") {
		t.Error("expected isRunning=false after onExit")
	}
}

func TestLaunchedApps_DoubleStartFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses posix sleep")
	}
	l := newLaunchedApps()
	exited := make(chan error, 1)
	if err := l.start("dup", "sleep 30", func(err error) { exited <- err }); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		l.kill("dup")
		<-exited
	}()

	if err := l.start("dup", "sleep 30", nil); err == nil {
		t.Error("expected error on second start with same name")
	}
}

func TestLaunchedApps_NaturalExitFiresCallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses posix true command")
	}
	l := newLaunchedApps()
	exited := make(chan error, 1)
	if err := l.start("quick", "true", func(err error) { exited <- err }); err != nil {
		t.Fatalf("start: %v", err)
	}
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("onExit never fired")
	}
	if l.isRunning("quick") {
		t.Error("expected entry removed after exit")
	}
}

func TestLaunchedApps_KillUnknownIsNoOp(t *testing.T) {
	l := newLaunchedApps()
	// Should not panic / error.
	l.kill("does-not-exist")
}

func TestLaunchedApps_StartFailureNotTracked(t *testing.T) {
	l := newLaunchedApps()
	// A command that the shell will start successfully but exits fast
	// is not the test target — we want a Start() failure. exec.Cmd.Start
	// fails when the executable does not exist; emulate by setting SHELL
	// to a non-existent path (posix path).
	if runtime.GOOS == "windows" {
		t.Skip("posix-specific shell substitution")
	}
	t.Setenv("SHELL", "/no/such/shell")

	if err := l.start("bad", "echo hi", nil); err == nil {
		t.Error("expected start to fail when shell does not exist")
	}
	if l.isRunning("bad") {
		t.Error("failed start should not be tracked")
	}
}

// runningNames must be safe under concurrent start/kill. A regression here
// would surface as a race report.
func TestLaunchedApps_ConcurrentSafe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses posix sleep")
	}
	l := newLaunchedApps()
	var wg sync.WaitGroup
	exited := make(chan struct{}, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := string(rune('a' + i))
			if err := l.start(name, "sleep 5", func(error) { exited <- struct{}{} }); err != nil {
				t.Errorf("start %s: %v", name, err)
				return
			}
			_ = l.runningNames()
			l.kill(name)
		}(i)
	}
	wg.Wait()
	for i := 0; i < 8; i++ {
		<-exited
	}
}
