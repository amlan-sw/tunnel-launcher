package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
)

// launchedApps tracks goroutines waiting on launched processes, keyed by
// tunnel name. Used to avoid double-launching and to surface state to the UI.
type launchedApps struct {
	mu      sync.Mutex
	running map[string]*exec.Cmd
}

func newLaunchedApps() *launchedApps {
	return &launchedApps{running: make(map[string]*exec.Cmd)}
}

func (l *launchedApps) isRunning(name string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.running[name]
	return ok
}

// start spawns the command associated with the tunnel name. The onExit
// callback fires after the command terminates, on a background goroutine.
func (l *launchedApps) start(name, command string, onExit func(error)) error {
	l.mu.Lock()
	if _, ok := l.running[name]; ok {
		l.mu.Unlock()
		return fmt.Errorf("app for %q already running", name)
	}
	cmd := buildAppCmd(command)
	if err := cmd.Start(); err != nil {
		l.mu.Unlock()
		return fmt.Errorf("could not start: %v", err)
	}
	l.running[name] = cmd
	l.mu.Unlock()

	go func() {
		err := cmd.Wait()
		l.mu.Lock()
		delete(l.running, name)
		l.mu.Unlock()
		if onExit != nil {
			onExit(err)
		}
	}()
	return nil
}

// kill terminates the running app for the given tunnel, if any.
func (l *launchedApps) kill(name string) {
	l.mu.Lock()
	cmd, ok := l.running[name]
	l.mu.Unlock()
	if !ok || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}

// runningNames returns a snapshot of the names of currently running apps.
func (l *launchedApps) runningNames() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.running))
	for n := range l.running {
		out = append(out, n)
	}
	return out
}

func buildAppCmd(command string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.Command("cmd", "/C", command)
	}
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	return exec.Command(shell, "-c", command)
}
