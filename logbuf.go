package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// verbose mirrors the -v command-line flag. When false, no log output is
// written to stdout; the per-tunnel ring buffers still capture connection
// logs for the in-app log window. Package-level so log helpers and tests
// can flip it without threading it through every call site.
var verbose bool

// stdoutLog writes a single timestamped line to stdout iff verbose is set.
// Shared by appLog (app-wide events) and the per-tunnel logger.
func stdoutLog(format string, args ...any) {
	if !verbose {
		return
	}
	fmt.Fprintf(os.Stdout, time.Now().Format("15:04:05")+"  "+format+"\n", args...)
}

// appLog reports an application-wide event (startup, config errors, etc.).
// These events have no associated tunnel, so they go to stdout only — never
// to a per-tunnel buffer. Silent unless -v is given.
func appLog(format string, args ...any) {
	stdoutLog(format, args...)
}

// logBuffer is a thread-safe ring buffer for connection logs.
type logBuffer struct {
	mu    sync.Mutex
	lines []string
	max   int
	onAdd func()
}

func newLogBuffer(max int) *logBuffer {
	return &logBuffer{max: max}
}

// Log appends a timestamped line. The optional onAdd callback fires after
// the buffer mutates, on the calling goroutine.
func (b *logBuffer) Log(format string, args ...any) {
	line := time.Now().Format("15:04:05") + "  " + fmt.Sprintf(format, args...)
	b.mu.Lock()
	b.lines = append(b.lines, line)
	if len(b.lines) > b.max {
		b.lines = b.lines[len(b.lines)-b.max:]
	}
	cb := b.onAdd
	b.mu.Unlock()
	if cb != nil {
		cb()
	}
}

func (b *logBuffer) SetOnAdd(f func()) {
	b.mu.Lock()
	b.onAdd = f
	b.mu.Unlock()
}

// Snapshot returns a copy of the current buffer.
func (b *logBuffer) Snapshot() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.lines))
	copy(out, b.lines)
	return out
}

func (b *logBuffer) Clear() {
	b.mu.Lock()
	b.lines = nil
	cb := b.onAdd
	b.mu.Unlock()
	if cb != nil {
		cb()
	}
}
