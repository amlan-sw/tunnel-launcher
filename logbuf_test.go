package main

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestLogBuffer_LogAndSnapshot(t *testing.T) {
	b := newLogBuffer(10)
	b.Log("hello %s", "world")
	b.Log("second")

	lines := b.Snapshot()
	if len(lines) != 2 {
		t.Fatalf("len = %d", len(lines))
	}
	if !strings.HasSuffix(lines[0], "hello world") {
		t.Errorf("[0] = %q", lines[0])
	}
	if !strings.HasSuffix(lines[1], "second") {
		t.Errorf("[1] = %q", lines[1])
	}
}

func TestLogBuffer_RingTruncation(t *testing.T) {
	b := newLogBuffer(3)
	for i := 0; i < 10; i++ {
		b.Log("line %d", i)
	}
	lines := b.Snapshot()
	if len(lines) != 3 {
		t.Fatalf("len = %d", len(lines))
	}
	for i, want := range []string{"line 7", "line 8", "line 9"} {
		if !strings.HasSuffix(lines[i], want) {
			t.Errorf("[%d] = %q, want suffix %q", i, lines[i], want)
		}
	}
}

func TestLogBuffer_SnapshotIsCopy(t *testing.T) {
	b := newLogBuffer(10)
	b.Log("first")
	s1 := b.Snapshot()
	b.Log("second")
	s2 := b.Snapshot()

	if len(s1) != 1 {
		t.Errorf("snapshot 1 len = %d, want 1 (mutation leaked into snapshot)", len(s1))
	}
	if len(s2) != 2 {
		t.Errorf("snapshot 2 len = %d, want 2", len(s2))
	}
}

func TestLogBuffer_OnAddCallback(t *testing.T) {
	b := newLogBuffer(10)
	var calls atomic.Int32
	b.SetOnAdd(func() { calls.Add(1) })

	b.Log("a")
	b.Log("b")
	if got := calls.Load(); got != 2 {
		t.Errorf("calls = %d, want 2", got)
	}

	// Clear must also fire the callback.
	b.Clear()
	if got := calls.Load(); got != 3 {
		t.Errorf("after clear, calls = %d, want 3", got)
	}
	if len(b.Snapshot()) != 0 {
		t.Errorf("clear did not empty buffer")
	}
}

func TestLogBuffer_OnAddCanBeDisabled(t *testing.T) {
	b := newLogBuffer(10)
	var calls atomic.Int32
	b.SetOnAdd(func() { calls.Add(1) })
	b.Log("once")
	b.SetOnAdd(nil)
	b.Log("not counted")
	if got := calls.Load(); got != 1 {
		t.Errorf("calls = %d, want 1", got)
	}
}

// Concurrent writers must not race on b.lines or b.onAdd. Rely on the
// race detector to catch regressions.
func TestLogBuffer_ConcurrentLog(t *testing.T) {
	b := newLogBuffer(1000)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				b.Log("g%d-%d", i, j)
			}
		}(i)
	}
	wg.Wait()
	if got := len(b.Snapshot()); got != 800 {
		t.Errorf("len = %d, want 800", got)
	}
}

// The onAdd callback fires while NOT holding the buffer mutex, so a
// callback that calls Snapshot must not deadlock.
func TestLogBuffer_OnAddCanCallSnapshot(t *testing.T) {
	b := newLogBuffer(10)
	done := make(chan int, 1)
	b.SetOnAdd(func() {
		done <- len(b.Snapshot())
	})
	b.Log("hello")
	if got := <-done; got != 1 {
		t.Errorf("snapshot inside onAdd got len %d, want 1", got)
	}
}
