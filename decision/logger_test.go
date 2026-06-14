package decision

import (
	"sync"
	"testing"
	"time"
)

// mockSink implements the Sink interface for testing.
type mockSink struct {
	mu      sync.Mutex
	batches [][]Entry
}

func (m *mockSink) Send(entries []Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Copy the slice to avoid aliasing with buffer internals.
	batch := make([]Entry, len(entries))
	copy(batch, entries)
	m.batches = append(m.batches, batch)
	return nil
}

func (m *mockSink) allEntries() []Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []Entry
	for _, b := range m.batches {
		all = append(all, b...)
	}
	return all
}

func (m *mockSink) batchCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.batches)
}

func TestLogger_Log(t *testing.T) {
	sink := &mockSink{}
	logger := NewLogger(sink, 100, 50, time.Hour, nil) // Large interval — we flush manually.

	logger.Log(Entry{
		RequestID: "req-1",
		User:      "alice",
		Relation:  "read",
		Object:    "doc:budget",
		Allowed:   true,
	})
	logger.Log(Entry{
		RequestID: "req-2",
		User:      "bob",
		Relation:  "write",
		Object:    "doc:budget",
		Allowed:   false,
	})

	// Entries should be in the buffer but not yet sent.
	if sink.batchCount() != 0 {
		t.Errorf("expected no batches before flush, got %d", sink.batchCount())
	}

	// Manual flush via Stop (which flushes remaining).
	// But first we need to Start to make Stop's final flush work correctly.
	logger.Start()
	logger.Stop()

	entries := sink.allEntries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries after Stop flush, got %d", len(entries))
	}
	if entries[0].RequestID != "req-1" {
		t.Errorf("entries[0].RequestID = %q, want %q", entries[0].RequestID, "req-1")
	}
	if entries[1].RequestID != "req-2" {
		t.Errorf("entries[1].RequestID = %q, want %q", entries[1].RequestID, "req-2")
	}
}

func TestLogger_TimestampAutoSet(t *testing.T) {
	sink := &mockSink{}
	logger := NewLogger(sink, 100, 50, time.Hour, nil)

	before := time.Now()
	logger.Log(Entry{
		RequestID: "req-ts",
		User:      "alice",
		Relation:  "read",
		Object:    "doc:1",
		Allowed:   true,
		// Timestamp intentionally left as zero value.
	})
	after := time.Now()

	// Start and stop to trigger final flush.
	logger.Start()
	logger.Stop()

	entries := sink.allEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	ts := entries[0].Timestamp
	if ts.IsZero() {
		t.Fatal("expected non-zero timestamp, got zero")
	}
	if ts.Before(before) || ts.After(after) {
		t.Errorf("timestamp %v not in range [%v, %v]", ts, before, after)
	}
}

func TestLogger_TimestampPreserved(t *testing.T) {
	sink := &mockSink{}
	logger := NewLogger(sink, 100, 50, time.Hour, nil)

	fixedTime := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	logger.Log(Entry{
		RequestID: "req-fixed",
		User:      "alice",
		Relation:  "read",
		Object:    "doc:1",
		Allowed:   true,
		Timestamp: fixedTime,
	})

	logger.Start()
	logger.Stop()

	entries := sink.allEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if !entries[0].Timestamp.Equal(fixedTime) {
		t.Errorf("timestamp = %v, want %v", entries[0].Timestamp, fixedTime)
	}
}

func TestLogger_StartStop(t *testing.T) {
	sink := &mockSink{}
	// Short flush interval so the background loop flushes quickly.
	logger := NewLogger(sink, 100, 50, 20*time.Millisecond, nil)

	logger.Start()

	// Log some entries.
	for i := 0; i < 5; i++ {
		logger.Log(Entry{
			RequestID: "req",
			User:      "alice",
			Relation:  "read",
			Object:    "doc:1",
			Allowed:   true,
		})
	}

	// Give the flush loop time to run at least once.
	time.Sleep(60 * time.Millisecond)

	logger.Stop()

	// All entries should have been sent (either by periodic flush or final flush).
	entries := sink.allEntries()
	if len(entries) != 5 {
		t.Errorf("expected 5 entries total, got %d", len(entries))
	}
}

func TestLogger_FlushBySize(t *testing.T) {
	sink := &mockSink{}
	// flushSize=3, large interval so only size-triggered flushing matters
	// (via the periodic ticker).
	logger := NewLogger(sink, 100, 3, 20*time.Millisecond, nil)

	logger.Start()

	// Log 6 entries — should produce at least 2 batches of 3 when flushed.
	for i := 0; i < 6; i++ {
		logger.Log(Entry{
			RequestID: "req",
			User:      "alice",
			Relation:  "read",
			Object:    "doc:1",
			Allowed:   true,
		})
	}

	// Wait for periodic flushes to process entries.
	time.Sleep(60 * time.Millisecond)

	logger.Stop()

	entries := sink.allEntries()
	if len(entries) != 6 {
		t.Errorf("expected 6 entries total, got %d", len(entries))
	}

	// Verify that no batch exceeds flushSize (3).
	for i, batch := range sink.batches {
		if len(batch) > 3 {
			t.Errorf("batch[%d] has %d entries, exceeding flushSize of 3", i, len(batch))
		}
	}
}

func TestLogger_EmptyFlush(t *testing.T) {
	sink := &mockSink{}
	logger := NewLogger(sink, 100, 50, 20*time.Millisecond, nil)

	// Start and stop without logging anything.
	logger.Start()
	time.Sleep(50 * time.Millisecond)
	logger.Stop()

	// Sink should have received zero batches (empty drains are skipped).
	if sink.batchCount() != 0 {
		t.Errorf("expected 0 batches for empty logger, got %d", sink.batchCount())
	}
}
