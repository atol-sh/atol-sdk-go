package decision

import (
	"sync"
	"testing"
	"time"
)

func TestBuffer_Push(t *testing.T) {
	tests := []struct {
		name     string
		capacity int
		pushN    int
		wantOK   bool // expected return value of the last Push
		wantLen  int  // expected buffer length after all pushes
	}{
		{
			name:     "push within capacity succeeds",
			capacity: 5,
			pushN:    3,
			wantOK:   true,
			wantLen:  3,
		},
		{
			name:     "push at capacity succeeds",
			capacity: 3,
			pushN:    3,
			wantOK:   true,
			wantLen:  3,
		},
		{
			name:     "push when full returns false",
			capacity: 2,
			pushN:    3,
			wantOK:   false,
			wantLen:  2,
		},
		{
			name:     "push to zero capacity always fails",
			capacity: 0,
			pushN:    1,
			wantOK:   false,
			wantLen:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBuffer(tt.capacity)
			var lastOK bool
			for i := 0; i < tt.pushN; i++ {
				lastOK = b.Push(Entry{
					RequestID: "req",
					User:      "user",
					Relation:  "read",
					Object:    "doc:1",
					Allowed:   true,
				})
			}
			if lastOK != tt.wantOK {
				t.Errorf("last Push() = %v, want %v", lastOK, tt.wantOK)
			}
			if got := b.Len(); got != tt.wantLen {
				t.Errorf("Len() = %d, want %d", got, tt.wantLen)
			}
		})
	}
}

func TestBuffer_Drain(t *testing.T) {
	t.Run("drain returns entries in order", func(t *testing.T) {
		b := NewBuffer(10)
		for i := 0; i < 5; i++ {
			b.Push(Entry{RequestID: string(rune('A' + i))})
		}

		entries := b.Drain(3)
		if len(entries) != 3 {
			t.Fatalf("Drain(3) returned %d entries, want 3", len(entries))
		}
		for i, e := range entries {
			want := string(rune('A' + i))
			if e.RequestID != want {
				t.Errorf("entries[%d].RequestID = %q, want %q", i, e.RequestID, want)
			}
		}

		// Remaining 2 entries should still be in the buffer.
		if got := b.Len(); got != 2 {
			t.Errorf("Len() after Drain(3) = %d, want 2", got)
		}
	})

	t.Run("drain on empty returns nil", func(t *testing.T) {
		b := NewBuffer(10)
		entries := b.Drain(5)
		if entries != nil {
			t.Errorf("Drain on empty buffer = %v, want nil", entries)
		}
	})

	t.Run("drain with n greater than length returns all", func(t *testing.T) {
		b := NewBuffer(10)
		b.Push(Entry{RequestID: "A"})
		b.Push(Entry{RequestID: "B"})

		entries := b.Drain(100)
		if len(entries) != 2 {
			t.Fatalf("Drain(100) returned %d entries, want 2", len(entries))
		}
		if entries[0].RequestID != "A" || entries[1].RequestID != "B" {
			t.Errorf("unexpected entries: %+v", entries)
		}

		// Buffer should now be empty.
		if got := b.Len(); got != 0 {
			t.Errorf("Len() after full drain = %d, want 0", got)
		}
	})

	t.Run("drain then push reuses space", func(t *testing.T) {
		b := NewBuffer(3)
		b.Push(Entry{RequestID: "1"})
		b.Push(Entry{RequestID: "2"})
		b.Push(Entry{RequestID: "3"})

		// Buffer is full.
		if b.Push(Entry{RequestID: "4"}) {
			t.Fatal("Push to full buffer should return false")
		}

		// Drain all.
		b.Drain(3)

		// Should be able to push again.
		if !b.Push(Entry{RequestID: "5"}) {
			t.Error("Push after drain should succeed")
		}
		if got := b.Len(); got != 1 {
			t.Errorf("Len() = %d, want 1", got)
		}
	})
}

func TestBuffer_ConcurrentAccess(t *testing.T) {
	// Verify no panics or data races under concurrent access.
	// Run with -race flag: go test -race ./pkg/sdk/decision/
	b := NewBuffer(1000)
	var wg sync.WaitGroup

	// Concurrent pushers.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				b.Push(Entry{
					RequestID: "req",
					User:      "user",
					Relation:  "read",
					Object:    "doc:1",
					Allowed:   true,
					Timestamp: time.Now(),
				})
			}
		}()
	}

	// Concurrent drainers.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				b.Drain(10)
			}
		}()
	}

	// Concurrent readers.
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				b.Len()
			}
		}()
	}

	wg.Wait()

	// No assertion on final state — this test verifies no panics/races.
}
