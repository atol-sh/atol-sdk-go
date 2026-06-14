package decision

import "sync"

// Buffer is a bounded, lock-free-ish ring buffer for decision entries.
// If full, new entries are dropped (never block the hot path).
type Buffer struct {
	mu      sync.Mutex
	entries []Entry
	size    int
}

// NewBuffer creates a buffer with the given capacity.
func NewBuffer(size int) *Buffer {
	return &Buffer{
		entries: make([]Entry, 0, size),
		size:    size,
	}
}

// Push adds an entry to the buffer. Drops if full.
func (b *Buffer) Push(e Entry) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.entries) >= b.size {
		return false // Drop — buffer full.
	}
	b.entries = append(b.entries, e)
	return true
}

// Drain removes up to n entries from the buffer.
func (b *Buffer) Drain(n int) []Entry {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.entries) == 0 {
		return nil
	}
	if n > len(b.entries) {
		n = len(b.entries)
	}
	out := make([]Entry, n)
	copy(out, b.entries[:n])
	b.entries = b.entries[n:]
	return out
}

// Len returns the number of buffered entries.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries)
}
