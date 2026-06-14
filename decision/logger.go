// Package decision provides async decision logging for the SDK.
// Decisions are buffered in a ring buffer and flushed in batches
// to the control plane via the DP Agent's IngestDecisionLogs RPC.
package decision

import (
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// Entry represents a single authorization decision.
type Entry struct {
	RequestID     string
	User          string
	Relation      string
	Object        string
	Allowed       bool
	MatchedRule   string
	EvalUs        int32
	ZanzibarCalls int32
	AuthMethod    string
	Timestamp     time.Time
}

// Sink receives batches of decision log entries.
type Sink interface {
	Send(entries []Entry) error
}

// Logger buffers decision entries and flushes them periodically.
// Failures are never silent: dropped entries are counted (Dropped) and
// failed flushes are logged through the injected zap logger.
type Logger struct {
	buffer        *Buffer
	sink          Sink
	flushSize     int
	flushInterval time.Duration
	logger        *zap.Logger
	stopCh        chan struct{}
	wg            sync.WaitGroup

	dropped       atomic.Uint64 // entries dropped because the buffer was full
	reportedDrops uint64        // drops already reported by the flush loop
	sendFailures  atomic.Uint64 // flush batches that failed to send
}

// NewLogger creates a decision logger with the given sink. A nil logger
// falls back to zap.NewNop().
func NewLogger(sink Sink, bufferSize, flushSize int, flushInterval time.Duration, logger *zap.Logger) *Logger {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Logger{
		buffer:        NewBuffer(bufferSize),
		sink:          sink,
		flushSize:     flushSize,
		flushInterval: flushInterval,
		logger:        logger,
		stopCh:        make(chan struct{}),
	}
}

// Log records a decision entry. Non-blocking — drops if buffer is full.
// Drops are counted and reported by the flush loop; use Dropped() to
// observe loss.
func (l *Logger) Log(entry Entry) {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	if !l.buffer.Push(entry) {
		l.dropped.Add(1)
	}
}

// Dropped returns the total number of entries dropped because the buffer
// was full.
func (l *Logger) Dropped() uint64 {
	return l.dropped.Load()
}

// SendFailures returns the total number of flush batches that failed to
// send to the sink. Entries in a failed batch are lost (by design — the
// hot path never blocks), but the loss is observable here and in logs.
func (l *Logger) SendFailures() uint64 {
	return l.sendFailures.Load()
}

// Start begins the background flush goroutine.
func (l *Logger) Start() {
	l.wg.Add(1)
	go l.flushLoop()
}

// Stop gracefully stops the logger and flushes remaining entries.
func (l *Logger) Stop() {
	close(l.stopCh)
	l.wg.Wait()
	l.flush() // Final flush.
}

func (l *Logger) flushLoop() {
	defer l.wg.Done()
	ticker := time.NewTicker(l.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-l.stopCh:
			return
		case <-ticker.C:
			l.flush()
		}
	}
}

func (l *Logger) flush() {
	// Report drops accumulated since the last flush. Drop accounting is
	// done here (not in Log) so the hot path stays log-free.
	if d := l.dropped.Load(); d > l.reportedDrops {
		l.logger.Warn("decision log entries dropped: buffer full",
			zap.Uint64("dropped_since_last_flush", d-l.reportedDrops),
			zap.Uint64("dropped_total", d))
		l.reportedDrops = d
	}

	entries := l.buffer.Drain(l.flushSize)
	if len(entries) == 0 {
		return
	}
	// Send never blocks the hot path; a failed batch is lost but the
	// failure is counted and logged.
	if err := l.sink.Send(entries); err != nil {
		l.sendFailures.Add(1)
		l.logger.Error("decision log flush failed; batch lost",
			zap.Error(err),
			zap.Int("entries", len(entries)),
			zap.Uint64("send_failures_total", l.sendFailures.Load()))
	}
}
