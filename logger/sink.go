package logger

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"helix-honeypot/model"
)

const (
	sinkQueueSize     = 1024
	sinkBatchEvents   = 64
	sinkBatchBytes    = 256 << 10
	sinkFlushInterval = time.Second
	sinkSendAttempts  = 2
	sinkRetryDelay    = 250 * time.Millisecond
)

// Sink is one additional destination for sanitized honeypot events. Emit
// receives the canonical JSON encoding of an already-redacted event and must
// never block the honeypot: implementations drop rather than stall.
type Sink interface {
	Emit(event model.Event, json []byte)
	Close() error
}

type sinkPayload struct {
	event model.Event
	json  []byte
}

// sinkFactories is the registry behind NewSink. Adding a destination means
// adding one entry here plus a constructor that returns a Sink.
var sinkFactories = map[string]func(model.LogSinkConfig) (Sink, error){
	"file":          newFileSink,
	"splunk":        newSplunkSink,
	"elasticsearch": newElasticsearchSink,
	"elk":           newElasticsearchSink,
	"http":          newHTTPSink,
}

// NewSink builds one sink from its type entry in the registry.
func NewSink(cfg model.LogSinkConfig) (Sink, error) {
	factory, ok := sinkFactories[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("unknown log sink type %q", cfg.Type)
	}
	return factory(cfg)
}

// NewSinks builds every configured sink. A failure closes the sinks that were
// already created so partial startup never leaks files or goroutines.
func NewSinks(cfgs []model.LogSinkConfig) ([]Sink, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}
	sinks := make([]Sink, 0, len(cfgs))
	for i, cfg := range cfgs {
		sink, err := NewSink(cfg)
		if err != nil {
			for _, opened := range sinks {
				_ = opened.Close()
			}
			return nil, fmt.Errorf("log sink %d (%s): %w", i+1, cfg.Type, err)
		}
		sinks = append(sinks, sink)
	}
	return sinks, nil
}

// batchShipper is the shared asynchronous machinery for remote sinks. Events
// accumulate in a bounded queue and ship in batches; a full queue or a failed
// delivery drops events rather than blocking or retrying forever.
type batchShipper struct {
	name    string
	queue   chan sinkPayload
	done    chan struct{}
	wg      sync.WaitGroup
	closed  atomic.Bool
	dropped atomic.Uint64
	send    func(batch []sinkPayload) error
}

func newBatchShipper(name string, send func([]sinkPayload) error) *batchShipper {
	shipper := &batchShipper{
		name:  name,
		queue: make(chan sinkPayload, sinkQueueSize),
		done:  make(chan struct{}),
		send:  send,
	}
	shipper.wg.Add(1)
	go shipper.run()
	return shipper
}

func (s *batchShipper) Emit(event model.Event, json []byte) {
	if s.closed.Load() {
		s.dropped.Add(1)
		return
	}
	select {
	case s.queue <- sinkPayload{event: event, json: json}:
	default:
		s.dropped.Add(1)
	}
}

// Close stops the shipper, drains whatever is still queued, and waits for the
// final delivery attempt. Delivery timeouts bound the total wait.
func (s *batchShipper) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		close(s.done)
	}
	s.wg.Wait()
	if dropped := s.dropped.Load(); dropped > 0 {
		slog.Warn("log sink dropped events", "sink", s.name, "events", dropped)
	}
	return nil
}

func (s *batchShipper) run() {
	defer s.wg.Done()
	ticker := time.NewTicker(sinkFlushInterval)
	defer ticker.Stop()
	batch := make([]sinkPayload, 0, sinkBatchEvents)
	batchBytes := 0
	flush := func() {
		s.deliver(batch)
		batch = batch[:0]
		batchBytes = 0
	}
	for {
		select {
		case payload := <-s.queue:
			batch = append(batch, payload)
			batchBytes += len(payload.json)
			if len(batch) >= sinkBatchEvents || batchBytes >= sinkBatchBytes {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-s.done:
			// Final drain: take what is still queued, ship it once, and exit.
			for {
				select {
				case payload := <-s.queue:
					batch = append(batch, payload)
					continue
				default:
					flush()
					return
				}
			}
		}
	}
}

func (s *batchShipper) deliver(batch []sinkPayload) {
	if len(batch) == 0 {
		return
	}
	var err error
	for attempt := 0; attempt < sinkSendAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(sinkRetryDelay)
		}
		if err = s.send(batch); err == nil {
			return
		}
	}
	s.dropped.Add(uint64(len(batch)))
	slog.Warn("log sink dropped a batch after send failures", "sink", s.name, "events", len(batch), "error", err)
}

// fileSink appends one JSON event per line to a local file. Writes are
// synchronous and serialized; file I/O is fast enough for honeypot volume and
// keeps the sink crash-safe.
type fileSink struct {
	mu     sync.Mutex
	file   *os.File
	closed bool
}

func newFileSink(cfg model.LogSinkConfig) (Sink, error) {
	file, err := os.OpenFile(cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open log sink file: %w", err)
	}
	return &fileSink{file: file}, nil
}

func (s *fileSink) Emit(_ model.Event, json []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	_, _ = s.file.Write(append(json, '\n'))
}

func (s *fileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.file.Close()
}
