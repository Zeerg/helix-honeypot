package logger

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"helix-honeypot/model"
)

type capturedRequest struct {
	path          string
	authorization string
	contentType   string
	header        string
	body          string
}

func captureServer(t *testing.T, requests chan<- capturedRequest, headerName string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		requests <- capturedRequest{
			path:          r.URL.Path,
			authorization: r.Header.Get("Authorization"),
			contentType:   r.Header.Get("Content-Type"),
			header:        r.Header.Get(headerName),
			body:          string(body),
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return server
}

func awaitRequest(t *testing.T, requests <-chan capturedRequest) capturedRequest {
	t.Helper()
	select {
	case request := <-requests:
		return request
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for sink delivery")
		return capturedRequest{}
	}
}

func TestNewSinkRejectsUnknownType(t *testing.T) {
	if _, err := NewSink(model.LogSinkConfig{Type: "carrier-pigeon"}); err == nil {
		t.Fatal("NewSink() accepted an unregistered sink type")
	}
}

func TestFileSinkAppendsJSONLines(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "events.jsonl")
	sink, err := NewSink(model.LogSinkConfig{Type: "file", Path: filename})
	if err != nil {
		t.Fatalf("NewSink() error = %v", err)
	}
	sink.Emit(model.Event{Sensor: "tcp"}, []byte(`{"sensor":"tcp"}`))
	sink.Emit(model.Event{Sensor: "udp"}, []byte(`{"sensor":"udp"}`))
	if err := sink.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 2 {
		t.Fatalf("file sink wrote %d lines, want 2", len(lines))
	}
	for _, line := range lines {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("file sink line is not JSON: %v", err)
		}
	}
}

func TestSplunkSinkPostsHECFormat(t *testing.T) {
	requests := make(chan capturedRequest, 4)
	server := captureServer(t, requests, "")
	sink, err := NewSink(model.LogSinkConfig{
		Type: "splunk", URL: server.URL, Token: "synthetic-hec-token", Index: "honeypot",
	})
	if err != nil {
		t.Fatalf("NewSink() error = %v", err)
	}
	defer sink.Close()

	sink.Emit(model.Event{Sensor: "kubernetes", Timestamp: "2026-01-02T03:04:05Z"}, []byte(`{"sensor":"kubernetes"}`))
	request := awaitRequest(t, requests)

	if request.path != splunkHECEndpoint {
		t.Fatalf("splunk path = %q, want %q", request.path, splunkHECEndpoint)
	}
	if request.authorization != "Splunk synthetic-hec-token" {
		t.Fatalf("splunk authorization = %q", request.authorization)
	}
	for _, want := range []string{`"index":"honeypot"`, `,"event":{"sensor":"kubernetes"}`, `"sourcetype":"_json"`} {
		if !strings.Contains(request.body, want) {
			t.Fatalf("splunk body %q missing %q", request.body, want)
		}
	}
}

func TestElasticsearchSinkPostsBulkNDJSON(t *testing.T) {
	requests := make(chan capturedRequest, 4)
	server := captureServer(t, requests, "")
	sink, err := NewSink(model.LogSinkConfig{
		Type: "elasticsearch", URL: server.URL, Index: "honeypot-events", Token: "synthetic-api-key",
	})
	if err != nil {
		t.Fatalf("NewSink() error = %v", err)
	}
	defer sink.Close()

	sink.Emit(model.Event{Sensor: "http"}, []byte(`{"sensor":"http"}`))
	request := awaitRequest(t, requests)

	if request.path != "/_bulk" {
		t.Fatalf("elasticsearch path = %q, want /_bulk", request.path)
	}
	if request.authorization != "ApiKey synthetic-api-key" {
		t.Fatalf("elasticsearch authorization = %q", request.authorization)
	}
	if request.contentType != "application/x-ndjson" {
		t.Fatalf("elasticsearch content type = %q", request.contentType)
	}
	if !strings.Contains(request.body, `{"index":{"_index":"honeypot-events"}}`+"\n"+`{"sensor":"http"}`+"\n") {
		t.Fatalf("elasticsearch body is not bulk NDJSON: %q", request.body)
	}
}

func TestHTTPSinkSendsCustomHeadersAndBearer(t *testing.T) {
	requests := make(chan capturedRequest, 4)
	server := captureServer(t, requests, "X-Team")
	sink, err := NewSink(model.LogSinkConfig{
		Type: "http", URL: server.URL + "/ingest", Token: "synthetic-bearer",
		Headers: map[string]string{"X-Team": "secops"},
	})
	if err != nil {
		t.Fatalf("NewSink() error = %v", err)
	}
	defer sink.Close()

	sink.Emit(model.Event{Sensor: "udp"}, []byte(`{"sensor":"udp"}`))
	request := awaitRequest(t, requests)

	if request.path != "/ingest" {
		t.Fatalf("http sink path = %q, want /ingest", request.path)
	}
	if request.authorization != "Bearer synthetic-bearer" {
		t.Fatalf("http sink authorization = %q", request.authorization)
	}
	if request.header != "secops" {
		t.Fatalf("http sink custom header = %q", request.header)
	}
	if request.body != `{"sensor":"udp"}`+"\n" {
		t.Fatalf("http sink body = %q, want NDJSON line", request.body)
	}
}

func TestHTTPSinkKeepsConfiguredAuthorization(t *testing.T) {
	requests := make(chan capturedRequest, 4)
	server := captureServer(t, requests, "")
	sink, err := NewSink(model.LogSinkConfig{
		Type: "http", URL: server.URL, Token: "ignored",
		Headers: map[string]string{"Authorization": "Basic abc123"},
	})
	if err != nil {
		t.Fatalf("NewSink() error = %v", err)
	}
	defer sink.Close()

	sink.Emit(model.Event{Sensor: "udp"}, []byte(`{"sensor":"udp"}`))
	request := awaitRequest(t, requests)
	if request.authorization != "Basic abc123" {
		t.Fatalf("configured Authorization header was overridden: %q", request.authorization)
	}
}

func TestBatchShipperDropsWhenDestinationCannotKeepUp(t *testing.T) {
	release := make(chan struct{})
	shipper := newBatchShipper("test", func([]sinkPayload) error {
		<-release
		return nil
	})
	// The shipper may hold one in-flight batch while the queue fills; emit well
	// beyond both capacities so at least one event must drop.
	for i := 0; i < sinkQueueSize+sinkBatchEvents+1; i++ {
		shipper.Emit(model.Event{Sensor: "tcp"}, []byte(`{"sensor":"tcp"}`))
	}
	if dropped := shipper.dropped.Load(); dropped == 0 {
		t.Fatal("overwhelmed shipper did not drop any events")
	}
	close(release)
	if err := shipper.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestBatchShipperCloseFlushesQueuedEvents(t *testing.T) {
	requests := make(chan capturedRequest, 4)
	server := captureServer(t, requests, "")
	sink, err := newHTTPSink(model.LogSinkConfig{Type: "http", URL: server.URL})
	if err != nil {
		t.Fatalf("newHTTPSink() error = %v", err)
	}
	sink.Emit(model.Event{Sensor: "tcp"}, []byte(`{"sensor":"tcp"}`))
	if err := sink.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	request := awaitRequest(t, requests)
	if !strings.Contains(request.body, `{"sensor":"tcp"}`) {
		t.Fatalf("close did not flush queued event: %q", request.body)
	}
}

func TestEventLoggerFansOutToAttachedSinks(t *testing.T) {
	var output strings.Builder
	eventLogger := NewEventLogger(&output)
	received := make(chan []byte, 1)
	eventLogger.AttachSinks([]Sink{captureSink{received: received}})
	eventLogger.Write(model.Event{Sensor: "tcp", RemoteAddr: "127.0.0.1:9"})

	select {
	case payload := <-received:
		var event map[string]any
		if err := json.Unmarshal(payload, &event); err != nil {
			t.Fatalf("sink did not receive event JSON: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("attached sink did not receive the event")
	}
	if !strings.Contains(output.String(), `"sensor":"tcp"`) {
		t.Fatalf("local output missing event: %q", output.String())
	}
}

type captureSink struct {
	received chan []byte
}

func (s captureSink) Emit(_ model.Event, json []byte) {
	s.received <- json
}

func (s captureSink) Close() error { return nil }
