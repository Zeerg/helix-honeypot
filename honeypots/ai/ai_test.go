package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"helix-honeypot/config"
	"helix-honeypot/logger"
	"helix-honeypot/model"
)

func request(h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestWireFormatsAndStreams(t *testing.T) {
	h := NewHandler(nil, "")
	tests := []struct{ path, body, needle, ctype string }{
		{"/api/chat", `{"model":"llama3.2","messages":[{"role":"user","content":"Hi"}],"stream":false}`, `"done":true`, "application/json"},
		{"/api/generate", `{"model":"llama3.2","prompt":"Hi"}`, `"done":false`, "application/x-ndjson"},
		{"/v1/chat/completions", `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`, `"object":"chat.completion"`, "application/json"},
		{"/v1/chat/completions", `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}],"stream":true,"stream_options":{"include_usage":true}}`, `data: [DONE]`, "text/event-stream"},
		{"/v1/responses", `{"model":"gpt-4o-mini","input":"Hi"}`, `"status":"completed"`, "application/json"},
		{"/v1/responses", `{"model":"gpt-4o-mini","input":"Hi","stream":true}`, `event: response.completed`, "text/event-stream"},
		{"/v1/messages", `{"model":"claude-3-5-sonnet-latest","max_tokens":64,"messages":[{"role":"user","content":[{"type":"text","text":"Hi"}]}]}`, `"stop_reason":"end_turn"`, "application/json"},
		{"/v1/messages", `{"model":"claude-3-5-sonnet-latest","max_tokens":64,"messages":[{"role":"user","content":"Hi"}],"stream":true}`, `event: message_stop`, "text/event-stream"},
	}
	for _, tc := range tests {
		t.Run(tc.path+tc.ctype, func(t *testing.T) {
			w := request(h, "POST", tc.path, tc.body, nil)
			if w.Code != 200 || w.Header().Get("Content-Type") != tc.ctype || !strings.Contains(w.Body.String(), tc.needle) {
				t.Fatalf("wire: %d %s", w.Code, w.Body)
			}
			if w.Body.Len() > maxOutput {
				t.Fatal("output limit")
			}
		})
	}
	for _, path := range []string{"/", "/api/version", "/api/tags", "/api/ps", "/v1/models"} {
		if w := request(h, "GET", path, "", nil); w.Code != 200 {
			t.Fatalf("discovery %s: %d", path, w.Code)
		}
	}
	if w := request(h, "HEAD", "/api/version", "", nil); w.Code != 200 || w.Body.Len() != 0 {
		t.Fatal("HEAD wrote body")
	}
	// Parse every semantic SSE frame and check lifecycle order and sequence.
	for _, path := range []string{"/v1/messages", "/v1/responses"} {
		body := `{"model":"gpt-4o-mini","input":"Hi","messages":[{"role":"user","content":"Hi"}],"max_tokens":64,"stream":true}`
		w := request(h, "POST", path, body, nil)
		sequence := 0
		for _, line := range strings.Split(w.Body.String(), "\n") {
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var event object
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
				t.Fatal(err)
			}
			if path == "/v1/responses" {
				if event["sequence_number"] != float64(sequence) {
					t.Fatal("sequence")
				}
				sequence++
			}
		}
		if path == "/v1/responses" && sequence != 9 {
			t.Fatal("missing terminal event")
		}
	}
}
func TestAuthenticationAndPrivateTelemetry(t *testing.T) {
	var logs bytes.Buffer
	secret := "synthetic-auth-needle"
	h := NewHandler(logger.NewEventLoggerWithConfig(&logs, model.LoggingConfig{IncludeUserAgent: true}, secret), secret)
	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"PROMPT-PRIVATE-NEEDLE"}],"tools":[{"type":"function","function":{"name":"TOOL-PRIVATE-NEEDLE","arguments":"ARGUMENT-PRIVATE-NEEDLE"}}],"metadata":{"password":"BODY-PRIVATE-NEEDLE"}}`
	for _, auth := range []string{"", "wrong", secret, "Bearer wrong"} {
		if w := request(h, "POST", "/v1/chat/completions", body, map[string]string{"Authorization": auth}); w.Code != 401 {
			t.Fatalf("accepted auth %q", auth)
		}
	}
	headers := map[string]string{"Authorization": "Bearer " + secret, "Cookie": "COOKIE-PRIVATE-NEEDLE", "User-Agent": "AGENT-PRIVATE-NEEDLE"}
	if w := request(h, "POST", "/v1/chat/completions?token=QUERY-PRIVATE-NEEDLE", body, headers); w.Code != 200 || strings.Contains(w.Body.String(), "PRIVATE-NEEDLE") {
		t.Fatalf("valid request: %d %s", w.Code, w.Body)
	}
	if w := request(h, "POST", "/v1/messages", `{"model":"claude-3-5-sonnet-latest","max_tokens":64,"messages":[{"role":"user","content":"Hi"}]}`, map[string]string{"x-api-key": secret}); w.Code != 200 {
		t.Fatal("Anthropic auth")
	}
	request(h, "GET", "/UNKNOWN-PRIVATE-NEEDLE", "", headers)
	request(h, "POST", "/v1/responses", `{"model":"MODEL-PRIVATE-NEEDLE","input":"Hi"}`, headers)
	for _, needle := range []string{secret, "PRIVATE-NEEDLE"} {
		if strings.Contains(logs.String(), needle) {
			t.Fatalf("private data leaked: %s", logs.String())
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var event model.Event
		if err := json.Unmarshal([]byte(line), &event); err != nil || event.Sensor != "ai" {
			t.Fatal("missing structured AI event")
		}
	}
	if !strings.Contains(logs.String(), "messages:1 tools:1") {
		t.Fatal("count telemetry missing")
	}
}
func TestInputAndCapacityLimits(t *testing.T) {
	h := NewHandler(nil, "").(*sensor)
	tests := []struct {
		body string
		code int
	}{
		{"", 400}, {"null", 400}, {"[]", 400}, {`{} {}`, 400}, {`{"model":"gpt-4o-mini","messages":null}`, 400},
		{`{"model":"gpt-4o-mini","messages":[true]}`, 400},
		{`{"model":"gpt-4o-mini","messages":[{"role":"user","content":42}]}`, 400},
		{`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}],"stream":"true"}`, 400},
		{`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}],"tools":[1]}`, 400},
		{`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}],"n":2}`, 400},
		{strings.Repeat(" ", maxBody+1), 413},
		{`{"x":` + strings.Repeat("[", maxDepth) + `0` + strings.Repeat("]", maxDepth) + `}`, 400},
		{`{"model":"gpt-4o-mini","messages":[` + strings.TrimSuffix(strings.Repeat(`{"role":"user","content":"hi"},`, maxItems+1), ",") + `]}`, 400},
	}
	for _, tc := range tests {
		if w := request(h, "POST", "/v1/chat/completions", tc.body, nil); w.Code != tc.code {
			t.Fatalf("limit: %d want %d, %.160s", w.Code, tc.code, tc.body)
		}
	}
	if w := request(h, "GET", "/api/version", "", map[string]string{"Content-Encoding": "gzip"}); w.Code != 415 {
		t.Fatal("compressed body accepted")
	}
	if w := request(h, "POST", "/api/version", "{}", nil); w.Code != 405 {
		t.Fatal("method")
	}
	// Hold 32 actual body reads, then prove a 33rd request is rejected and
	// capacity is reclaimed once those clients finish.
	released := make(chan struct{})
	var pending sync.WaitGroup
	for i := 0; i < 32; i++ {
		entered := make(chan struct{})
		r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		r.Body = &heldBody{entered: entered, released: released}
		pending.Go(func() { h.ServeHTTP(httptest.NewRecorder(), r) })
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("body read did not start")
		}
	}
	if w := request(h, "GET", "/api/version", "", nil); w.Code != 503 {
		t.Fatal("capacity")
	}
	close(released)
	pending.Wait()
	if w := request(h, "GET", "/api/version", "", nil); w.Code != 200 {
		t.Fatal("capacity not reclaimed")
	}
	for _, conn := range []*session{{id: "test", opened: time.Now().Add(-sessionLifetime - time.Second)}, {id: "test", opened: time.Now()}} {
		if time.Since(conn.opened) < sessionLifetime {
			conn.requests.Store(maxRequests)
		}
		r := httptest.NewRequest("GET", "/api/version", nil).WithContext(context.WithValue(context.Background(), sessionKey{}, conn))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 429 || w.Header().Get("Connection") != "close" {
			t.Fatal("session bound")
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("GET", "/api/version", nil).WithContext(cancelled)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 408 {
		t.Fatal("cancelled request")
	}
}
func TestUntrustedInputsNeverFetchOrExecute(t *testing.T) {
	var callbacks atomic.Int32
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { callbacks.Add(1) }))
	defer callback.Close()
	h := NewHandler(nil, "")
	body := fmt.Sprintf(`{"model":"gpt-4o-mini","input":[{"role":"user","content":[{"type":"input_image","image_url":%q}]}],"tools":[{"type":"mcp","server_url":%q},{"type":"code_interpreter","command":"touch /tmp/helix-must-not-execute"}]}`, callback.URL, callback.URL)
	if w := request(h, "POST", "/v1/responses", body, nil); w.Code != 200 || strings.Contains(w.Body.String(), callback.URL) {
		t.Fatalf("untrusted tools: %d", w.Code)
	}
	for _, path := range []string{"/api/pull", "/api/push", "/api/create", "/api/copy", "/api/delete"} {
		method := "POST"
		if path == "/api/delete" {
			method = "DELETE"
		}
		if w := request(h, method, path, fmt.Sprintf(`{"model":%q,"from":%q}`, callback.URL, callback.URL), nil); w.Code != 501 {
			t.Fatalf("mutation %s", path)
		}
	}
	if callbacks.Load() != 0 {
		t.Fatal("sensor made outbound request")
	}
	for _, body := range []string{`{"model":"gpt-4o-mini","input":"hi","previous_response_id":"resp_stored"}`, `{"model":"gpt-4o-mini","input":"hi","background":true}`} {
		if w := request(h, "POST", "/v1/responses", body, nil); w.Code != 400 {
			t.Fatal("accepted stored/background work")
		}
	}
}
func TestConcurrentRequests(t *testing.T) {
	var logs bytes.Buffer
	h := NewHandler(logger.NewEventLogger(&logs), "")
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Go(func() {
			w := request(h, "POST", "/v1/responses", `{"model":"gpt-4o-mini","input":"hi","stream":true}`, nil)
			if w.Code != 200 && w.Code != 503 {
				t.Errorf("concurrent %d", w.Code)
			}
		})
	}
	wg.Wait()
}
func TestListenerShutdown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	cfg := config.Defaults()
	cfg.RunMode.RunMode = "ai"
	cfg.AI.Port = strconv.Itoa(port)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- StartAIHoneypot(ctx, &cfg) }()
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	url := fmt.Sprintf("http://127.0.0.1:%d/api/version", port)
	connected := false
	for i := 0; i < 100; i++ {
		res, err := client.Get(url)
		if err == nil {
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			connected = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !connected {
		t.Fatal("listener never opened")
	}
	// A deliberately incomplete body must not keep shutdown alive beyond its bound.
	stalled, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	fmt.Fprint(stalled, "POST /api/chat HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000\r\n\r\n{")
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown leaked handler")
	}
	if conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
		conn.Close()
		t.Fatal("listener remained open")
	}
}
func FuzzDecode(f *testing.F) {
	for _, seed := range []string{`{"model":"gpt-4o-mini","input":"Hi"}`, `{"messages":[{"role":"user","content":"{}[]\\\""}]}`, `null`, `[]`, `{"x":[[[0]]]}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > maxBody {
			return
		}
		req, err := decode(body)
		if err == nil {
			if req == nil {
				t.Fatal("nil object")
			}
			_, _ = selectedModel(req)
			_, _ = itemCount(req, "tools", false)
		}
	})
}

type heldBody struct {
	entered  chan struct{}
	released chan struct{}
	once     sync.Once
}

func (b *heldBody) Read(_ []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.released
	return 0, io.EOF
}
func (b *heldBody) Close() error { return nil }

func TestSyntheticOutputBudgets(t *testing.T) {
	h := NewHandler(nil, "")
	for _, tc := range []struct{ path, body string }{
		{"/api/generate", `{"model":"llama3.2","prompt":"Hi","options":{"num_predict":1},"stream":false}`},
		{"/v1/chat/completions", `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}],"max_tokens":1}`},
		{"/v1/responses", `{"model":"gpt-4o-mini","input":"Hi","max_output_tokens":1}`},
		{"/v1/messages", `{"model":"claude-3-5-sonnet-latest","messages":[{"role":"user","content":"Hi"}],"max_tokens":1}`},
	} {
		w := request(h, "POST", tc.path, tc.body, nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), cannedText) || !strings.Contains(w.Body.String(), "Hello") {
			t.Fatalf("output budget %s %d %s", tc.path, w.Code, w.Body)
		}
	}
	for _, limit := range []string{"0", "-1", "1.5", "1e100", "true", "null"} {
		body := fmt.Sprintf(`{"model":"gpt-4o-mini","input":"Hi","max_output_tokens":%s}`, limit)
		if w := request(h, "POST", "/v1/responses", body, nil); w.Code != 400 {
			t.Fatalf("accepted invalid output limit %s", limit)
		}
	}
}
