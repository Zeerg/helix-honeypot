// Package ai provides bounded Ollama, OpenAI and Anthropic HTTP façades.
// Responses are synthetic. Input never reaches a model, tool, URL or file.
package ai

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"helix-honeypot/internal/netlimit"
	"helix-honeypot/logger"
	"helix-honeypot/model"
)

const (
	maxBody         = 64 << 10
	maxOutput       = 32 << 10
	maxItems        = 128
	maxDepth        = 32
	maxRequests     = 128
	sessionLifetime = 2 * time.Minute
	cannedText      = "Hello! How can I help you today?"
	ollamaModel     = "llama3.2:latest"
	openaiModel     = "gpt-4o-mini"
	anthropicModel  = "claude-3-5-sonnet-latest"
)

var modelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

type object = map[string]any

type sessionKey struct{}
type session struct {
	id       string
	opened   time.Time
	requests atomic.Int32
}
type sensor struct {
	events *logger.EventLogger
	token  string
	work   chan struct{}
	ids    atomic.Uint64
}

// NewHandler creates a stateless synthetic gateway. token is optional and
// must be synthetic; startup validation bounds its size. No payload is retained.
func NewHandler(events *logger.EventLogger, token string) http.Handler {
	return &sensor{events: events, token: token, work: make(chan struct{}, 32)}
}

func StartAIHoneypot(ctx context.Context, cfg *model.Config) error {
	if ctx == nil || cfg == nil {
		return errors.New("AI sensor requires context and configuration")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	events, err := logger.NewEventLoggerFromConfig(nil, cfg)
	if err != nil {
		return err
	}
	defer events.Close()
	listener, err := net.Listen("tcp", net.JoinHostPort(cfg.AI.Host, cfg.AI.Port))
	if err != nil {
		return err
	}
	capped, err := netlimit.NewCappedListener(listener, 64)
	if err != nil {
		listener.Close()
		return err
	}
	defer capped.Close()
	s := NewHandler(events, cfg.AI.Token).(*sensor)
	srv := &http.Server{Handler: s, BaseContext: func(net.Listener) context.Context { return ctx }, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10,
		// Request-derived errors can contain request bytes; event logging below is
		// the sole sensor telemetry path.
		ErrorLog: log.New(io.Discard, "", 0),
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, sessionKey{}, &session{id: fmt.Sprintf("ai-%d", s.ids.Add(1)), opened: time.Now()})
		},
	}
	finished := make(chan struct{})
	stopped := make(chan struct{})
	defer close(finished)
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdown)
			_ = srv.Close()
		case <-finished:
		}
	}()
	err = srv.Serve(capped)
	if ctx.Err() != nil {
		<-stopped
	}
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

type result struct {
	code                         int
	frames                       [][]byte
	contentType, outcome, detail string
}

func jsonResult(code int, value any) result {
	data, err := json.Marshal(value)
	if err != nil {
		return result{code: 500, contentType: "application/json", frames: [][]byte{[]byte(`{"error":"response unavailable"}`)}}
	}
	return result{code: code, contentType: "application/json", frames: [][]byte{data}}
}
func failure(profile string, code int, message string) result {
	kind := "invalid_request_error"
	if code == 401 {
		kind = "authentication_error"
	}
	if code == 404 {
		kind = "not_found_error"
	}
	if code == 429 || code == 503 {
		kind = "rate_limit_error"
	}
	if profile == "ollama" {
		return jsonResult(code, object{"error": message})
	}
	e := object{"type": kind, "message": message}
	if profile == "anthropic" {
		return jsonResult(code, object{"type": "error", "error": e})
	}
	e["param"] = nil
	e["code"] = nil
	return jsonResult(code, object{"error": e})
}
func profileFor(path string) string {
	if path == "/v1/messages" || path == "/v1/messages/count_tokens" {
		return "anthropic"
	}
	if strings.HasPrefix(path, "/v1/") {
		return "openai"
	}
	return "ollama"
}

// All routes and actions used by telemetry are constants. Unknown paths,
// model strings, auth headers, prompts, URLs and tool names never enter logs.
func route(path string) (method, action string) {
	switch path {
	case "/":
		return "GET", "health"
	case "/api/version":
		return "GET", "version"
	case "/api/tags", "/api/ps", "/v1/models":
		return "GET", "models.list"
	case "/api/show":
		return "POST", "models.inspect"
	case "/api/chat", "/v1/chat/completions", "/v1/messages":
		return "POST", "inference.chat"
	case "/api/generate":
		return "POST", "inference.generate"
	case "/v1/responses":
		return "POST", "inference.responses"
	case "/v1/messages/count_tokens":
		return "POST", "tokens.count"
	case "/api/pull", "/api/push", "/api/create", "/api/copy":
		return "POST", "models.modify"
	case "/api/delete":
		return "DELETE", "models.modify"
	default:
		return "", "unknown"
	}
}
func (s *sensor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	profile := profileFor(r.URL.Path)
	expected, action := route(r.URL.Path)
	logPath := r.URL.Path
	if expected == "" {
		logPath = "/unknown"
	}
	logMethod := r.Method
	switch logMethod {
	case "GET", "HEAD", "POST", "DELETE", "PUT", "PATCH", "OPTIONS":
	default:
		logMethod = "OTHER"
	}
	var received int64
	sessionID := ""
	result := failure(profile, 500, "response unavailable")
	defer func() {
		outcome := result.outcome
		if outcome == "" {
			outcome = "simulated"
			if result.code >= 400 {
				outcome = "rejected"
			}
		}
		total := 0
		for _, frame := range result.frames {
			total += len(frame)
		}
		if total > maxOutput {
			result = failure(profile, 500, "response unavailable")
			outcome = "rejected"
		}
		w.Header().Set("Content-Type", result.contentType)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(result.code)
		sent := 0
		if r.Method != "HEAD" {
			for _, frame := range result.frames {
				if r.Context().Err() != nil {
					outcome = "interrupted"
					break
				}
				n, err := w.Write(frame)
				sent += n
				if err != nil {
					outcome = "interrupted"
					break
				}
				if strings.Contains(result.contentType, "stream") || result.contentType == "application/x-ndjson" {
					if err := http.NewResponseController(w).Flush(); err != nil {
						outcome = "interrupted"
						break
					}
				}
			}
		}
		if s.events != nil {
			s.events.Write(model.Event{Sensor: "ai", SessionID: sessionID, RemoteAddr: r.RemoteAddr, Method: logMethod, Path: logPath, Action: action, Outcome: outcome, Profile: profile, StatusCode: result.code, BytesReceived: received, BytesSent: int64(sent), Detail: result.detail})
		}
	}()
	if conn, ok := r.Context().Value(sessionKey{}).(*session); ok {
		sessionID = conn.id
		if conn.requests.Add(1) > maxRequests || time.Since(conn.opened) > sessionLifetime {
			w.Header().Set("Connection", "close")
			result = failure(profile, 429, "session limit exceeded")
			return
		}
	}
	if len(r.URL.Path) > 4096 || len(r.URL.RawQuery) > 8192 {
		result = failure(profile, 414, "request target too long")
		return
	}
	if r.Context().Err() != nil {
		result = failure(profile, 408, "request cancelled")
		return
	}
	select {
	case s.work <- struct{}{}:
		defer func() { <-s.work }()
	default:
		result = failure(profile, 503, "sensor capacity exceeded")
		return
	}
	if s.token != "" {
		provided := ""
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			provided = strings.TrimPrefix(auth, "Bearer ")
		}
		if profile == "anthropic" {
			provided = r.Header.Get("x-api-key")
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) != 1 {
			result = failure(profile, 401, "invalid authentication")
			return
		}
	}
	if r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity" {
		result = failure(profile, 415, "compressed requests are unsupported")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	received = int64(len(body))
	if err != nil {
		var size *http.MaxBytesError
		code := 400
		if errors.As(err, &size) {
			code = 413
		}
		result = failure(profile, code, "invalid or oversized body")
		return
	}
	if expected == "" {
		result = failure(profile, 404, "endpoint unavailable")
		return
	}
	if r.Method != expected && !(expected == "GET" && r.Method == "HEAD") {
		w.Header().Set("Allow", expected)
		result = failure(profile, 405, "method not allowed")
		return
	}
	if expected == "GET" {
		result = s.discovery(r.URL.Path)
		return
	}
	req, err := decode(body)
	if err != nil {
		result = failure(profile, 400, "invalid request object")
		return
	}
	if action == "models.modify" {
		result = failure(profile, 501, "model management unavailable")
		result.outcome = "refused"
		return
	}
	result = s.respond(r.URL.Path, profile, req)
}

// Check nesting before decoding so attacker-controlled JSON cannot consume a
// deep parser stack. The standard decoder remains responsible for JSON syntax.
func decode(body []byte) (object, error) {
	depth := 0
	quoted := false
	escaped := false
	for _, c := range body {
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		switch c {
		case '"':
			quoted = true
		case '{', '[':
			depth++
			if depth > maxDepth {
				return nil, errors.New("nesting limit")
			}
		case '}', ']':
			depth--
		}
	}
	var req object
	if err := json.Unmarshal(body, &req); err != nil || req == nil {
		return nil, errors.New("invalid object")
	}
	return req, nil
}
func selectedModel(req object) (string, bool) {
	name, ok := req["model"].(string)
	if !ok || !modelPattern.MatchString(name) {
		return "", false
	}
	switch name {
	case "llama3.2":
		name = ollamaModel
	}
	return name, true
}
func streamFlag(req object, defaultValue bool) (bool, bool) {
	raw, exists := req["stream"]
	if !exists {
		return defaultValue, true
	}
	value, ok := raw.(bool)
	return value, ok
}
func itemCount(req object, key string, required bool) (int, bool) {
	raw, exists := req[key]
	if !exists {
		return 0, !required
	}
	items, ok := raw.([]any)
	if !ok || len(items) > maxItems || (required && len(items) == 0) {
		return 0, false
	}
	for _, item := range items {
		if _, ok := item.(map[string]any); !ok {
			return 0, false
		}
	}
	return len(items), true
}
func validMessages(req object) bool {
	messages, _ := req["messages"].([]any)
	for _, raw := range messages {
		msg := raw.(map[string]any)
		role, _ := msg["role"].(string)
		switch role {
		case "user", "assistant", "system", "developer", "tool":
		default:
			return false
		}
		switch content := msg["content"].(type) {
		case string:
		case []any:
			if len(content) > maxItems {
				return false
			}
			for _, raw := range content {
				if _, ok := raw.(map[string]any); !ok {
					return false
				}
			}
		case nil:
			if role != "assistant" {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func (s *sensor) respond(path, profile string, req object) result {
	name, ok := selectedModel(req)
	if !ok {
		return failure(profile, 400, "model is required")
	}
	if name != ollamaModel && name != openaiModel && name != anthropicModel {
		return failure(profile, 404, "model unavailable")
	}
	if path == "/api/show" {
		return jsonResult(200, object{"details": modelDetails(), "model_info": object{"general.architecture": "llama", "llama.context_length": 8192}, "capabilities": []string{"completion"}, "parameters": "temperature 0.7"})
	}
	stream, ok := streamFlag(req, strings.HasPrefix(path, "/api/"))
	if !ok {
		return failure(profile, 400, "stream must be boolean")
	}
	tools, ok := itemCount(req, "tools", false)
	if !ok {
		return failure(profile, 400, "invalid tools")
	}
	messages := 0
	if path == "/api/chat" || path == "/v1/chat/completions" || strings.HasPrefix(path, "/v1/messages") {
		messages, ok = itemCount(req, "messages", true)
		if !ok || !validMessages(req) {
			return failure(profile, 400, "invalid messages")
		}
	}
	if path == "/api/generate" {
		if raw, exists := req["prompt"]; exists {
			if _, ok := raw.(string); !ok {
				return failure(profile, 400, "invalid prompt")
			}
		}
	}
	if path == "/v1/responses" {
		switch input := req["input"].(type) {
		case string:
		case []any:
			if len(input) == 0 || len(input) > maxItems {
				return failure(profile, 400, "invalid input")
			}
			for _, raw := range input {
				if _, ok := raw.(map[string]any); !ok {
					return failure(profile, 400, "invalid input")
				}
			}
		default:
			return failure(profile, 400, "input is required")
		}
		for _, key := range []string{"previous_response_id", "conversation"} {
			if req[key] != nil {
				return failure(profile, 400, "stored conversations unavailable")
			}
		}
		if req["background"] == true {
			return failure(profile, 400, "background responses unavailable")
		}
	}
	if path == "/v1/messages" {
		n, ok := req["max_tokens"].(float64)
		if !ok || n < 1 || n > 32768 || n != float64(int(n)) {
			return failure(profile, 400, "invalid max_tokens")
		}
	}
	if path == "/v1/chat/completions" {
		if n, exists := req["n"]; exists && n != float64(1) {
			return failure(profile, 400, "only one choice supported")
		}
	}
	text, tokens, ok := generatedText(req)
	if !ok {
		return failure(profile, 400, "invalid output limit")
	}
	id := fmt.Sprintf("%d-%d", time.Now().UnixNano(), s.ids.Add(1))
	var out result
	switch path {
	case "/api/chat", "/api/generate":
		out = ollamaReply(path, name, stream, text, tokens)
	case "/v1/chat/completions":
		out = chatReply(name, "chatcmpl-"+id, stream, req, text, tokens)
	case "/v1/responses":
		out = responsesReply(name, "resp_"+id, stream, text, tokens)
	case "/v1/messages":
		out = anthropicReply(name, "msg_"+id, stream, text, tokens)
	case "/v1/messages/count_tokens":
		out = jsonResult(200, object{"input_tokens": 1})
	default:
		out = failure(profile, 404, "endpoint unavailable")
	}
	out.detail = fmt.Sprintf("messages:%d tools:%d streaming:%t", messages, tools, stream)
	return out
}
func modelDetails() object {
	return object{"parent_model": "", "format": "gguf", "family": "llama", "families": []string{"llama"}, "parameter_size": "3.2B", "quantization_level": "Q4_K_M"}
}
func (s *sensor) discovery(path string) result {
	switch path {
	case "/":
		return result{code: 200, contentType: "text/plain", frames: [][]byte{[]byte("Ollama is running")}}
	case "/api/version":
		return jsonResult(200, object{"version": "0.5.7"})
	case "/api/tags", "/api/ps":
		return jsonResult(200, object{"models": []object{{"name": ollamaModel, "model": ollamaModel, "modified_at": "2025-01-01T00:00:00Z", "size": 2019393189, "digest": strings.Repeat("a", 64), "details": modelDetails()}}})
	case "/v1/models":
		models := []object{}
		for _, name := range []string{ollamaModel, openaiModel, anthropicModel} {
			models = append(models, object{"id": name, "object": "model", "created": 1735689600, "owned_by": "local"})
		}
		return jsonResult(200, object{"object": "list", "data": models})
	default:
		return failure("openai", 404, "endpoint unavailable")
	}
}
