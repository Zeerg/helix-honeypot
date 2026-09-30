package redis

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"helix-honeypot/logger"
	"helix-honeypot/model"
)

func command(args ...string) []byte {
	items := make([]any, 0, len(args))
	for _, arg := range args {
		items = append(items, bulk(arg))
	}
	return encode(items, 2)
}
func testState() *session { return &session{id: 1, protocol: 2, authenticated: true} }
func call(s *sensor, state *session, args ...string) string {
	return string(encode(s.handle(state, args).value, state.protocol))
}

func TestRESPParsingAndLimits(t *testing.T) {
	valid := command("SET", "binary\x00key", "binary\r\nvalue")
	args, n, err := readCommand(bufio.NewReader(bytes.NewReader(valid)))
	if err != nil || n != len(valid) || args[2] != "binary\r\nvalue" {
		t.Fatalf("binary frame: %v %d %v", args, n, err)
	}
	if args, n, err := readCommand(bufio.NewReader(bytes.NewReader(append([]byte("\r\n\r\n"), valid...)))); err != nil || n != len(valid)+4 || args[0] != "SET" {
		t.Fatalf("pipe sentinel padding: %v %d %v", args, n, err)
	}
	if _, _, err := readCommand(bufio.NewReader(strings.NewReader(strings.Repeat("\r\n", maxCommandBytes/2+1)))); err == nil {
		t.Fatal("unbounded blank-line input")
	}
	for _, data := range []string{"*0\r\n", "*129\r\n", "*2\r\n$-1\r\n", "*1\r\n*1\r\n", "*1\r\n$999999999\r\n", "*1\r\n$4\r\nPING\n\n", "PING\n", strings.Repeat("x", 5000) + "\r\n", string(valid[:len(valid)-1])} {
		if _, _, err := readCommand(bufio.NewReader(strings.NewReader(data))); err == nil {
			t.Fatalf("accepted invalid frame %q", data[:min(len(data), 100)])
		}
	}
	large := command("SET", "key", strings.Repeat("x", maxBulkBytes), strings.Repeat("x", maxBulkBytes))
	if _, _, err := readCommand(bufio.NewReader(bytes.NewReader(large))); err == nil {
		t.Fatal("accepted aggregate frame over command budget")
	}
}

func TestAuthenticationAndRESP3(t *testing.T) {
	s := newSensor(model.RedisConfig{Password: "synthetic-password"}, nil)
	state := &session{protocol: 2}
	if got := call(s, state, "GET", "app:version"); !strings.HasPrefix(got, "-NOAUTH") {
		t.Fatal(got)
	}
	if got := call(s, state, "AUTH", "incorrect"); !strings.HasPrefix(got, "-WRONGPASS") || state.authenticated {
		t.Fatal(got)
	}
	if got := call(s, state, "HELLO", "3", "AUTH", "default", "synthetic-password"); !strings.HasPrefix(got, "%7\r\n") || state.protocol != 3 || !state.authenticated {
		t.Fatal(got)
	}
	if got := call(s, state, "GET", "missing"); got != "_\r\n" {
		t.Fatal(got)
	}
	if got := call(s, state, "HELLO", "9"); !strings.HasPrefix(got, "-NOPROTO") || state.protocol != 3 {
		t.Fatal(got)
	}
	other := &session{protocol: 2}
	if got := call(s, other, "PING"); !strings.HasPrefix(got, "-NOAUTH") {
		t.Fatal("authentication leaked across sessions", got)
	}
}

func TestKeyspaceExpiryConditionsAndScan(t *testing.T) {
	s := newSensor(model.RedisConfig{}, nil)
	state := testState()
	if got := call(s, state, "SET", "counter", "0", "NX"); got != "+OK\r\n" {
		t.Fatal(got)
	}
	if got := call(s, state, "SET", "counter", "100", "NX"); got != "$-1\r\n" {
		t.Fatal(got)
	}
	if got := call(s, state, "INCR", "counter"); got != ":1\r\n" {
		t.Fatal(got)
	}
	if got := call(s, state, "SET", "empty", ""); got != "+OK\r\n" {
		t.Fatal(got)
	}
	if got := call(s, state, "INCR", "empty"); !strings.HasPrefix(got, "-ERR") {
		t.Fatal(got)
	}
	if got := call(s, state, "SET", "expiring", "value", "PX", "1000"); got != "+OK\r\n" {
		t.Fatal(got)
	}
	if got := call(s, state, "PTTL", "expiring"); !strings.HasPrefix(got, ":") || got == ":-1\r\n" {
		t.Fatal(got)
	}
	s.mu.Lock()
	value := s.data["expiring"]
	value.expires = time.Now().Add(-time.Second)
	s.data["expiring"] = value
	s.mu.Unlock()
	if got := call(s, state, "GET", "expiring"); got != "$-1\r\n" {
		t.Fatal(got)
	}
	if got := call(s, state, "TTL", "expiring"); got != ":-2\r\n" {
		t.Fatal(got)
	}
	if got := call(s, state, "SCAN", "0", "MATCH", "app:*", "COUNT", "100"); !strings.Contains(got, "app:version") || strings.Contains(got, "counter") {
		t.Fatal(got)
	}
	if got := call(s, state, "SET", "counter", "2", "XX", "EX", "999999999999"); !strings.HasPrefix(got, "-ERR") {
		t.Fatal(got)
	}
}

func TestKeyspaceCapacityAndReclamation(t *testing.T) {
	s := newSensor(model.RedisConfig{}, nil)
	state := testState()
	if got := call(s, state, "SET", "oversize", strings.Repeat("x", maxValueBytes+1)); !strings.HasPrefix(got, "-OOM") {
		t.Fatal(got)
	}
	for i := 0; i < maxKeys-2; i++ {
		if got := call(s, state, "SET", fmt.Sprintf("key%d", i), "value"); got != "+OK\r\n" {
			t.Fatalf("key %d: %s", i, got)
		}
	}
	if got := call(s, state, "SET", "full", "value"); !strings.HasPrefix(got, "-OOM") {
		t.Fatal(got)
	}
	if got := call(s, state, "DEL", "key0"); got != ":1\r\n" {
		t.Fatal(got)
	}
	if got := call(s, state, "SET", "reclaimed", "value"); got != "+OK\r\n" {
		t.Fatal(got)
	}
	// Byte capacity is independent of the entry-count limit.
	s = newSensor(model.RedisConfig{}, nil)
	for i := 0; i < maxStoreBytes/maxValueBytes+2; i++ {
		got := call(s, state, "SET", fmt.Sprintf("large%d", i), strings.Repeat("x", maxValueBytes))
		if strings.HasPrefix(got, "-OOM") {
			if s.bytes > maxStoreBytes {
				t.Fatal("byte limit exceeded")
			}
			return
		}
	}
	t.Fatal("byte capacity was not enforced")
}

func TestRefusedCommandsHaveNoSideEffects(t *testing.T) {
	s := newSensor(model.RedisConfig{}, nil)
	state := testState()
	original := s.bytes
	for _, cmd := range []string{"EVAL", "MODULE", "REPLICAOF", "CONFIG", "BGSAVE", "MIGRATE", "FLUSHALL"} {
		result := s.handle(state, []string{cmd, "sensitive-argument"})
		if result.outcome != "refused" {
			t.Fatal(cmd, result)
		}
	}
	if s.bytes != original || len(s.data) != 2 {
		t.Fatal("refused command changed the keyspace")
	}
}

func TestPipelinedSessionsPrivacyAndCancellation(t *testing.T) {
	var events bytes.Buffer
	s := newSensor(model.RedisConfig{}, logger.NewEventLoggerWithConfig(&events, model.LoggingConfig{}, "sensitive-key", "sensitive-value"))
	server, client := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.serve(ctx, server); close(done) }()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	payload := append(command("SET", "sensitive-key", "sensitive-value"), command("GET", "sensitive-key")...)
	go func() {
		for _, b := range payload {
			if _, err := client.Write([]byte{b}); err != nil {
				return
			}
		}
	}()
	expected := "+OK\r\n$15\r\nsensitive-value\r\n"
	reply := make([]byte, len(expected))
	if _, err := io.ReadFull(client, reply); err != nil || string(reply) != expected {
		t.Fatalf("pipeline: %q %v", reply, err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle session did not cancel")
	}
	client.Close()
	if strings.Contains(events.String(), "sensitive-key") || strings.Contains(events.String(), "sensitive-value") || !strings.Contains(events.String(), "command.set") || !strings.Contains(events.String(), "session_id") {
		t.Fatalf("unsafe session events: %s", &events)
	}
}

func TestConcurrentKeyspace(t *testing.T) {
	s := newSensor(model.RedisConfig{}, nil)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			state := testState()
			for j := 0; j < 50; j++ {
				key := fmt.Sprintf("key-%d", i)
				_ = call(s, state, "SET", key, "value")
				_ = call(s, state, "SCAN", "0")
				_ = call(s, state, "DEL", key)
			}
		}(i)
	}
	wg.Wait()
}

func TestSessionOutputBudget(t *testing.T) {
	s := newSensor(model.RedisConfig{}, nil)
	if got := call(s, testState(), "SET", "large", strings.Repeat("x", maxValueBytes)); got != "+OK\r\n" {
		t.Fatal(got)
	}
	server, client := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.serve(ctx, server); close(done) }()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	response := encode(bulk(strings.Repeat("x", maxValueBytes)), 2)
	complete := 0
	for i := 0; i < 100; i++ {
		if _, err := client.Write(command("GET", "large")); err != nil {
			break
		}
		data := make([]byte, len(response))
		if _, err := io.ReadFull(client, data); err != nil {
			break
		}
		complete++
	}
	if complete == 0 || complete*len(response) > maxSessionBytes || complete == 100 {
		t.Fatalf("output budget not enforced: %d replies", complete)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("limited session did not close")
	}
}

func FuzzReadCommand(f *testing.F) {
	for _, frame := range [][]byte{command("PING"), command("SET", "key", "value"), []byte("*999999\r\n"), []byte("PING\r\n")} {
		f.Add(frame)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxCommandBytes+4096 {
			return
		}
		args, _, err := readCommand(bufio.NewReader(bytes.NewReader(data)))
		if err == nil && (len(args) == 0 || len(args) > maxArguments) {
			t.Fatal("unbounded command")
		}
	})
}
