// Package redis implements a bounded Redis-shaped keyspace and protocol.
// No commands are executed on the host and no replication, scripts, modules,
// persistence, filesystem access, or outbound connections are implemented.
package redis

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"helix-honeypot/internal/netlimit"
	"helix-honeypot/logger"
	"helix-honeypot/model"
)

const (
	redisVersion       = "7.2.5"
	maxKeys            = 1024
	maxKeyBytes        = 1024
	maxValueBytes      = 16 << 10
	maxStoreBytes      = 8 << 20
	maxSessionBytes    = 1 << 20
	maxSessionCommands = 1024
	sessionLifetime    = 2 * time.Minute
)

type entry struct {
	value   string
	expires time.Time
}
type sensor struct {
	mu       sync.Mutex
	data     map[string]entry
	bytes    int
	password string
	port     string
	nextID   atomic.Int64
	events   *logger.EventLogger
}
type session struct {
	id            int64
	protocol      int
	authenticated bool
}
type result struct {
	value   any
	outcome string
	close   bool
}

func newSensor(cfg model.RedisConfig, events *logger.EventLogger) *sensor {
	s := &sensor{data: make(map[string]entry), password: cfg.Password, port: cfg.Port, events: events}
	for key, value := range map[string]string{"app:environment": "staging", "app:version": "1.0.0"} {
		s.data[key] = entry{value: value}
		s.bytes += len(key) + len(value)
	}
	return s
}

func StartRedisHoneypot(ctx context.Context, cfg *model.Config) error {
	if ctx == nil || cfg == nil {
		return errors.New("Redis sensor requires context and configuration")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	events, err := logger.NewEventLoggerFromConfig(nil, cfg)
	if err != nil {
		return err
	}
	defer events.Close()
	listener, err := net.Listen("tcp", net.JoinHostPort(cfg.Redis.Host, cfg.Redis.Port))
	if err != nil {
		return err
	}
	capped, err := netlimit.NewCappedListener(listener, 64)
	if err != nil {
		listener.Close()
		return err
	}
	defer capped.Close()
	s := newSensor(cfg.Redis, events)
	var handlers sync.WaitGroup
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			_ = capped.Close()
		case <-finished:
		}
	}()
	defer func() { cancel(); _ = capped.Close(); handlers.Wait() }()
	for {
		conn, err := capped.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		handlers.Add(1)
		go func() { defer handlers.Done(); s.serve(ctx, conn) }()
	}
}

func (s *sensor) serve(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-finished:
		}
	}()
	reader := bufio.NewReaderSize(io.LimitReader(conn, maxSessionBytes), 4096)
	state := &session{id: s.nextID.Add(1), protocol: 2, authenticated: s.password == ""}
	s.emit(conn, state, "session.open", "observed", 0, 0)
	deadline := time.Now().Add(sessionLifetime)
	input, output := 0, 0
	for i := 0; i < maxSessionCommands; i++ {
		readDeadline := time.Now().Add(10 * time.Second)
		if deadline.Before(readDeadline) {
			readDeadline = deadline
		}
		_ = conn.SetReadDeadline(readDeadline)
		args, n, err := readCommand(reader)
		input += n
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				s.emit(conn, state, "protocol.invalid", "rejected", n, 0)
			}
			return
		}
		if input > maxSessionBytes {
			s.emit(conn, state, "session.limit", "rejected", n, 0)
			return
		}
		command := strings.ToUpper(args[0])
		action := commandAction(command)
		result := s.handle(state, args)
		data := encode(result.value, state.protocol)
		if output+len(data) > maxSessionBytes {
			s.emit(conn, state, "session.limit", "rejected", n, 0)
			return
		}
		writeDeadline := time.Now().Add(5 * time.Second)
		if deadline.Before(writeDeadline) {
			writeDeadline = deadline
		}
		_ = conn.SetWriteDeadline(writeDeadline)
		written := 0
		for written < len(data) {
			count, err := conn.Write(data[written:])
			written += count
			if err != nil || count == 0 {
				s.emit(conn, state, action, "disconnected", n, written)
				return
			}
		}
		output += written
		outcome := result.outcome
		if outcome == "" {
			outcome = "simulated"
			if _, ok := result.value.(protocolError); ok {
				outcome = "rejected"
			}
		}
		s.emit(conn, state, action, outcome, n, written)
		if result.close {
			return
		}
	}
	s.emit(conn, state, "session.limit", "rejected", 0, 0)
}

func (s *sensor) emit(conn net.Conn, state *session, action, outcome string, received, sent int) {
	if s.events != nil {
		s.events.Write(model.Event{Sensor: "redis", SessionID: fmt.Sprintf("redis-%d", state.id), Action: action, Outcome: outcome, Profile: "redis/" + redisVersion, RemoteAddr: conn.RemoteAddr().String(), BytesReceived: int64(received), BytesSent: int64(sent)})
	}
}

func commandAction(command string) string {
	switch command {
	case "PING", "ECHO", "AUTH", "HELLO", "INFO", "SET", "GET", "DEL", "EXISTS", "DBSIZE", "INCR", "EXPIRE", "PEXPIRE", "TTL", "PTTL", "KEYS", "SCAN", "SELECT", "CLIENT", "COMMAND", "QUIT", "CONFIG", "EVAL", "EVALSHA", "SCRIPT", "MODULE", "SLAVEOF", "REPLICAOF", "SAVE", "BGSAVE", "RESTORE", "MIGRATE", "FLUSHALL", "FLUSHDB":
		return "command." + strings.ToLower(command)
	default:
		return "command.unknown"
	}
}

func failed(message string) result { return result{value: protocolError(message)} }
func arity() result                { return failed("ERR wrong number of arguments") }

func (s *sensor) handle(state *session, args []string) result {
	if len(args) == 0 {
		return arity()
	}
	command := strings.ToUpper(args[0])
	if command == "AUTH" {
		if len(args) != 2 && len(args) != 3 {
			return arity()
		}
		if s.password == "" {
			return failed("ERR AUTH called without any password configured")
		}
		username := "default"
		if len(args) == 3 {
			username = args[1]
		}
		state.authenticated = username == "default" && subtle.ConstantTimeCompare([]byte(args[len(args)-1]), []byte(s.password)) == 1
		if !state.authenticated {
			return failed("WRONGPASS invalid username-password pair")
		}
		return result{value: simple("OK"), outcome: "authenticated"}
	}
	if command == "HELLO" {
		return s.hello(state, args)
	}
	if !state.authenticated && command != "QUIT" {
		return failed("NOAUTH Authentication required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	switch command {
	case "PING":
		if len(args) == 1 {
			return result{value: simple("PONG")}
		}
		if len(args) == 2 {
			return result{value: bulk(args[1])}
		}
		return arity()
	case "ECHO":
		if len(args) != 2 {
			return arity()
		}
		return result{value: bulk(args[1])}
	case "QUIT":
		if len(args) != 1 {
			return arity()
		}
		return result{value: simple("OK"), close: true}
	case "INFO":
		if len(args) > 2 {
			return arity()
		}
		info := fmt.Sprintf("# Server\r\nredis_version:%s\r\nredis_mode:standalone\r\nos:Linux 6.8.0 x86_64\r\narch_bits:64\r\ntcp_port:%s\r\n# Clients\r\nconnected_clients:1\r\n# Memory\r\nused_memory:%d\r\n# Keyspace\r\ndb0:keys=%d,expires=0,avg_ttl=0\r\n", redisVersion, s.port, s.bytes, len(s.data))
		return result{value: bulk(info)}
	case "SELECT":
		if len(args) != 2 {
			return arity()
		}
		if args[1] != "0" {
			return failed("ERR DB index is out of range")
		}
		return result{value: simple("OK")}
	case "CLIENT":
		if len(args) < 2 {
			return arity()
		}
		switch strings.ToUpper(args[1]) {
		case "SETINFO":
			if len(args) != 4 {
				return arity()
			}
			return result{value: simple("OK")}
		case "SETNAME":
			if len(args) != 3 {
				return arity()
			}
			return result{value: simple("OK")}
		case "GETNAME":
			if len(args) != 2 {
				return arity()
			}
			return result{value: nil}
		case "ID":
			if len(args) != 2 {
				return arity()
			}
			return result{value: state.id}
		default:
			return failed("ERR CLIENT subcommand unavailable")
		}
	case "COMMAND":
		return result{value: []any{}}
	case "GET":
		if len(args) != 2 {
			return arity()
		}
		if value, ok := s.data[args[1]]; ok {
			return result{value: bulk(value.value)}
		}
		return result{value: nil}
	case "SET":
		return s.set(args)
	case "DBSIZE":
		if len(args) != 1 {
			return arity()
		}
		return result{value: len(s.data)}
	case "DEL", "EXISTS":
		if len(args) < 2 {
			return arity()
		}
		count := 0
		for _, key := range args[1:] {
			if value, ok := s.data[key]; ok {
				count++
				if command == "DEL" {
					delete(s.data, key)
					s.bytes -= len(key) + len(value.value)
				}
			}
		}
		return result{value: count}
	case "INCR":
		if len(args) != 2 {
			return arity()
		}
		old, exists := s.data[args[1]]
		value := int64(0)
		if exists {
			var err error
			value, err = strconv.ParseInt(old.value, 10, 64)
			if err != nil || value == int64(^uint64(0)>>1) {
				return failed("ERR value is not an integer or out of range")
			}
		}
		value++
		text := strconv.FormatInt(value, 10)
		if err := s.put(args[1], entry{value: text, expires: old.expires}); err != nil {
			return failed("OOM simulated keyspace capacity reached")
		}
		return result{value: value}
	case "EXPIRE", "PEXPIRE":
		if len(args) != 3 {
			return arity()
		}
		duration, err := strconv.ParseInt(args[2], 10, 64)
		limit := int64(86400)
		unit := time.Second
		if command == "PEXPIRE" {
			limit *= 1000
			unit = time.Millisecond
		}
		if err != nil || duration > limit {
			return failed("ERR invalid expiry time")
		}
		value, ok := s.data[args[1]]
		if !ok {
			return result{value: 0}
		}
		if duration <= 0 {
			delete(s.data, args[1])
			s.bytes -= len(args[1]) + len(value.value)
		} else {
			value.expires = time.Now().Add(time.Duration(duration) * unit)
			s.data[args[1]] = value
		}
		return result{value: 1}
	case "TTL", "PTTL":
		if len(args) != 2 {
			return arity()
		}
		value, ok := s.data[args[1]]
		if !ok {
			return result{value: -2}
		}
		if value.expires.IsZero() {
			return result{value: -1}
		}
		duration := time.Until(value.expires)
		if command == "PTTL" {
			return result{value: duration.Milliseconds()}
		}
		return result{value: int64(duration / time.Second)}
	case "KEYS":
		if len(args) != 2 {
			return arity()
		}
		if !validPattern(args[1]) {
			return failed("ERR only exact and prefix patterns are supported")
		}
		keys := []string{}
		for _, key := range s.keys() {
			if matches(key, args[1]) {
				keys = append(keys, key)
			}
		}
		if len(keys) > 128 {
			return failed("ERR use SCAN for this keyspace")
		}
		return result{value: keyArray(keys)}
	case "SCAN":
		return s.scan(args)
	case "CONFIG", "EVAL", "EVALSHA", "SCRIPT", "MODULE", "SLAVEOF", "REPLICAOF", "SAVE", "BGSAVE", "RESTORE", "MIGRATE", "FLUSHALL", "FLUSHDB":
		return result{value: protocolError("ERR command disabled"), outcome: "refused"}
	default:
		return failed("ERR unknown command")
	}
}

func (s *sensor) hello(state *session, args []string) result {
	protocol := state.protocol
	if len(args) > 1 {
		parsed, err := strconv.Atoi(args[1])
		if err != nil || (parsed != 2 && parsed != 3) {
			return failed("NOPROTO unsupported protocol version")
		}
		protocol = parsed
	}
	username, password := "", ""
	auth := false
	for i := 2; i < len(args); {
		switch strings.ToUpper(args[i]) {
		case "AUTH":
			if i+2 >= len(args) || auth {
				return failed("ERR syntax error")
			}
			auth = true
			username, password = args[i+1], args[i+2]
			i += 3
		case "SETNAME":
			if i+1 >= len(args) {
				return failed("ERR syntax error")
			}
			i += 2
		default:
			return failed("ERR syntax error")
		}
	}
	if auth {
		if s.password != "" && (username != "default" || subtle.ConstantTimeCompare([]byte(password), []byte(s.password)) != 1) {
			return failed("WRONGPASS invalid username-password pair")
		}
		if username != "default" {
			return failed("WRONGPASS invalid username-password pair")
		}
		state.authenticated = true
	}
	if !state.authenticated {
		return failed("NOAUTH Authentication required")
	}
	state.protocol = protocol
	return result{value: respMap{bulk("server"), bulk("redis"), bulk("version"), bulk(redisVersion), bulk("proto"), protocol, bulk("id"), state.id, bulk("mode"), bulk("standalone"), bulk("role"), bulk("master"), bulk("modules"), []any{}}}
}

func (s *sensor) set(args []string) result {
	if len(args) < 3 {
		return arity()
	}
	key, value := args[1], args[2]
	expires := time.Time{}
	nx, xx := false, false
	expiry := false
	for i := 3; i < len(args); i++ {
		switch strings.ToUpper(args[i]) {
		case "NX":
			if nx || xx {
				return failed("ERR syntax error")
			}
			nx = true
		case "XX":
			if nx || xx {
				return failed("ERR syntax error")
			}
			xx = true
		case "EX", "PX":
			if i+1 >= len(args) || expiry {
				return failed("ERR syntax error")
			}
			unit := time.Second
			limit := int64(86400)
			if strings.EqualFold(args[i], "PX") {
				unit = time.Millisecond
				limit *= 1000
			}
			duration, err := strconv.ParseInt(args[i+1], 10, 64)
			if err != nil || duration < 1 || duration > limit {
				return failed("ERR invalid expiry time")
			}
			expires = time.Now().Add(time.Duration(duration) * unit)
			expiry = true
			i++
		default:
			return failed("ERR syntax error")
		}
	}
	_, exists := s.data[key]
	if (nx && exists) || (xx && !exists) {
		return result{value: nil}
	}
	if err := s.put(key, entry{value: value, expires: expires}); err != nil {
		return failed("OOM simulated keyspace capacity reached")
	}
	return result{value: simple("OK")}
}

func (s *sensor) put(key string, value entry) error {
	if len(key) > maxKeyBytes || len(value.value) > maxValueBytes {
		return errors.New("entry too large")
	}
	old, exists := s.data[key]
	cost := len(key) + len(value.value)
	if exists {
		cost -= len(key) + len(old.value)
	}
	if (!exists && len(s.data) >= maxKeys) || s.bytes+cost > maxStoreBytes {
		return errors.New("keyspace full")
	}
	s.data[key] = value
	s.bytes += cost
	return nil
}
func (s *sensor) prune() {
	now := time.Now()
	for key, value := range s.data {
		if !value.expires.IsZero() && !now.Before(value.expires) {
			delete(s.data, key)
			s.bytes -= len(key) + len(value.value)
		}
	}
}
func (s *sensor) keys() []string {
	keys := make([]string, 0, len(s.data))
	for key := range s.data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
func keyArray(keys []string) []any {
	items := make([]any, 0, len(keys))
	for _, key := range keys {
		items = append(items, bulk(key))
	}
	return items
}
func (s *sensor) scan(args []string) result {
	if len(args) < 2 {
		return arity()
	}
	cursor, err := strconv.Atoi(args[1])
	if err != nil || cursor < 0 || cursor > maxKeys {
		return failed("ERR invalid cursor")
	}
	count := 10
	pattern := "*"
	for i := 2; i < len(args); i += 2 {
		if i+1 >= len(args) {
			return failed("ERR syntax error")
		}
		switch strings.ToUpper(args[i]) {
		case "COUNT":
			parsed, err := strconv.Atoi(args[i+1])
			if err != nil || parsed < 1 {
				return failed("ERR invalid count")
			}
			count = min(parsed, 100)
		case "MATCH":
			pattern = args[i+1]
		default:
			return failed("ERR syntax error")
		}
	}
	keys := s.keys()
	if !validPattern(pattern) {
		return failed("ERR only exact and prefix patterns are supported")
	}
	end := min(cursor+count, len(keys))
	items := []any{}
	if cursor < len(keys) {
		for _, key := range keys[cursor:end] {
			if matches(key, pattern) {
				items = append(items, bulk(key))
			}
		}
	}
	next := end
	if end >= len(keys) {
		next = 0
	}
	return result{value: []any{bulk(strconv.Itoa(next)), items}}
}

func validPattern(pattern string) bool {
	if len(pattern) > maxKeyBytes || strings.ContainsAny(pattern, "?[]\\") {
		return false
	}
	return !strings.Contains(pattern, "*") || (strings.HasSuffix(pattern, "*") && strings.Count(pattern, "*") == 1)
}
func matches(key, pattern string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(key, strings.TrimSuffix(pattern, "*"))
	}
	return key == pattern
}
