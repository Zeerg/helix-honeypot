package logger

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/labstack/echo/v5"
	"uuid"

	"helix-honeypot/model"
)

// EventLogger writes one privacy-limited structured event per line.
type EventLogger struct {
	mu                sync.Mutex
	out               io.Writer
	format            string
	includeUserAgent  bool
	trustedProxyCIDRs []netip.Prefix
	sensitiveValues   *strings.Replacer
	sinks             []Sink
}

const (
	maxHTTPBody            = 64 * 1024
	maxUserAgentInputBytes = 64 * 1024
)

// NewEventLogger creates an event logger. A nil writer defaults to stdout.
func NewEventLogger(out io.Writer) *EventLogger {
	return NewEventLoggerWithConfig(out, model.LoggingConfig{})
}

// NewEventLoggerFromConfig builds the local event logger plus every configured
// remote sink. A sink failure closes anything already opened and aborts
// startup so operators notice a dead destination instead of losing events
// silently.
func NewEventLoggerFromConfig(out io.Writer, cfg *model.Config) (*EventLogger, error) {
	if cfg == nil {
		return nil, fmt.Errorf("event logger requires configuration")
	}
	sinks, err := NewSinks(cfg.Logging.Sinks)
	if err != nil {
		return nil, err
	}
	eventLogger := NewEventLoggerWithConfig(out, cfg.Logging, cfg.SensitiveValues()...)
	eventLogger.AttachSinks(sinks)
	return eventLogger, nil
}

// AttachSinks fans each sanitized event out to the given destinations after
// the local record is written.
func (l *EventLogger) AttachSinks(sinks []Sink) {
	if len(sinks) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sinks = append(l.sinks, sinks...)
}

// Close releases attached sinks and stops further fan-out. The local writer is
// caller-owned (stdout or a test buffer) and is left open.
func (l *EventLogger) Close() error {
	l.mu.Lock()
	sinks := l.sinks
	l.sinks = nil
	l.mu.Unlock()
	var first error
	for _, sink := range sinks {
		if err := sink.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// NewEventLoggerWithConfig creates an event logger using the configured
// output format and trusted proxy policy. Invalid formats and CIDRs fail
// closed to JSON output and an empty trusted-proxy list, respectively.
func NewEventLoggerWithConfig(out io.Writer, config model.LoggingConfig, sensitiveValues ...string) *EventLogger {
	if out == nil {
		out = os.Stdout
	}
	format := strings.ToLower(strings.TrimSpace(config.Format))
	if format != "text" {
		format = "json"
	}
	return &EventLogger{
		out:               out,
		format:            format,
		includeUserAgent:  config.IncludeUserAgent,
		trustedProxyCIDRs: parseTrustedProxyCIDRs(config.TrustedProxyCIDRs),
		sensitiveValues:   newSensitiveValueReplacer(sensitiveValues),
	}
}

// Write emits a normalized event as one line in the configured format. The
// lock keeps concurrent protocol handlers from interleaving shared output.
func (l *EventLogger) Write(event model.Event) {
	l.write(event, "")
}

func (l *EventLogger) write(event model.Event, trustedClientAddr string) {
	if l == nil || l.out == nil || !validSensor(event.Sensor) {
		return
	}

	now := time.Now().UTC()
	if parsed, err := time.Parse(time.RFC3339Nano, event.Timestamp); err == nil {
		event.Timestamp = parsed.UTC().Format(time.RFC3339Nano)
	} else {
		event.Timestamp = now.Format(time.RFC3339Nano)
	}
	if event.EventID == "" {
		event.EventID = uuid.New().String()
	}
	event.RemoteAddr = boundedText(event.RemoteAddr, 256)
	event.ClientAddr = normalizeIPString(trustedClientAddr)
	event.Method = sanitizeMethod(event.Method, l.sensitiveValues)
	event.Path = sanitizePathWithReplacer(event.Path, l.sensitiveValues)
	if l.includeUserAgent {
		event.UserAgent = sanitizeUserAgent(event.UserAgent, l.sensitiveValues)
	} else {
		event.UserAgent = ""
	}
	if event.StatusCode < 0 {
		event.StatusCode = 0
	}
	if event.BytesReceived < 0 {
		event.BytesReceived = 0
	}
	if event.BytesSent < 0 {
		event.BytesSent = 0
	}

	jsonLine, err := json.Marshal(event)
	if err != nil {
		return
	}
	line := jsonLine
	if l.format == "text" {
		line = marshalText(event)
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	for len(line) > 0 {
		n, writeErr := l.out.Write(line)
		if writeErr != nil || n <= 0 {
			return
		}
		line = line[n:]
	}
	for _, sink := range l.sinks {
		sink.Emit(event, jsonLine)
	}
}

// HTTPMiddleware records request metadata and byte counts without reading or
// retaining request or response contents. sensor must be one of the schema's
// protocol names.
func (l *EventLogger) HTTPMiddleware(sensor string) echo.MiddlewareFunc {
	if !validSensor(sensor) {
		sensor = "http"
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			req := c.Request()
			var received *countingReadCloser
			if req.Body != nil {
				boundedBody := http.MaxBytesReader(c.Response(), req.Body, maxHTTPBody)
				received = &countingReadCloser{ReadCloser: boundedBody}
				req.Body = received
				c.SetRequest(req)
			}

			err := next(c)
			if err != nil {
				// Resolve returned errors here so status and response size are
				// captured after the response. Error text is never exposed.
				if response, unwrapErr := echo.UnwrapResponse(c.Response()); unwrapErr == nil && !response.Committed {
					status := echo.StatusCode(err)
					if status < http.StatusBadRequest || status > 599 {
						status = http.StatusInternalServerError
					}
					_ = c.NoContent(status)
				}
			}
			if received != nil {
				// Generic honeypot handlers do not consume request bodies. Drain
				// only through the bounded reader, and discard every byte, so the
				// event still has an observed body-byte count without retaining data.
				_, _ = io.Copy(io.Discard, received)
			}

			remoteAddr := req.RemoteAddr
			path := ""
			if req.URL != nil {
				// Path only. RawQuery is intentionally never passed to telemetry.
				path = req.URL.Path
			}
			status := 0
			responseBytes := int64(0)
			if response, unwrapErr := echo.UnwrapResponse(c.Response()); unwrapErr == nil {
				status = response.Status
				responseBytes = response.Size
			}
			if status == 0 {
				status = http.StatusOK
			}
			var bytesReceived int64
			if received != nil {
				bytesReceived = atomic.LoadInt64(&received.count)
			}
			event := model.Event{
				Sensor:        sensor,
				RemoteAddr:    remoteAddr,
				Method:        req.Method,
				Path:          path,
				StatusCode:    status,
				BytesReceived: bytesReceived,
				BytesSent:     responseBytes,
			}
			clientAddr := clientAddrFromXFF(req.RemoteAddr, req.Header.Values("X-Forwarded-For"), l.trustedProxyCIDRs)
			if l.includeUserAgent {
				event.UserAgent = req.UserAgent()
			}
			l.write(event, clientAddr)
			return nil
		}
	}
}

type countingReadCloser struct {
	io.ReadCloser
	count int64
}

func (r *countingReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		atomic.AddInt64(&r.count, int64(n))
	}
	return n, err
}

func validSensor(sensor string) bool {
	switch sensor {
	case "http", "tcp", "udp", "kubernetes", "kubelet":
		return true
	default:
		return false
	}
}

func boundedText(value string, max int) string {
	if len(value) > max {
		value = value[:max]
	}
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		if r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		} else {
			b.WriteByte(' ')
		}
	}
	return strings.TrimSpace(b.String())
}

func sanitizePath(path string) string {
	return sanitizePathWithReplacer(path, nil)
}

func sanitizePathWithReplacer(path string, redactor *strings.Replacer) string {
	if path == "" {
		return ""
	}
	if len(path) > 8192 {
		return ""
	}
	for i := 0; i < 8; i++ {
		decoded, err := url.PathUnescape(path)
		if err != nil {
			if i == 0 {
				return ""
			}
			break
		}
		if decoded == path {
			break
		}
		path = decoded
		if len(path) > 8192 {
			return ""
		}
		if i == 7 {
			// Avoid logging a path that may still hide sensitive labels behind
			// excessive percent-encoding layers.
			if more, err := url.PathUnescape(path); err == nil && more != path {
				return ""
			}
		}
	}
	path = replaceSensitive(redactor, path)
	parts := strings.Split(path, "/")
	redactNext := false
	for i, part := range parts {
		if redactNext && part != "" {
			parts[i] = "[redacted]"
			redactNext = false
			continue
		}
		if sensitiveLabel(part) {
			redactNext = true
			continue
		}
		if containsSensitiveLabel(part) {
			parts[i] = "[redacted]"
			continue
		}
		if looksLikeSecret(part) {
			parts[i] = "[redacted]"
		}
	}
	return boundedText(strings.Join(parts, "/"), 2048)
}

func (l *EventLogger) redactSensitive(value string) string {
	if l == nil {
		return value
	}
	return replaceSensitive(l.sensitiveValues, value)
}

func replaceSensitive(redactor *strings.Replacer, value string) string {
	if redactor == nil || value == "" {
		return value
	}
	return redactor.Replace(value)
}

func newSensitiveValueReplacer(values []string) *strings.Replacer {
	const (
		maxValues       = 320
		maxSourceBytes  = 16 << 10
		maxVariantBytes = 256 << 10
	)
	variants := make(map[string]struct{})
	sourceBytes := 0
	variantBytes := 0
	for index, value := range values {
		if index >= maxValues || value == "" || len(value) > maxSourceBytes || sourceBytes+len(value) > maxSourceBytes {
			continue
		}
		sourceBytes += len(value)
		for _, variant := range []string{
			value,
			base64.StdEncoding.EncodeToString([]byte(value)),
			base64.RawStdEncoding.EncodeToString([]byte(value)),
			base64.URLEncoding.EncodeToString([]byte(value)),
			base64.RawURLEncoding.EncodeToString([]byte(value)),
			url.QueryEscape(value),
			url.PathEscape(value),
		} {
			if variant == "" {
				continue
			}
			if _, exists := variants[variant]; exists {
				continue
			}
			if variantBytes+len(variant) > maxVariantBytes {
				break
			}
			variants[variant] = struct{}{}
			variantBytes += len(variant)
		}
	}
	if len(variants) == 0 {
		return nil
	}
	ordered := make([]string, 0, len(variants))
	for variant := range variants {
		ordered = append(ordered, variant)
	}
	sort.Slice(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
	pairs := make([]string, 0, len(ordered)*2)
	for _, variant := range ordered {
		pairs = append(pairs, variant, "[redacted]")
	}
	return strings.NewReplacer(pairs...)
}

func sanitizeMethod(value string, redactor *strings.Replacer) string {
	if len(value) > maxUserAgentInputBytes {
		return ""
	}
	candidate := value
	for depth := 0; depth <= 8; depth++ {
		if hasCredentialMarker(candidate) {
			return ""
		}
		if replaceSensitive(redactor, candidate) != candidate {
			return "[redacted]"
		}
		decoded, err := url.PathUnescape(candidate)
		if err != nil {
			return ""
		}
		if decoded == candidate {
			return boundedText(value, 32)
		}
		if depth == 8 {
			return ""
		}
		candidate = decoded
	}
	return ""
}

func sanitizeUserAgent(value string, redactor *strings.Replacer) string {
	// Bound work, then scan the raw source before normalizing controls or
	// truncating output. Both operations could otherwise hide a honeytoken.
	if len(value) > maxUserAgentInputBytes {
		return ""
	}
	source := value
	candidate := source
	for depth := 0; depth <= 8; depth++ {
		if hasCredentialMarker(candidate) {
			return ""
		}
		if replaceSensitive(redactor, candidate) != candidate {
			return "[redacted]"
		}
		decoded, err := url.PathUnescape(candidate)
		if err != nil {
			return ""
		}
		if decoded == candidate {
			return boundedText(source, 512)
		}
		if depth == 8 {
			return ""
		}
		candidate = decoded
	}
	return ""
}

func hasCredentialMarker(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"bearer ", "token=", "access_token", "api_key", "apikey=", "secret=", "password="} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func sensitiveLabel(value string) bool {
	value = strings.ToLower(strings.NewReplacer("-", "", "_", "", ".", "").Replace(value))
	switch value {
	case "token", "tokens", "accesstoken", "refreshtoken", "idtoken", "secret", "secrets", "clientsecret", "password", "passwd", "authorization", "auth", "apikey", "key", "credential", "credentials", "cookie", "cookies", "bearer":
		return true
	default:
		return false
	}
}

func containsSensitiveLabel(value string) bool {
	for _, part := range strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return r == '-' || r == '_' || r == '.' || r == ':' || r == '?' || r == '&' || r == '=' || r == ';'
	}) {
		if sensitiveLabel(part) {
			return true
		}
	}
	return false
}

func looksLikeSecret(value string) bool {
	if len(value) < 12 {
		return false
	}
	var hasLower, hasUpper, hasDigit bool
	unique := make(map[rune]struct{}, len(value))
	for _, r := range value {
		if r >= 'a' && r <= 'z' {
			hasLower = true
		}
		if r >= 'A' && r <= 'Z' {
			hasUpper = true
		}
		if r >= '0' && r <= '9' {
			hasDigit = true
		}
		unique[r] = struct{}{}
	}
	if hasDigit && (hasLower || hasUpper) && len(unique) >= 6 {
		return true
	}
	return len(value) >= 20 && hasLower && hasUpper && len(unique) >= 10
}

func marshalText(event model.Event) []byte {
	line := make([]byte, 0, 256)
	line = appendTextString(line, "timestamp", event.Timestamp, false)
	line = appendTextString(line, "event_id", event.EventID, false)
	line = appendTextString(line, "sensor", event.Sensor, false)
	line = appendTextString(line, "remote_addr", event.RemoteAddr, false)
	line = appendTextString(line, "client_addr", event.ClientAddr, true)
	line = appendTextString(line, "method", event.Method, true)
	line = appendTextString(line, "path", event.Path, true)
	line = appendTextInt(line, "status_code", int64(event.StatusCode), true)
	line = appendTextInt(line, "bytes_received", event.BytesReceived, true)
	line = appendTextInt(line, "bytes_sent", event.BytesSent, true)
	line = appendTextString(line, "user_agent", event.UserAgent, true)
	return line
}

func appendTextString(line []byte, key, value string, optional bool) []byte {
	if optional && value == "" {
		return line
	}
	line = appendTextKey(line, key)
	line = strconv.AppendQuote(line, value)
	return line
}

func appendTextInt(line []byte, key string, value int64, optional bool) []byte {
	if optional && value == 0 {
		return line
	}
	line = appendTextKey(line, key)
	return strconv.AppendInt(line, value, 10)
}

func appendTextKey(line []byte, key string) []byte {
	if len(line) > 0 {
		line = append(line, ' ')
	}
	line = append(line, key...)
	return append(line, '=')
}

func parseTrustedProxyCIDRs(values []string) []netip.Prefix {
	trusted := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || prefix.Addr().Zone() != "" {
			continue
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				continue
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		trusted = append(trusted, prefix.Masked())
	}
	return trusted
}

func clientAddrFromXFF(remoteAddr string, forwardedValues []string, trusted []netip.Prefix) string {
	if len(trusted) == 0 || len(forwardedValues) == 0 {
		return ""
	}
	peer, ok := parseRemoteIP(remoteAddr)
	if !ok || !isTrustedProxy(peer, trusted) {
		return ""
	}

	const (
		maxForwardedBytes = 4096
		maxForwardedHops  = 32
	)
	hops := make([]netip.Addr, 0, len(forwardedValues))
	totalBytes := 0
	for _, value := range forwardedValues {
		totalBytes += len(value)
		if totalBytes > maxForwardedBytes {
			return ""
		}
		for _, field := range strings.Split(value, ",") {
			field = strings.TrimSpace(field)
			if field == "" || len(hops) >= maxForwardedHops {
				return ""
			}
			addr, err := netip.ParseAddr(field)
			if err != nil || addr.Zone() != "" {
				return ""
			}
			hops = append(hops, addr.Unmap())
		}
	}

	for i := len(hops) - 1; i >= 0; i-- {
		if isTrustedProxy(hops[i], trusted) {
			continue
		}
		return hops[i].String()
	}
	return ""
}

func parseRemoteIP(remoteAddr string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func isTrustedProxy(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, prefix := range trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func normalizeIPString(value string) string {
	if value == "" {
		return ""
	}
	addr, err := netip.ParseAddr(value)
	if err != nil || addr.Zone() != "" {
		return ""
	}
	return addr.Unmap().String()
}
