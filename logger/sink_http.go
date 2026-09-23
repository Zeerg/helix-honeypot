package logger

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"helix-honeypot/model"
)

const (
	sinkHTTPTimeout   = 10 * time.Second
	sinkResponseDrain = 4 << 10
	splunkHECEndpoint = "/services/collector/event"
	defaultSourcetype = "_json"
	eventSourceName   = "helix-honeypot"
)

// newSinkHTTPClient builds a delivery client that never follows redirects, so
// honeypot events can only reach the endpoint the operator configured.
func newSinkHTTPClient() *http.Client {
	return &http.Client{
		Timeout: sinkHTTPTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			MaxIdleConns:        4,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}
}

func postBatch(client *http.Client, endpoint string, headers map[string]string, contentType string, body []byte) error {
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build log sink request: %w", err)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	request.Header.Set("Content-Type", contentType)
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("deliver log sink batch: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, sinkResponseDrain))
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("log sink endpoint returned status %d", response.StatusCode)
	}
	return nil
}

func mergeSinkHeaders(custom map[string]string, headers map[string]string) map[string]string {
	merged := make(map[string]string, len(custom)+len(headers))
	for name, value := range custom {
		merged[name] = value
	}
	for name, value := range headers {
		merged[name] = value
	}
	return merged
}

func hasHeader(headers map[string]string, name string) bool {
	for key := range headers {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

// newSplunkSink ships events to a Splunk HTTP Event Collector. A bare base URL
// gets the standard /services/collector/event path appended; an explicit path
// is used as given so token-based raw collectors also work.
func newSplunkSink(cfg model.LogSinkConfig) (Sink, error) {
	parsed, err := url.Parse(cfg.URL)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("invalid splunk url")
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = splunkHECEndpoint
	}
	endpoint := parsed.String()

	sourcetype := cfg.Sourcetype
	if sourcetype == "" {
		sourcetype = defaultSourcetype
	}
	headers := mergeSinkHeaders(cfg.Headers, nil)
	if cfg.Token != "" {
		headers["Authorization"] = "Splunk " + cfg.Token
	}
	client := newSinkHTTPClient()
	return newBatchShipper("splunk", func(batch []sinkPayload) error {
		return postBatch(client, endpoint, headers, "application/json", buildSplunkBody(batch, cfg.Index, cfg.Source, sourcetype))
	}), nil
}

// buildSplunkBody concatenates one HEC event object per record, which is the
// batch format the collector expects. Event fields stay nested under "event".
func buildSplunkBody(batch []sinkPayload, index, source, sourcetype string) []byte {
	var body bytes.Buffer
	for _, payload := range batch {
		body.WriteString(`{"time":`)
		body.WriteString(strconv.FormatFloat(hecTime(payload.event), 'f', -1, 64))
		body.WriteString(`,"host":`)
		body.WriteString(strconv.Quote(eventSourceName))
		body.WriteString(`,"sourcetype":`)
		body.WriteString(strconv.Quote(sourcetype))
		if index != "" {
			body.WriteString(`,"index":`)
			body.WriteString(strconv.Quote(index))
		}
		if source != "" {
			body.WriteString(`,"source":`)
			body.WriteString(strconv.Quote(source))
		}
		body.WriteString(`,"event":`)
		body.Write(payload.json)
		body.WriteByte('}')
	}
	return body.Bytes()
}

func hecTime(event model.Event) float64 {
	if timestamp, err := time.Parse(time.RFC3339Nano, event.Timestamp); err == nil {
		return float64(timestamp.Unix()) + float64(timestamp.Nanosecond())/1e9
	}
	return float64(time.Now().Unix())
}

// newElasticsearchSink ships events to the _bulk API as NDJSON, one
// index-action line plus one document line per event.
func newElasticsearchSink(cfg model.LogSinkConfig) (Sink, error) {
	endpoint := strings.TrimRight(cfg.URL, "/") + "/_bulk"
	headers := make(map[string]string, len(cfg.Headers)+1)
	if cfg.Token != "" {
		headers["Authorization"] = "ApiKey " + cfg.Token
	} else if cfg.Username != "" {
		credentials := cfg.Username + ":" + cfg.Password
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
	}
	headers = mergeSinkHeaders(cfg.Headers, headers)
	client := newSinkHTTPClient()
	action := `{"index":{"_index":` + strconv.Quote(cfg.Index) + `}}` + "\n"
	return newBatchShipper("elasticsearch", func(batch []sinkPayload) error {
		var body bytes.Buffer
		for _, payload := range batch {
			body.WriteString(action)
			body.Write(payload.json)
			body.WriteByte('\n')
		}
		return postBatch(client, endpoint, headers, "application/x-ndjson", body.Bytes())
	}), nil
}

// newHTTPSink is the generic webhook destination: newline-delimited JSON
// events with optional static headers and a shorthand Bearer token. It covers
// collectors like Vector, Fluent Bit http inputs, and custom pipelines.
func newHTTPSink(cfg model.LogSinkConfig) (Sink, error) {
	headers := mergeSinkHeaders(cfg.Headers, nil)
	if cfg.Token != "" && !hasHeader(headers, "Authorization") {
		headers["Authorization"] = "Bearer " + cfg.Token
	}
	client := newSinkHTTPClient()
	return newBatchShipper("http", func(batch []sinkPayload) error {
		var body bytes.Buffer
		for _, payload := range batch {
			body.Write(payload.json)
			body.WriteByte('\n')
		}
		return postBatch(client, cfg.URL, headers, "application/x-ndjson", body.Bytes())
	}), nil
}
