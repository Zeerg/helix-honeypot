package model

// Event is the complete, deliberately small telemetry record emitted by a
// honeypot. Keep this schema free of request and response contents.
type Event struct {
	Timestamp     string `json:"timestamp"`
	EventID       string `json:"event_id"`
	Sensor        string `json:"sensor"`
	RemoteAddr    string `json:"remote_addr"`
	ClientAddr    string `json:"client_addr,omitempty"`
	Method        string `json:"method,omitempty"`
	Path          string `json:"path,omitempty"`
	StatusCode    int    `json:"status_code,omitempty"`
	BytesReceived int64  `json:"bytes_received,omitempty"`
	BytesSent     int64  `json:"bytes_sent,omitempty"`
	UserAgent     string `json:"user_agent,omitempty"`
}
