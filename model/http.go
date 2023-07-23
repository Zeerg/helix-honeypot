package model

import (
	"net/http"
	"github.com/sirupsen/logrus"
)

type HTTPLog struct {
	Method    string
	Path      string
	Query     string
	Status    int
	Response  int64
	UserAgent string
	RemoteIP  string
	Headers   http.Header
	MachineID string
	Location  string
}

func (h *HTTPLog) ToLogrusFields() logrus.Fields {
	return logrus.Fields{
		"method":     h.Method,
		"path":       h.Path,
		"query":      h.Query,
		"status":     h.Status,
		"response":   h.Response,
		"user-agent": h.UserAgent,
		"remote-ip":  h.RemoteIP,
		"headers":    h.Headers,
		"machine-id": h.MachineID,
		"location":   h.Location,
	}
}