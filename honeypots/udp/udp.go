package udp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"helix-honeypot/logger"
	"helix-honeypot/model"
)

const (
	maxUDPDatagramSize = 65535
	udpPollInterval    = time.Second
)

// StartUDPHoneypot records datagram metadata and byte counts without retaining
// or replying with datagram contents.
func StartUDPHoneypot(ctx context.Context, cfg *model.Config) error {
	if cfg == nil {
		return errors.New("UDP honeypot requires configuration")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	addr := net.JoinHostPort(cfg.UDP.Host, cfg.UDP.Port)
	listener, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("listen UDP honeypot: %w", err)
	}
	defer listener.Close()

	eventLogger, err := logger.NewEventLoggerFromConfig(nil, cfg)
	if err != nil {
		return fmt.Errorf("configure event sinks: %w", err)
	}
	defer eventLogger.Close()
	buf := make([]byte, maxUDPDatagramSize)
	for {
		if ctx.Err() != nil {
			return nil
		}
		if err := listener.SetReadDeadline(time.Now().Add(udpPollInterval)); err != nil {
			return fmt.Errorf("set UDP honeypot read deadline: %w", err)
		}
		n, remote, err := listener.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return fmt.Errorf("read UDP honeypot datagram: %w", err)
		}
		eventLogger.Write(model.Event{
			Sensor:        "udp",
			RemoteAddr:    remote.String(),
			BytesReceived: int64(n),
		})
	}
}
