package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"helix-honeypot/logger"
	"helix-honeypot/model"
)

const (
	maxTCPInput       = 64 * 1024
	tcpReadTimeout    = 5 * time.Second
	maxTCPConnections = 128
)

// StartTCPHoneypot accepts a bounded number of connections, reads a bounded
// amount for a bounded duration, and records only metadata and byte counts.
func StartTCPHoneypot(ctx context.Context, cfg *model.Config) error {
	if cfg == nil {
		return errors.New("TCP honeypot requires configuration")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	addr := net.JoinHostPort(cfg.TCP.Host, cfg.TCP.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen TCP honeypot: %w", err)
	}
	defer listener.Close()

	eventLogger, err := logger.NewEventLoggerFromConfig(nil, cfg)
	if err != nil {
		return fmt.Errorf("configure event sinks: %w", err)
	}
	defer eventLogger.Close()
	connections := make(chan struct{}, maxTCPConnections)
	var handlers sync.WaitGroup
	listenFinished := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-listenFinished:
		}
	}()
	defer func() {
		close(listenFinished)
		_ = listener.Close()
		handlers.Wait()
	}()

	for {
		select {
		case connections <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		conn, err := listener.Accept()
		if err != nil {
			<-connections
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept TCP honeypot connection: %w", err)
		}
		handlers.Add(1)
		go func(conn net.Conn) {
			defer handlers.Done()
			defer func() { <-connections }()
			readOneConnection(ctx, conn, eventLogger)
		}(conn)
	}
}

func readOneConnection(ctx context.Context, conn net.Conn, eventLogger *logger.EventLogger) {
	defer conn.Close()
	finished := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-finished:
		}
	}()
	defer close(finished)

	_ = conn.SetReadDeadline(time.Now().Add(tcpReadTimeout))
	buf := make([]byte, maxTCPInput)
	n, _ := conn.Read(buf)
	eventLogger.Write(model.Event{
		Sensor:        "tcp",
		RemoteAddr:    conn.RemoteAddr().String(),
		BytesReceived: int64(n),
	})
}
