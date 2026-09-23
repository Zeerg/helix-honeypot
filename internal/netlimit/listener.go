// Package netlimit provides bounded wrappers for network listeners.
package netlimit

import (
	"errors"
	"net"
	"sync"
)

// NewCappedListener limits the number of accepted connections that have not
// yet been closed. Close also unblocks an Accept waiting for a free slot.
func NewCappedListener(listener net.Listener, maxConnections int) (net.Listener, error) {
	if listener == nil {
		return nil, errors.New("listener is required")
	}
	if maxConnections < 1 {
		return nil, errors.New("max connections must be positive")
	}
	return &cappedListener{
		Listener: listener,
		slots:    make(chan struct{}, maxConnections),
		done:     make(chan struct{}),
	}, nil
}

type cappedListener struct {
	net.Listener
	slots     chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func (l *cappedListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}

	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &cappedConn{
		Conn: conn,
		release: func() {
			<-l.slots
		},
	}, nil
}

func (l *cappedListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		l.closeErr = l.Listener.Close()
	})
	return l.closeErr
}

type cappedConn struct {
	net.Conn
	releaseOnce sync.Once
	release     func()
}

func (c *cappedConn) Close() error {
	err := c.Conn.Close()
	c.releaseOnce.Do(c.release)
	return err
}
