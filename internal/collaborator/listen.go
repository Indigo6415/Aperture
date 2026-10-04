package collaborator

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// tlsHandshakeByte is the first byte of every TLS record carrying a ClientHello
// (content type 0x16 = handshake). Plain HTTP always starts with an ASCII method
// name, so this byte alone tells the two protocols apart.
const tlsHandshakeByte = 0x16

// sniffDeadline bounds how long a new connection may take to send its first
// byte. Without it, a client that connects and says nothing would hold a
// goroutine forever.
const sniffDeadline = 10 * time.Second

// Serve runs plain and secure HTTP on one listener. Each accepted connection is
// routed by its first byte: a TLS handshake goes to secure (whose TLSConfig
// must be set), anything else to plain. When tlsOn reports false, TLS
// connections are closed instead, so the HTTPS side can be switched off at
// runtime without restarting the listener. Blocks until one of the servers
// stops.
func Serve(ln net.Listener, plain, secure *http.Server, tlsOn func() bool) error {
	plainLn := newChanListener(ln.Addr())
	tlsLn := newChanListener(ln.Addr())

	// Accept loop: hand each connection to the sniffer. A failed Accept means the
	// listener was closed, so both sub-listeners are closed too.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				plainLn.Close()
				tlsLn.Close()
				return
			}
			go route(c, plainLn, tlsLn, tlsOn)
		}
	}()

	errc := make(chan error, 2)
	go func() { errc <- plain.Serve(plainLn) }()
	go func() { errc <- secure.Serve(tls.NewListener(tlsLn, secure.TLSConfig)) }()
	return <-errc
}

// route reads the first byte of c and hands the connection to the matching
// sub-listener. The peeked byte is not consumed, so the chosen server still
// sees the full request or handshake.
func route(c net.Conn, plainLn, tlsLn *chanListener, tlsOn func() bool) {
	// Bound the first read so an idle client can't hold this goroutine forever.
	_ = c.SetReadDeadline(time.Now().Add(sniffDeadline))
	br := bufio.NewReader(c)
	first, err := br.Peek(1)
	if err != nil {
		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	bc := &bufferedConn{Conn: c, r: br}
	// Keep the first byte the sniffer peeked, since the server still needs it.
	if first[0] == tlsHandshakeByte {
		// Reject TLS while HTTPS is turned off, rather than serving it.
		if !tlsOn() {
			c.Close()
			return
		}
		tlsLn.push(bc)
		return
	}
	plainLn.push(bc)
}

// bufferedConn is a net.Conn whose reads go through a bufio.Reader, so bytes the
// sniffer peeked are still returned to the server.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// chanListener is a net.Listener fed by push instead of by a socket. It lets
// one real listener feed two http.Servers.
type chanListener struct {
	addr net.Addr
	ch   chan net.Conn
	done chan struct{}
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{addr: addr, ch: make(chan net.Conn), done: make(chan struct{})}
}

// push hands c to the next Accept call. If the listener is already closed, c is closed instead.
func (l *chanListener) push(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.done:
		c.Close()
	}
}

// Accept returns the next pushed connection, or net.ErrClosed once closed.
func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops Accept. It's safe to call more than once.
func (l *chanListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

// Addr returns the address of the underlying real listener.
func (l *chanListener) Addr() net.Addr { return l.addr }
