package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nextdns/nextdns/resolver"
	"github.com/nextdns/nextdns/resolver/query"
	"golang.org/x/net/dns/dnsmessage"
)

func TestProxy_maxInflightRequests(t *testing.T) {
	tests := []struct {
		name string
		p    Proxy
		want int
	}{
		{
			name: "default when unset",
			p:    Proxy{},
			want: defaultMaxInflightRequests,
		},
		{
			name: "configured limit",
			p:    Proxy{MaxInflightRequests: 123},
			want: 123,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.maxInflightRequests(); got != tt.want {
				t.Fatalf("maxInflightRequests() = %d, want %d", got, tt.want)
			}
		})
	}
}

type mockResolver struct {
	f func(ctx context.Context, q query.Query, buf []byte) (int, resolver.ResolveInfo, error)
}

func (m mockResolver) Resolve(ctx context.Context, q query.Query, buf []byte) (int, resolver.ResolveInfo, error) {
	if m.f != nil {
		return m.f(ctx, q, buf)
	}
	return replyRCode(dnsmessage.RCodeSuccess, q, buf), resolver.ResolveInfo{}, nil
}

type panicResolver struct{}

func (panicResolver) Resolve(ctx context.Context, q query.Query, buf []byte) (int, resolver.ResolveInfo, error) {
	if q.ID == 9999 {
		panic("simulated resolver crash")
	}
	return replyRCode(dnsmessage.RCodeSuccess, q, buf), resolver.ResolveInfo{}, nil
}

func makeQuery(id uint16) []byte {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               id,
			Response:         false,
			OpCode:           0,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName("example.com."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	buf, _ := msg.Pack()
	return buf
}

func writeDoTQuery(c net.Conn, q []byte) error {
	buf := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(q)))
	copy(buf[2:], q)
	_, err := c.Write(buf)
	return err
}

func readDoTResponse(c net.Conn) ([]byte, error) {
	var buf [2]byte
	if _, err := io.ReadFull(c, buf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(buf[:])
	resp := make([]byte, length)
	_, err := io.ReadFull(c, resp)
	return resp, err
}

func parseResponse(t *testing.T, data []byte) dnsmessage.Message {
	t.Helper()
	var msg dnsmessage.Message
	if err := msg.Unpack(data); err != nil {
		t.Fatalf("failed to unpack response: %v", err)
	}
	return msg
}

func startTestDoTServer(t *testing.T, p Proxy, maxConns int, idleTimeout time.Duration) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile := generateTestCert(t, dir)
	tlsCfg, err := NewServerTLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if maxConns <= 0 {
		maxConns = p.maxTLSConnections()
	}
	p.MaxTLSConnections = uint(maxConns)
	if idleTimeout > 0 {
		p.TLSIdleTimeout = idleTimeout
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsL := tls.NewListener(l, tlsCfg)

	ctx, cancel := context.WithCancel(context.Background())
	inflight := make(chan struct{}, 256)
	conns := make(chan struct{}, maxConns)
	go func() { _ = p.serveTLS(ctx, tlsL, inflight, conns) }()

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			cancel()
			_ = tlsL.Close()
		})
	}
	t.Cleanup(cleanup)
	return l.Addr().String(), cleanup
}

func TestProxy_DoT(t *testing.T) {
	t.Run("Standard DoT Query & Response", func(t *testing.T) {
		var loggedQuery QueryInfo
		var logMu sync.Mutex

		p := Proxy{
			Upstream: mockResolver{},
			QueryLog: func(qi QueryInfo) {
				logMu.Lock()
				loggedQuery = qi
				logMu.Unlock()
			},
		}

		addr, _ := startTestDoTServer(t, p, 10, 0)

		clientCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}}
		c, err := tls.Dial("tcp", addr, clientCfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()

		q := makeQuery(1234)
		if err := writeDoTQuery(c, q); err != nil {
			t.Fatal(err)
		}

		respBytes, err := readDoTResponse(c)
		if err != nil {
			t.Fatal(err)
		}

		resp := parseResponse(t, respBytes)
		if resp.ID != 1234 {
			t.Fatalf("expected ID 1234, got %d", resp.ID)
		}
		if resp.RCode != dnsmessage.RCodeSuccess {
			t.Fatalf("expected RCodeSuccess, got %v", resp.RCode)
		}

		// wait briefly for logging
		time.Sleep(50 * time.Millisecond)
		logMu.Lock()
		defer logMu.Unlock()
		if loggedQuery.Protocol != "DoT" {
			t.Fatalf("expected Protocol 'DoT', got %q", loggedQuery.Protocol)
		}
	})

	t.Run("Pipelined Concurrent Query Framing Integrity", func(t *testing.T) {
		p := Proxy{Upstream: mockResolver{}}
		addr, _ := startTestDoTServer(t, p, 10, 0)

		clientCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}}
		c, err := tls.Dial("tcp", addr, clientCfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()

		const numQueries = 10
		var wg sync.WaitGroup
		errs := make(chan error, numQueries*2)

		// send concurrently
		for i := 0; i < numQueries; i++ {
			wg.Add(1)
			go func(id uint16) {
				defer wg.Done()
				q := makeQuery(id)
				if err := writeDoTQuery(c, q); err != nil {
					errs <- err
				}
			}(uint16(i + 1))
		}

		wg.Wait()

		// read responses sequentially to prevent interleaving
		for i := 0; i < numQueries; i++ {
			respBytes, err := readDoTResponse(c)
			if err != nil {
				errs <- err
				break
			}
			resp := parseResponse(t, respBytes)
			if resp.RCode != dnsmessage.RCodeSuccess {
				errs <- errors.New("bad rcode")
			}
		}
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("pipelined query error: %v", err)
			}
		}
	})

	t.Run("Connection Limit & Rejection", func(t *testing.T) {
		p := Proxy{Upstream: mockResolver{}}
		addr, _ := startTestDoTServer(t, p, 3, 0)

		clientCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}}
		var openConns []net.Conn
		for i := 0; i < 3; i++ {
			c, err := tls.Dial("tcp", addr, clientCfg)
			if err != nil {
				t.Fatalf("conn %d failed: %v", i, err)
			}
			openConns = append(openConns, c)
		}
		defer func() {
			for _, c := range openConns {
				_ = c.Close()
			}
		}()

		// 4th connection
		extra, err := tls.Dial("tcp", addr, clientCfg)
		if err == nil {
			_ = extra.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			buf := make([]byte, 4)
			_, err = extra.Read(buf)
			if err == nil {
				t.Fatal("expected 4th connection to fail or close")
			}
			_ = extra.Close()
		}
	})

	t.Run("Connection Slot Reclamation", func(t *testing.T) {
		p := Proxy{Upstream: mockResolver{}}
		addr, _ := startTestDoTServer(t, p, 3, 0)

		clientCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}}
		for i := 0; i < 3; i++ {
			c, err := tls.Dial("tcp", addr, clientCfg)
			if err != nil {
				t.Fatalf("first round conn %d failed: %v", i, err)
			}
			_ = c.Close()
		}

		// wait for closures to propagate
		time.Sleep(100 * time.Millisecond)

		var openConns []net.Conn
		for i := 0; i < 3; i++ {
			c, err := tls.Dial("tcp", addr, clientCfg)
			if err != nil {
				t.Fatalf("second round conn %d failed: %v", i, err)
			}
			openConns = append(openConns, c)
		}
		for _, c := range openConns {
			_ = c.Close()
		}
	})

	t.Run("Oversized Frame Drop", func(t *testing.T) {
		p := Proxy{Upstream: mockResolver{}}
		addr, _ := startTestDoTServer(t, p, 10, 0)

		clientCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}}
		c, err := tls.Dial("tcp", addr, clientCfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()

		var buf [2]byte
		binary.BigEndian.PutUint16(buf[:], 5000)
		if _, err := c.Write(buf[:]); err != nil {
			t.Fatal(err)
		}

		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		respBuf := make([]byte, 4)
		_, err = c.Read(respBuf)
		if err == nil {
			t.Fatal("expected connection to be closed")
		}
	})

	t.Run("Slowloris Handshake Timeout Drop", func(t *testing.T) {
		p := Proxy{Upstream: mockResolver{}}
		addr, _ := startTestDoTServer(t, p, 10, 0)

		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()

		// no handshake sent, just read. server should timeout in ~3s.
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4)
		_, err = c.Read(buf)
		if err == nil {
			t.Fatal("expected connection to be closed due to handshake timeout")
		}
	})

	t.Run("ALPN Rejection", func(t *testing.T) {
		p := Proxy{Upstream: mockResolver{}}
		addr, _ := startTestDoTServer(t, p, 10, 0)

		clientCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}
		_, err := tls.Dial("tcp", addr, clientCfg)
		if err == nil {
			t.Fatal("expected TLS handshake to fail due to wrong ALPN")
		}
	})

	t.Run("ALPN Omission Acceptance", func(t *testing.T) {
		p := Proxy{Upstream: mockResolver{}}
		addr, _ := startTestDoTServer(t, p, 10, 0)

		clientCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: nil}
		c, err := tls.Dial("tcp", addr, clientCfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()

		q := makeQuery(1234)
		if err := writeDoTQuery(c, q); err != nil {
			t.Fatal(err)
		}

		respBytes, err := readDoTResponse(c)
		if err != nil {
			t.Fatal(err)
		}
		if len(respBytes) == 0 {
			t.Fatal("expected valid response")
		}
	})

	t.Run("Idle Timeout", func(t *testing.T) {
		p := Proxy{Upstream: mockResolver{}}
		addr, _ := startTestDoTServer(t, p, 10, 100*time.Millisecond)

		clientCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}}
		c, err := tls.Dial("tcp", addr, clientCfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()

		q := makeQuery(1234)
		if err := writeDoTQuery(c, q); err != nil {
			t.Fatal(err)
		}
		_, err = readDoTResponse(c)
		if err != nil {
			t.Fatal(err)
		}

		time.Sleep(250 * time.Millisecond)

		// next query should fail
		if err := writeDoTQuery(c, q); err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, err = readDoTResponse(c)
		if err == nil {
			t.Fatal("expected connection to be closed by idle timeout")
		}
	})

	t.Run("Payload Read Timeout Slowloris", func(t *testing.T) {
		addr, cleanup := startTestDoTServer(t, Proxy{Upstream: mockResolver{}}, 10, 100*time.Millisecond)
		defer cleanup()

		clientCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}}
		c, err := tls.Dial("tcp", addr, clientCfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()

		// Send 2-byte header claiming a 200-byte payload, but send no payload bytes
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], 200)
		if _, err := c.Write(hdr[:]); err != nil {
			t.Fatal(err)
		}

		// Wait for idle timeout (100ms) to trigger server disconnect
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 10)
		_, err = c.Read(buf)
		if err == nil {
			t.Fatal("expected connection to be closed by server on stalled payload read")
		}
	})

	t.Run("expReturns Drain & Clean Shutdown", func(t *testing.T) {
		dir := t.TempDir()
		certFile, keyFile := generateTestCert(t, dir)
		tlsCfg, err := NewServerTLSConfig(certFile, keyFile)
		if err != nil {
			t.Fatal(err)
		}

		p := Proxy{
			Upstream:  mockResolver{},
			Addrs:     []string{"127.0.0.1:0"},
			TLSAddrs:  []string{"127.0.0.1:0"},
			TLSConfig: tlsCfg,
		}

		ctx, cancel := context.WithCancel(context.Background())

		errs := make(chan error, 1)
		go func() {
			errs <- p.ListenAndServe(ctx)
		}()

		time.Sleep(100 * time.Millisecond)
		cancel()

		select {
		case err := <-errs:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("ListenAndServe returned unexpected error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("ListenAndServe deadlocked or didn't shut down in time")
		}
	})

	t.Run("Panic Recovery And Inflight Reclamation", func(t *testing.T) {
		loggedErrCh := make(chan error, 2)
		p := Proxy{
			Upstream: panicResolver{},
			QueryLog: func(qi QueryInfo) {
				select {
				case loggedErrCh <- qi.Error:
				default:
				}
			},
		}
		addr, cleanup := startTestDoTServer(t, p, 10, 1*time.Second)
		defer cleanup()

		clientCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}}
		c, err := tls.Dial("tcp", addr, clientCfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()

		q := makeQuery(9999)
		if err := writeDoTQuery(c, q); err != nil {
			t.Fatal(err)
		}

		// Server should catch panic, log it, and not crash.
		select {
		case loggedErr := <-loggedErrCh:
			if loggedErr == nil || !strings.Contains(loggedErr.Error(), "simulated resolver crash") {
				t.Fatalf("expected logged panic error, got: %v", loggedErr)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for query log after panic")
		}

		// Subsequent query should succeed, confirming inflight token was reclaimed
		// and the connection remains intact and healthy.
		q2 := makeQuery(10000)
		if err := writeDoTQuery(c, q2); err != nil {
			t.Fatalf("failed to write subsequent query: %v", err)
		}

		respBytes, err := readDoTResponse(c)
		if err != nil {
			t.Fatalf("failed to read response for subsequent query: %v", err)
		}
		resp := parseResponse(t, respBytes)
		if resp.ID != 10000 {
			t.Fatalf("expected ID 10000, got %d", resp.ID)
		}
		if resp.RCode != dnsmessage.RCodeSuccess {
			t.Fatalf("expected RCodeSuccess, got %v", resp.RCode)
		}

		select {
		case loggedErr2 := <-loggedErrCh:
			if loggedErr2 != nil {
				t.Fatalf("expected nil error for subsequent query, got: %v", loggedErr2)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for subsequent query log")
		}
	})

	t.Run("Malformed Query FORMERR", func(t *testing.T) {
		addr, cleanup := startTestDoTServer(t, Proxy{Upstream: mockResolver{}}, 10, 1*time.Second)
		defer cleanup()

		clientCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}}
		c, err := tls.Dial("tcp", addr, clientCfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()

		// Send >14 bytes of corrupt DNS data
		corruptPayload := bytes.Repeat([]byte{0xff}, 32)
		if err := writeDoTQuery(c, corruptPayload); err != nil {
			t.Fatal(err)
		}

		respBytes, err := readDoTResponse(c)
		if err != nil {
			t.Fatalf("expected FORMERR response, got err: %v", err)
		}
		var msg dnsmessage.Message
		if err := msg.Unpack(respBytes); err != nil {
			t.Fatalf("failed to unpack FORMERR response: %v", err)
		}
		if msg.RCode != dnsmessage.RCodeFormatError {
			t.Fatalf("expected RCodeFormatError (FORMERR), got %v", msg.RCode)
		}
	})

	t.Run("Inflight Exhaustion Drop", func(t *testing.T) {
		dir := t.TempDir()
		certFile, keyFile := generateTestCert(t, dir)
		tlsCfg, err := NewServerTLSConfig(certFile, keyFile)
		if err != nil {
			t.Fatal(err)
		}

		p := Proxy{Upstream: mockResolver{}}
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		tlsL := tls.NewListener(l, tlsCfg)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// 0 capacity inflight channel simulates 100% capacity exhaustion
		inflight := make(chan struct{}, 1)
		inflight <- struct{}{} // fill token pool
		conns := make(chan struct{}, 10)
		go func() { _ = p.serveTLS(ctx, tlsL, inflight, conns) }()

		clientCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}}
		c, err := tls.Dial("tcp", l.Addr().String(), clientCfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()

		q := makeQuery(1234)
		if err := writeDoTQuery(c, q); err != nil {
			t.Fatal(err)
		}

		// Server must immediately drop connection on inflight exhaustion
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 10)
		_, err = c.Read(buf)
		if err == nil {
			t.Fatal("expected connection to be dropped on inflight exhaustion")
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			t.Fatalf("expected immediate connection drop, got read timeout: %v", err)
		}
	})
}
