package proxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/nextdns/nextdns/resolver"
	"github.com/nextdns/nextdns/resolver/query"
	"golang.org/x/net/dns/dnsmessage"
)

const maxDoTPayload = 4096

type dotBuf [maxDoTPayload]byte

// readTCPHeader reads the 2-byte big-endian message length prefix from r.
func readTCPHeader(r io.Reader) (uint16, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

var writeTimeout = 5 * time.Second

// writeFrame writes a DNS frame with a 2-byte length prefix under a per-connection mutex.
// It coalesces header and payload into a single write to prevent interleaving
// under pipelined concurrency. The caller-provided scratch buffer eliminates
// per-write heap allocations; it must be at least 2+len(buf) bytes.
// A write deadline prevents a slow-reading client from blocking the connection
// indefinitely. On write failure the connection is closed to unblock any other
// goroutines waiting on the mutex.
func writeFrame(c net.Conn, mu *sync.Mutex, buf []byte, scratch []byte) error {
	if len(buf) > math.MaxUint16 {
		return errors.New("frame exceeds max uint16")
	}

	mu.Lock()
	defer mu.Unlock()

	binary.BigEndian.PutUint16(scratch[:2], uint16(len(buf)))
	copy(scratch[2:], buf)
	_ = c.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := c.Write(scratch[:2+len(buf)])
	if err != nil {
		_ = c.Close()
	}
	return err
}

// NewServerTLSConfig creates a tls.Config configured for DNS-over-TLS (DoT).
// It loads the certificate and private key from certFile and keyFile,
// enforces TLS 1.2 minimum version, and sets ALPN NextProtos to ["dot"].
func NewServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"dot"},
	}, nil
}

func (p Proxy) serveTLS(ctx context.Context, l net.Listener, inflightRequests chan struct{}, tlsConnections chan struct{}) error {
	bpool := &sync.Pool{
		New: func() any {
			return new(dotBuf)
		},
	}

	for {
		c, err := l.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}
		select {
		case tlsConnections <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		go func(c net.Conn) {
			if err := p.serveTLSConn(ctx, c, inflightRequests, tlsConnections, bpool); err != nil {
				p.logErr(err)
			}
		}(c)
	}
}

func (p Proxy) serveTLSConn(ctx context.Context, c net.Conn, inflightRequests chan struct{}, tlsConnections chan struct{}, bpool *sync.Pool) error {
	defer func() { <-tlsConnections }()
	defer func() { _ = c.Close() }()

	connDone := make(chan struct{})
	defer close(connDone)
	if ctx != nil {
		go func() {
			select {
			case <-ctx.Done():
				_ = c.Close()
			case <-connDone:
			}
		}()
	}

	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	tlsConn, ok := c.(*tls.Conn)
	if !ok {
		return errors.New("not a TLS connection")
	}
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("DoT handshake: %w", err)
	}
	_ = c.SetDeadline(time.Time{})

	if proto := tlsConn.ConnectionState().NegotiatedProtocol; proto != "" && proto != "dot" {
		return fmt.Errorf("DoT: unexpected ALPN %q", proto)
	}

	localAddr := c.LocalAddr()
	remoteAddr := c.RemoteAddr()
	localIP := addrIP(localAddr)
	sourceIP := addrIP(remoteAddr)
	localPort := addrPort(localAddr)
	remotePort := addrPort(remoteAddr)

	idleTimeout := p.tlsIdleTimeout()
	var writeMu sync.Mutex
	var writeScratch [2 + maxDoTPayload]byte

	for {
		if idleTimeout > 0 {
			_ = c.SetReadDeadline(time.Now().Add(idleTimeout))
		}
		length, err := readTCPHeader(c)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return nil
			}
			return fmt.Errorf("DoT read header: %w", err)
		}

		if length > maxDoTPayload {
			return fmt.Errorf("DoT frame too large: %d bytes (max %d)", length, maxDoTPayload)
		}
		if length <= 14 {
			return fmt.Errorf("DoT query too small: %d", length)
		}

		if !tryAcquireRequest(inflightRequests) {
			return errTooManyInflightRequests
		}

		bp := bpool.Get().(*dotBuf)
		buf := bp[:]
		if _, err := io.ReadFull(c, buf[:length]); err != nil {
			bpool.Put(bp)
			<-inflightRequests
			return fmt.Errorf("DoT read payload: %w", err)
		}
		_ = c.SetReadDeadline(time.Time{})

		start := time.Now()
		qsize := int(length)
		go func(bp *dotBuf, qsize int, start time.Time) {
			var err error
			var rsize int
			var ri resolver.ResolveInfo
			var rbp *dotBuf
			var q query.Query

			defer func() {
				if r := recover(); r != nil {
					stackBuf := make([]byte, 64<<10)
					stackBuf = stackBuf[:runtime.Stack(stackBuf, false)]
					err = fmt.Errorf("panic: %v: %s", r, string(stackBuf))
				}
				bpool.Put(bp)
				if rbp != nil {
					bpool.Put(rbp)
				}
				<-inflightRequests
				p.logQuery(QueryInfo{
					SourceIP:          sourceIP,
					RemotePort:        remotePort,
					LocalPort:         localPort,
					PeerIP:            q.PeerIP,
					Protocol:          "DoT",
					Type:              q.Type.String(),
					Name:              q.Name,
					QuerySize:         qsize,
					ResponseSize:      rsize,
					Duration:          time.Since(start),
					Profile:           ri.Profile,
					FromCache:         ri.FromCache,
					UpstreamTransport: ri.Transport,
					Error:             err,
				})
			}()

			buf := bp[:]
			q, err = query.New(buf[:qsize], sourceIP, localIP)
			if err != nil {
				p.logErr(err)
			}
			rbp = bpool.Get().(*dotBuf)
			rbuf := rbp[:]

			if err != nil {
				// Malformed query: reply with FORMERR and skip upstream resolution.
				rsize = replyRCode(dnsmessage.RCodeFormatError, q, rbuf)
				werr := writeFrame(c, &writeMu, rbuf[:rsize], writeScratch[:])
				if werr != nil {
					// Keep the parse error but include the write error.
					err = fmt.Errorf("%v (write: %w)", err, werr)
				}
				return
			}
			qctx := ctx
			if qctx == nil {
				qctx = context.Background()
			}
			if p.Timeout > 0 {
				var cancel context.CancelFunc
				qctx, cancel = context.WithTimeout(qctx, p.Timeout)
				defer cancel()
			}
			if rsize, ri, err = p.Resolve(qctx, q, rbuf); err != nil || rsize <= 0 || rsize > maxDoTPayload {
				rsize = replyRCode(dnsmessage.RCodeServerFailure, q, rbuf)
			}
			werr := writeFrame(c, &writeMu, rbuf[:rsize], writeScratch[:])
			if err == nil {
				// Do not overwrite resolve error when on cache fallback.
				err = werr
			}
		}(bp, qsize, start)
	}
}
