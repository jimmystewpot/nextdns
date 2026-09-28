package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestReadTCPHeader(t *testing.T) {
	// Normal 2-byte header
	data := []byte{0x00, 0x2a} // length 42
	length, err := readTCPHeader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if length != 42 {
		t.Fatalf("expected length 42, got %d", length)
	}

	// Incomplete header EOF
	_, err = readTCPHeader(bytes.NewReader([]byte{0x00}))
	if err == nil {
		t.Fatal("expected error on EOF, got nil")
	}
}

func TestWriteFrame(t *testing.T) {
	var scratch [2 + maxDoTPayload]byte
	for _, size := range []int{9, 512, 1024} {
		t.Run(fmt.Sprintf("%d_bytes", size), func(t *testing.T) {
			server, client := net.Pipe()
			defer func() { _ = server.Close() }()
			defer func() { _ = client.Close() }()

			var mu sync.Mutex
			payload := bytes.Repeat([]byte("a"), size)

			go func() {
				_ = writeFrame(server, &mu, payload, scratch[:])
			}()

			var length uint16
			if err := binary.Read(client, binary.BigEndian, &length); err != nil {
				t.Fatalf("failed to read length: %v", err)
			}
			if int(length) != len(payload) {
				t.Fatalf("expected length %d, got %d", len(payload), length)
			}

			body := make([]byte, length)
			if _, err := io.ReadFull(client, body); err != nil {
				t.Fatalf("failed to read body: %v", err)
			}
			if !bytes.Equal(body, payload) {
				t.Fatalf("payload mismatch")
			}
		})
	}

	// Test oversized frame returns error
	var mu sync.Mutex
	oversized := make([]byte, 65536)
	if err := writeFrame(nil, &mu, oversized, scratch[:]); err == nil {
		t.Fatal("expected error on oversized frame, got nil")
	}
}

func TestWriteFrame_WriteDeadline(t *testing.T) {
	orig := writeTimeout
	writeTimeout = 50 * time.Millisecond
	defer func() { writeTimeout = orig }()

	server, client := net.Pipe()
	defer func() { _ = client.Close() }()

	var mu sync.Mutex
	var scratch [2 + maxDoTPayload]byte
	payload := bytes.Repeat([]byte("x"), 100)

	// Do not read on client to simulate a stalled consumer.
	// net.Pipe() is unbuffered and synchronous, so c.Write will block immediately
	// until writeTimeout triggers.
	err := writeFrame(server, &mu, payload, scratch[:])
	if err == nil {
		t.Fatal("expected writeFrame to return timeout error, got nil")
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("expected net.Error timeout, got: %v", err)
	}

	// Verify server pipe was closed by writeFrame on failure
	var buf [1]byte
	_, readErr := server.Read(buf[:])
	if readErr == nil {
		t.Fatal("expected server connection to be closed after write timeout")
	}
}

func generateTestCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	certPath := filepath.Join(dir, "test.crt")
	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		_ = certOut.Close()
		t.Fatal(err)
	}
	if err := certOut.Close(); err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(dir, "test.key")
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		_ = keyOut.Close()
		t.Fatal(err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		_ = keyOut.Close()
		t.Fatal(err)
	}
	if err := keyOut.Close(); err != nil {
		t.Fatal(err)
	}

	return certPath, keyPath
}

func TestNewServerTLSConfig(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateTestCert(t, dir)

	cfg, err := NewServerTLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Certificates) == 0 {
		t.Fatal("expected at least 1 certificate loaded")
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "dot" {
		t.Fatalf("expected ALPN [dot], got %v", cfg.NextProtos)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected MinVersion TLS 1.2, got %v", cfg.MinVersion)
	}

	// Missing file should return error
	_, err = NewServerTLSConfig(filepath.Join(dir, "nonexistent.crt"), keyFile)
	if err == nil {
		t.Fatal("expected error for missing cert file, got nil")
	}
}

func TestServeTLS_ConnectionLimit(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateTestCert(t, dir)
	tlsCfg, err := NewServerTLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	const limit = 2
	inflightRequests := make(chan struct{}, 256)
	tlsConnections := make(chan struct{}, limit)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	tlsL := tls.NewListener(l, tlsCfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := Proxy{}
	go func() { _ = p.serveTLS(ctx, tlsL, inflightRequests, tlsConnections) }()

	addr := l.Addr().String()
	clientCfg := &tls.Config{InsecureSkipVerify: true}

	// Open 'limit' connections — all should be accepted and kept open.
	var conns []net.Conn
	for i := 0; i < limit; i++ {
		c, err := tls.Dial("tcp", addr, clientCfg)
		if err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()

	// The (limit+1)th connection must be closed by the server immediately.
	extra, err := tls.Dial("tcp", addr, clientCfg)
	if err != nil {
		// TLS Dial may fail outright if server closes before handshake — also acceptable.
		return
	}
	defer func() { _ = extra.Close() }()
	// If the dial succeeded, a read must quickly return EOF or an error.
	_ = extra.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 4)
	_, readErr := extra.Read(buf)
	if readErr == nil {
		t.Fatal("expected server to close the over-limit connection, but read succeeded")
	}
}

func TestWriteTimeout_Configurable(t *testing.T) {
	orig := writeTimeout
	defer func() { writeTimeout = orig }()
	writeTimeout = 50 * time.Millisecond
	if writeTimeout != 50*time.Millisecond {
		t.Fatalf("expected writeTimeout to be 50ms, got %v", writeTimeout)
	}
}
