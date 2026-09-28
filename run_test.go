package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nextdns/nextdns/config"
	"github.com/nextdns/nextdns/host"
	"github.com/nextdns/nextdns/proxy"
)

func Test_isLocalhostMode(t *testing.T) {
	tests := []struct {
		listens []string
		want    bool
	}{
		{[]string{"127.0.0.1:53"}, true},
		{[]string{"127.0.0.1:5353"}, true},
		{[]string{"10.0.0.1:53"}, false},
		{[]string{"127.0.0.1:53", "10.0.0.1:53"}, false},
		{[]string{"10.0.0.1:53", "127.0.0.1:53"}, false},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.listens, ","), func(t *testing.T) {
			if got := isLocalhostMode(&config.Config{Listens: tt.listens}); got != tt.want {
				t.Errorf("isLocalhostMode() = %v, want %v", got, tt.want)
			}
		})
	}
}

type fakeLogger struct {
	warnf func(string, ...any)
}

var _ host.Logger = (*fakeLogger)(nil)

func (f *fakeLogger) Debug(v ...any)                 {}
func (f *fakeLogger) Debugf(format string, a ...any) {}
func (f *fakeLogger) Info(v ...any)                  {}
func (f *fakeLogger) Infof(format string, a ...any)  {}
func (f *fakeLogger) Warning(v ...any)               {}
func (f *fakeLogger) Warningf(format string, a ...any) {
	if f.warnf != nil {
		f.warnf(format, a...)
	}
}
func (f *fakeLogger) Error(v ...any)                 {}
func (f *fakeLogger) Errorf(format string, a ...any) {}

func generateTestCertFiles(t *testing.T, certPath, keyPath string) {
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
}

func Test_applyDoTConfig(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "test.crt")
	keyFile := filepath.Join(dir, "test.key")
	generateTestCertFiles(t, certFile, keyFile)

	tests := []struct {
		name        string
		cfg         config.Config
		wantErr     bool
		wantWarning bool
		checkProxy  func(t *testing.T, p *proxy.Proxy)
	}{
		{
			name:    "no listen-tls: no-op",
			cfg:     config.Config{},
			wantErr: false,
			checkProxy: func(t *testing.T, p *proxy.Proxy) {
				if len(p.TLSAddrs) != 0 {
					t.Errorf("expected empty TLSAddrs, got %v", p.TLSAddrs)
				}
				if p.TLSConfig != nil {
					t.Errorf("expected nil TLSConfig, got %v", p.TLSConfig)
				}
			},
		},
		{
			name: "listen-tls, no cert (default absent): warn and degrade",
			cfg: config.Config{
				ListensTLS: []string{":853"},
			},
			wantErr:     false,
			wantWarning: true,
			checkProxy: func(t *testing.T, p *proxy.Proxy) {
				if len(p.TLSAddrs) != 0 {
					t.Errorf("expected empty TLSAddrs, got %v", p.TLSAddrs)
				}
				if p.TLSConfig != nil {
					t.Errorf("expected nil TLSConfig, got %v", p.TLSConfig)
				}
			},
		},
		{
			name: "listen-tls with valid cert+key: configures proxy",
			cfg: config.Config{
				ListensTLS:        []string{":853"},
				TLSCert:           certFile,
				TLSKey:            keyFile,
				MaxTLSConnections: 10,
				TLSIdleTimeout:    60 * time.Second,
			},
			wantErr: false,
			checkProxy: func(t *testing.T, p *proxy.Proxy) {
				if len(p.TLSAddrs) != 1 || p.TLSAddrs[0] != ":853" {
					t.Errorf("expected TLSAddrs [':853'], got %v", p.TLSAddrs)
				}
				if p.TLSConfig == nil {
					t.Errorf("expected non-nil TLSConfig")
				}
				if p.MaxTLSConnections != 10 {
					t.Errorf("expected MaxTLSConnections 10, got %d", p.MaxTLSConnections)
				}
				if p.TLSIdleTimeout != 60*time.Second {
					t.Errorf("expected TLSIdleTimeout 60s, got %v", p.TLSIdleTimeout)
				}
			},
		},
		{
			name: "listen-tls with missing cert: hard error",
			cfg: config.Config{
				ListensTLS: []string{":853"},
				TLSCert:    "nonexistent.pem",
				TLSKey:     keyFile,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var warned bool
			log := &fakeLogger{
				warnf: func(format string, a ...any) {
					warned = true
				},
			}
			var p proxy.Proxy
			err := applyDoTConfig(&tt.cfg, &p, log)
			if (err != nil) != tt.wantErr {
				t.Fatalf("applyDoTConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			if warned != tt.wantWarning {
				t.Errorf("warning logged = %v, want %v", warned, tt.wantWarning)
			}
			if tt.checkProxy != nil {
				tt.checkProxy(t, &p)
			}
		})
	}
}
