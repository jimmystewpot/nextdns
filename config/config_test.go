package config

import (
	"strings"
	"testing"
	"time"
)

func TestMaxInflightUpstreamRequestsFlag(t *testing.T) {
	var c Config
	c.Parse("nextdns run", []string{"-max-inflight-upstream-requests", "7"}, false)
	if got := c.MaxInflightUpstreamRequests; got != 7 {
		t.Fatalf("MaxInflightUpstreamRequests = %d, want 7", got)
	}
}

func TestMaxInflightUpstreamRequestsFlagDefault(t *testing.T) {
	var c Config
	c.Parse("nextdns run", nil, false)
	if got := c.MaxInflightUpstreamRequests; got != 32 {
		t.Fatalf("MaxInflightUpstreamRequests = %d, want 32", got)
	}
}

func TestValidateMaxInflightUpstreamRequests(t *testing.T) {
	for _, tt := range []struct {
		name       string
		configured uint
		proxy      uint
		wantErr    string
	}{
		{name: "default", configured: 32, proxy: 256},
		{name: "zero proxy uses proxy default", configured: 32, proxy: 0},
		{name: "small proxy accepts half", configured: 2, proxy: 4},
		{name: "small proxy rejects default", configured: 32, proxy: 4, wantErr: "must not exceed 2"},
		{name: "configured above half is invalid", configured: 3, proxy: 4, wantErr: "must not exceed 2"},
		{name: "one proxy slot accepts one", configured: 1, proxy: 1},
		{name: "one proxy slot rejects two", configured: 2, proxy: 1, wantErr: "must not exceed 1"},
		{name: "zero is invalid", configured: 0, proxy: 256, wantErr: "greater than zero"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := Config{
				MaxInflightRequests:         tt.proxy,
				MaxInflightUpstreamRequests: tt.configured,
			}
			err := c.Validate()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Validate() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() error = %v, want nil", err)
			}
		})
	}
}

func TestConfig_TLS(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		var c Config
		c.Parse("nextdns", []string{}, false)
		if c.MaxTLSConnections != 10 {
			t.Fatalf("expected MaxTLSConnections default 10, got %d", c.MaxTLSConnections)
		}
		if c.TLSIdleTimeout != 60*time.Second {
			t.Fatalf("expected TLSIdleTimeout default 60s, got %v", c.TLSIdleTimeout)
		}
	})

	t.Run("explicit flags", func(t *testing.T) {
		var c Config
		c.Parse("nextdns", []string{
			"-listen-tls", ":853",
			"-tls-cert", "/etc/ssl/fullchain.pem",
			"-tls-key", "/etc/ssl/privkey.pem",
			"-max-tls-connections", "25",
			"-tls-idle-timeout", "30s",
		}, false)
		if len(c.ListensTLS) != 1 || c.ListensTLS[0] != ":853" {
			t.Fatalf("expected ListensTLS [:853], got %v", c.ListensTLS)
		}
		if c.TLSCert != "/etc/ssl/fullchain.pem" || c.TLSKey != "/etc/ssl/privkey.pem" {
			t.Fatalf("unexpected cert/key: %s, %s", c.TLSCert, c.TLSKey)
		}
		if c.MaxTLSConnections != 25 {
			t.Fatalf("expected MaxTLSConnections 25, got %d", c.MaxTLSConnections)
		}
		if c.TLSIdleTimeout != 30*time.Second {
			t.Fatalf("expected TLSIdleTimeout 30s, got %v", c.TLSIdleTimeout)
		}
	})

	t.Run("validation: cert without key fails", func(t *testing.T) {
		var c Config
		c.Parse("nextdns", []string{
			"-listen-tls", ":853",
			"-tls-cert", "/etc/ssl/fullchain.pem",
		}, false)
		if err := c.Validate(); err == nil {
			t.Fatal("expected error when cert specified without key")
		}
	})

	t.Run("validation: key without cert fails", func(t *testing.T) {
		var c Config
		c.Parse("nextdns", []string{
			"-listen-tls", ":853",
			"-tls-key", "/etc/ssl/privkey.pem",
		}, false)
		if err := c.Validate(); err == nil {
			t.Fatal("expected error when key specified without cert")
		}
	})

	t.Run("validation: neither cert nor key passes", func(t *testing.T) {
		var c Config
		c.Parse("nextdns", []string{
			"-listen-tls", ":853",
		}, false)
		if err := c.Validate(); err != nil {
			t.Fatalf("expected nil error when neither cert nor key specified, got %v", err)
		}
	})

	t.Run("validation: both cert and key passes", func(t *testing.T) {
		var c Config
		c.Parse("nextdns", []string{
			"-listen-tls", ":853",
			"-tls-cert", "/etc/ssl/fullchain.pem",
			"-tls-key", "/etc/ssl/privkey.pem",
		}, false)
		if err := c.Validate(); err != nil {
			t.Fatalf("expected nil error when both cert and key specified, got %v", err)
		}
	})
}
