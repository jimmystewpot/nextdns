package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/nextdns/nextdns/hosts"
	"github.com/nextdns/nextdns/resolver"
	"github.com/nextdns/nextdns/resolver/query"
	"golang.org/x/net/dns/dnsmessage"
)

// QueryInfo provides information about a DNS query handled by Proxy.
type QueryInfo struct {
	SourceIP          net.IP
	RemotePort        int
	LocalPort         int
	Protocol          string
	Profile           string
	PeerIP            net.IP
	Type              string
	Name              string
	QuerySize         int
	ResponseSize      int
	Duration          time.Duration
	FromCache         bool
	UpstreamTransport string
	Error             error
}

type HostResolver interface {
	LookupAddr(addr string) []string
	LookupHost(addr string) []string
}

// Proxy is a DNS53 to DNS over anything proxy.
type Proxy struct {
	// Addrs specifies the TCP/UDP address to listen to, :53 if empty.
	Addrs []string

	// LocalResolver is called before the upstream to resolve local hostnames or
	// IPs.
	LocalResolver HostResolver

	// Upstream specifies the resolver used for incoming queries.
	Upstream resolver.Resolver

	// DiscoveryResolver is called after the upstream if no result was found.
	DiscoveryResolver HostResolver

	// BogusPriv specifies that reverse lookup on private subnets are answerd
	// with NXDOMAIN.
	BogusPriv bool

	// Timeout defines the maximum allowed time allowed for a request before
	// being cancelled.
	Timeout time.Duration

	// Maximum number of inflight requests. Further UDP requests receive
	// SERVFAIL and further TCP connections are closed without blocking a
	// listener loop.
	MaxInflightRequests uint

	// QueryLog specifies an optional log function called for each received query.
	QueryLog func(QueryInfo)

	// InfoLog specifies an option log function called when some actions are
	// performed.
	InfoLog func(string)

	// ErrorLog specifies an optional log function for errors. If not set,
	// errors are not reported.
	ErrorLog func(error)

	// TLSAddrs specifies the TLS addresses to listen to for DNS-over-TLS (DoT).
	TLSAddrs []string

	// TLSConfig specifies the TLS configuration for DoT listeners.
	TLSConfig *tls.Config

	// MaxTLSConnections defines the maximum number of concurrent TLS connections.
	MaxTLSConnections uint

	// TLSIdleTimeout defines the idle timeout for TLS connections.
	TLSIdleTimeout time.Duration
}

const defaultMaxInflightRequests = 256

var errTooManyInflightRequests = errors.New("too many inflight proxy requests")

// ListenAndServe listens on UDP and TCP and serve DNS queries. If ctx is
// canceled, listeners are closed and ListenAndServe returns context.Canceled
// error.
func (p Proxy) ListenAndServe(ctx context.Context) error {
	var addrs []string

	for _, addr := range p.Addrs {
		if addr == "" {
			addr = ":53"
		}

		// Try to lookup the given addr in the /etc/hosts file (for localhost for
		// instance).
		found := false
		if host, port, err := net.SplitHostPort(addr); err == nil {
			if ips := hosts.LookupHost(host); len(ips) > 0 {
				for _, ip := range ips {
					found = true
					addrs = append(addrs, net.JoinHostPort(ip, port))
				}
			}
		}
		if !found {
			addrs = append(addrs, addr)
		}
	}

	lc := &net.ListenConfig{}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	tlsListeners := 0
	if p.TLSConfig != nil {
		tlsListeners = len(p.TLSAddrs)
	}
	expReturns := (len(addrs) * 2) + tlsListeners + 1
	errs := make(chan error, expReturns)
	var closeAll []func() error
	var closeAllMu sync.Mutex
	inflightRequests := make(chan struct{}, p.maxInflightRequests())
	tlsConnections := make(chan struct{}, p.maxTLSConnections())

	for _, addr := range addrs {
		go func(addr string) {
			var err error
			p.logInfof("Listening on UDP/%s", addr)
			udp, err := lc.ListenPacket(ctx, "udp", addr)
			if err == nil {
				closeAllMu.Lock()
				closeAll = append(closeAll, udp.Close)
				closeAllMu.Unlock()
				err = p.serveUDP(udp, inflightRequests)
			}
			cancel()
			if err != nil {
				err = fmt.Errorf("udp: %w", err)
			}
			errs <- err
		}(addr)

		go func(addr string) {
			var err error
			p.logInfof("Listening on TCP/%s", addr)
			tcp, err := lc.Listen(ctx, "tcp", addr)
			if err == nil {
				closeAllMu.Lock()
				closeAll = append(closeAll, tcp.Close)
				closeAllMu.Unlock()
				err = p.serveTCP(tcp, inflightRequests)
			}
			cancel()
			if err != nil {
				err = fmt.Errorf("tcp: %w", err)
			}
			errs <- err
		}(addr)
	}

	if p.TLSConfig != nil {
		for _, addr := range p.TLSAddrs {
			go func(addr string) {
				var err error
				p.logInfof("Listening on DoT/%s", addr)
				tcp, err := lc.Listen(ctx, "tcp", addr)
				if err == nil {
					closeAllMu.Lock()
					closeAll = append(closeAll, tcp.Close)
					closeAllMu.Unlock()
					tlsL := tls.NewListener(tcp, p.TLSConfig)
					err = p.serveTLS(ctx, tlsL, inflightRequests, tlsConnections)
				}
				cancel()
				if err != nil {
					err = fmt.Errorf("dot: %w", err)
				}
				errs <- err
			}(addr)
		}
	}

	<-ctx.Done()
	errs <- ctx.Err()
	closeAllMu.Lock()
	for _, close := range closeAll {
		_ = close()
	}
	closeAllMu.Unlock()
	// Wait for the two sockets (+ ctx err) to be terminated and return the
	// initial error.
	var err error
	for range expReturns {
		if e := <-errs; (err == nil || errors.Is(err, context.Canceled)) && e != nil && !errors.Is(e, net.ErrClosed) {
			err = e
		}
	}
	if err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	return nil
}

func (p Proxy) Resolve(ctx context.Context, q query.Query, buf []byte) (n int, i resolver.ResolveInfo, err error) {
	if p.LocalResolver != nil {
		if _n, _i, _err := hostsResolve(p.LocalResolver, q, buf); _err == nil {
			return _n, _i, nil
		}
	}

	priv := q.Type == query.TypePTR && isPrivateReverse(q.Name)

	if !p.BogusPriv || !priv {
		n, i, err = p.Upstream.Resolve(ctx, q, buf)
	}

	if q.RecursionDesired && p.DiscoveryResolver != nil && (n <= 0 || isNXDomain(buf[:n])) {
		if _n, _i, _err := hostsResolve(p.DiscoveryResolver, q, buf); _err == nil {
			return _n, _i, nil
		}
	}

	if p.BogusPriv && priv {
		n = replyRCode(dnsmessage.RCodeNameError, q, buf)
		return n, i, nil
	}

	return n, i, err
}

func (p Proxy) maxInflightRequests() int {
	if p.MaxInflightRequests == 0 {
		return defaultMaxInflightRequests
	}
	return int(p.MaxInflightRequests)
}

func (p Proxy) maxTLSConnections() int {
	if p.MaxTLSConnections == 0 {
		return 10
	}
	return int(p.MaxTLSConnections)
}

func (p Proxy) tlsIdleTimeout() time.Duration {
	if p.TLSIdleTimeout == 0 {
		return 60 * time.Second
	}
	return p.TLSIdleTimeout
}

func tryAcquireRequest(inflightRequests chan struct{}) bool {
	select {
	case inflightRequests <- struct{}{}:
		return true
	default:
		return false
	}
}

func (p Proxy) logQuery(q QueryInfo) {
	if p.QueryLog != nil {
		p.QueryLog(q)
	}
}

func (p Proxy) logInfof(format string, a ...any) {
	if p.InfoLog != nil {
		p.InfoLog(fmt.Sprintf(format, a...))
	}
}

func (p Proxy) logErr(err error) {
	if err != nil && p.ErrorLog != nil {
		p.ErrorLog(err)
	}
}
