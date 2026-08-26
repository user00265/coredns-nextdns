package nextdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	dnsMessageMIME = "application/dns-message"

	defaultTimeout       = 5 * time.Second
	defaultKeepalive     = 30 * time.Second
	defaultMaxIdleConns  = 16
	defaultTLSHandshake  = 5 * time.Second
	defaultIdleConnTimeo = 90 * time.Second
)

// defaultEndpoints is the NextDNS anycast DoH service, with the well known
// anycast addresses used to bootstrap the connection. Bootstrapping matters
// here: this plugin *is* the resolver, so it cannot rely on the system resolver
// to look up dns.nextdns.io without creating a startup dependency loop.
var defaultEndpoints = []string{
	"https://dns.nextdns.io#45.90.28.0,2a07:a8c0::,45.90.30.0,2a07:a8c1::",
}

// endpoint is one DoH upstream: a base URL plus the literal addresses used to
// reach it without a prior DNS lookup.
type endpoint struct {
	base      string // e.g. https://dns.nextdns.io, no trailing slash
	host      string // hostname used for TLS and for bootstrap matching
	bootstrap []string
	next      uint32 // rotates over bootstrap addresses
}

// parseEndpoint parses "https://host[:port][/path][#ip1,ip2,...]".
func parseEndpoint(s string) (*endpoint, error) {
	spec := s
	var boot []string
	if i := strings.IndexByte(spec, '#'); i >= 0 {
		for _, ip := range strings.Split(spec[i+1:], ",") {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			if net.ParseIP(ip) == nil {
				return nil, fmt.Errorf("invalid bootstrap address %q in endpoint %q", ip, s)
			}
			boot = append(boot, ip)
		}
		spec = spec[:i]
	}

	u, err := url.Parse(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint %q: %v", s, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("endpoint %q must use https", s)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("endpoint %q has no host", s)
	}

	return &endpoint{
		base:      strings.TrimSuffix(u.String(), "/"),
		host:      u.Hostname(),
		bootstrap: boot,
	}, nil
}

// addrs returns the bootstrap addresses for this endpoint rotated by one, so
// that consecutive dials spread over them.
func (e *endpoint) addrs(network string) []string {
	if len(e.bootstrap) == 0 {
		return nil
	}
	start := int(atomic.AddUint32(&e.next, 1) - 1)
	out := make([]string, 0, len(e.bootstrap))
	for i := range e.bootstrap {
		ip := e.bootstrap[(start+i)%len(e.bootstrap)]
		if !matchesNetwork(network, ip) {
			continue
		}
		out = append(out, ip)
	}
	return out
}

// matchesNetwork reports whether ip can be used for a dial of the given network.
func matchesNetwork(network, ip string) bool {
	is4 := net.ParseIP(ip).To4() != nil
	switch network {
	case "tcp4", "udp4":
		return is4
	case "tcp6", "udp6":
		return !is4
	default:
		return true
	}
}

// dohClient talks DNS-over-HTTPS to one or more NextDNS endpoints.
type dohClient struct {
	endpoints []*endpoint
	hc        *http.Client
	timeout   time.Duration
	userAgent string

	mu sync.RWMutex
	// lastMod records, per profile, when NextDNS last reported a configuration
	// change. Anything cached before that timestamp was resolved under the old
	// configuration and must not be served.
	lastMod map[string]time.Time
}

type dohOptions struct {
	endpoints     []string
	timeout       time.Duration
	tlsServerName string
	maxIdleConns  int
}

func newDOHClient(o dohOptions) (*dohClient, error) {
	specs := o.endpoints
	if len(specs) == 0 {
		specs = defaultEndpoints
	}
	c := &dohClient{
		timeout:   o.timeout,
		userAgent: "coredns-nextdns/" + version,
		lastMod:   map[string]time.Time{},
	}
	if c.timeout <= 0 {
		c.timeout = defaultTimeout
	}
	for _, s := range specs {
		ep, err := parseEndpoint(s)
		if err != nil {
			return nil, err
		}
		c.endpoints = append(c.endpoints, ep)
	}

	maxIdle := o.maxIdleConns
	if maxIdle <= 0 {
		maxIdle = defaultMaxIdleConns
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: o.tlsServerName,
	}
	c.hc = &http.Client{
		// A DoH POST has no business being redirected, and following one is
		// actively harmful here: Go copies custom headers across a redirect to a
		// different host, stripping only Authorization and Cookie. That would
		// hand the device's LAN IP, name and ID to whatever host the redirect
		// names.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext:         c.dial,
			TLSClientConfig:     tlsCfg,
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        maxIdle,
			MaxIdleConnsPerHost: maxIdle,
			IdleConnTimeout:     defaultIdleConnTimeo,
			TLSHandshakeTimeout: defaultTLSHandshake,
		},
	}
	return c, nil
}

// dial resolves the endpoint hostname from the configured bootstrap addresses
// rather than through the system resolver, falling back to a normal dial when
// no bootstrap address is configured or all of them fail.
func (c *dohClient) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: c.timeout, KeepAlive: defaultKeepalive}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return d.DialContext(ctx, network, addr)
	}

	var lastErr error
	for _, ep := range c.endpoints {
		if ep.host != host {
			continue
		}
		for _, ip := range ep.addrs(network) {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
			bootstrapFailCount.WithLabelValues(ep.host, ip).Inc()
		}
		break
	}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil && lastErr != nil {
		return nil, fmt.Errorf("%v (bootstrap: %v)", err, lastErr)
	}
	return conn, err
}

// exchange sends r to NextDNS under the given profile and returns the reply.
// Endpoints are tried in order until one answers.
func (c *dohClient) exchange(ctx context.Context, profile string, r *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	// RFC 8484 recommends an ID of 0 on the wire so responses stay cacheable by
	// intermediaries; the client's ID is restored by the caller.
	q := r.Copy()
	q.Id = 0
	wire, err := q.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing query: %v", err)
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var lastErr error
	for _, ep := range c.endpoints {
		m, err := c.do(ctx, ep, profile, wire, ci)
		if err == nil {
			return m, nil
		}
		lastErr = err
		errorCount.WithLabelValues(ep.host).Inc()
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

func (c *dohClient) do(ctx context.Context, ep *endpoint, profile string, wire []byte, ci ClientInfo) (*dns.Msg, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.base+"/"+profile, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	// Let the transport replay the request if it loses a race with an idle
	// connection being closed by the far end.
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(wire)), nil }
	req.ContentLength = int64(len(wire))

	req.Header.Set("Content-Type", dnsMessageMIME)
	req.Header.Set("Accept", dnsMessageMIME)
	req.Header.Set("User-Agent", c.userAgent)
	// Ask NextDNS to tell us when the profile configuration last changed, so the
	// cache can be invalidated when a user changes their blocklists.
	req.Header.Set("X-Conf-Last-Modified", "true")
	ci.setHeaders(req.Header)

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: unexpected status %s", ep.host, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize))
	if err != nil {
		return nil, fmt.Errorf("%s: reading response: %v", ep.host, err)
	}

	m := new(dns.Msg)
	if err := m.Unpack(body); err != nil {
		return nil, fmt.Errorf("%s: unpacking response: %v", ep.host, err)
	}

	c.updateLastMod(profile, resp.Header.Get("X-Conf-Last-Modified"))
	return m, nil
}

// updateLastMod records a profile configuration change time reported by NextDNS.
func (c *dohClient) updateLastMod(profile, header string) {
	if header == "" {
		return
	}
	t, err := time.Parse(time.RFC1123, header)
	if err != nil {
		return
	}
	c.mu.RLock()
	cur := c.lastMod[profile]
	c.mu.RUnlock()
	if !t.After(cur) {
		return
	}
	c.mu.Lock()
	if t.After(c.lastMod[profile]) {
		c.lastMod[profile] = t
		log.Infof("Profile %s configuration changed at %s, invalidating cached entries", profile, t)
	}
	c.mu.Unlock()
}

// confChangedAt returns when the given profile's configuration last changed.
func (c *dohClient) confChangedAt(profile string) time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastMod[profile]
}

func (c *dohClient) close() {
	if t, ok := c.hc.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
}
