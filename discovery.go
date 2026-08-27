package nextdns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin/pkg/upstream"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// Device discovery by reverse DNS.
//
// ARP tables and DHCP lease files are not available to every deployment — a
// containerised CoreDNS, or one that does not sit on the client's segment, has
// neither. What every deployment does have is a resolver, and on most networks
// the DHCP server already publishes its leases as PTR records. So: ask for the
// PTR of the client address and use that as the device name.
//
// Two things make this safe to do on the query path.
//
// It is asynchronous. A device name is decoration on a log line, not part of
// the answer, and it is not worth making a client wait for it. A cold miss
// returns no name and schedules the lookup; by the time that device asks its
// next question the name is there.
//
// It cannot recurse. A reverse lookup issued here is marked on its context, and
// ServeDNS refuses to touch a marked query: it will not enrich it, and it will
// not send it to NextDNS. Without that, the internal resolver would route the
// PTR query back through this same plugin, which would try to discover the name
// of the client that asked it, forever.

const (
	defaultDiscoveryTTL     = time.Hour
	defaultDiscoveryRetry   = 5 * time.Minute
	defaultDiscoveryTimeout = 2 * time.Second
	defaultDiscoveryWait    = 200 * time.Millisecond
	defaultDiscoveryMax     = 4096

	// maxDiscoveryInflight bounds the lookups running at once. Each cold client
	// address costs a goroutine, and the set of client addresses is not
	// something this plugin controls.
	maxDiscoveryInflight = 64
)

// discoveryKey marks a context as belonging to a reverse lookup this plugin
// issued for itself.
type discoveryKey struct{}

func withDiscovery(ctx context.Context) context.Context {
	return context.WithValue(ctx, discoveryKey{}, true)
}

// isDiscovery reports whether this query is one of our own reverse lookups.
func isDiscovery(ctx context.Context) bool {
	v, _ := ctx.Value(discoveryKey{}).(bool)
	return v
}

// resolveFunc resolves a reverse name to a hostname. It returns an empty name
// when the lookup succeeded but there is no PTR record. The writer is the one a
// self-directed lookup should present to the plugin chain; resolvers that leave
// the process ignore it.
type resolveFunc func(ctx context.Context, arpa string, w dns.ResponseWriter) (string, error)

type discoveryEntry struct {
	name    string
	expires time.Time
}

// discoverer keeps a small expiring table of client address to device name.
type discoverer struct {
	resolve resolveFunc
	labels  metricLabels
	ttl     time.Duration
	// wait is how long a query is held on a cold miss, waiting for the lookup
	// it just started. Zero answers immediately and lets the name catch up.
	wait    time.Duration
	retry   time.Duration
	timeout time.Duration
	max     int

	// wg tracks the detached lookups so shutdown can join them instead of
	// abandoning them mid-flight.
	//
	// A WaitGroup requires that an Add which takes the counter up from zero
	// happens before any Wait. Queries can still be in flight when the server
	// shuts down, so that ordering is not free here: closing is what buys it.
	// Without it, an Add racing the last Done panics inside Done ("WaitGroup is
	// reused before previous Wait has returned") — and that panic is not covered
	// by lookup's recover, because the deferred Done runs after it. It would
	// take down the whole process.
	wg sync.WaitGroup

	mu sync.Mutex
	// closing is set before drain blocks, and no lookup may start once it is set.
	closing bool
	entries map[netip.Addr]discoveryEntry
	// inflight maps an address being looked up to a channel closed when the
	// result lands, so that every query waiting on that device is released
	// together rather than only the one that started it.
	inflight map[netip.Addr]chan struct{}
}

func newDiscoverer() *discoverer {
	return &discoverer{
		ttl:      defaultDiscoveryTTL,
		retry:    defaultDiscoveryRetry,
		timeout:  defaultDiscoveryTimeout,
		wait:     defaultDiscoveryWait,
		max:      defaultDiscoveryMax,
		entries:  map[netip.Addr]discoveryEntry{},
		inflight: map[netip.Addr]chan struct{}{},
	}
}

// name returns the discovered name for addr.
//
// On a cold miss it starts the lookup and holds the query for up to wait, so
// that a device's very first query is attributed too — that first query is
// often the one you most want to see named, and letting it go out bare is what
// makes a new device show up in the NextDNS log as a bare ID.
//
// The hold is bounded three ways: by wait, by the caller's context, and by the
// lookup's own timeout. It only ever happens when there is nothing to show:
// with a name in hand, even an expired one, the query is answered immediately
// and the refresh runs behind it.
func (d *discoverer) name(ctx context.Context, addr netip.Addr, local net.Addr) string {
	if d == nil || d.resolve == nil {
		return ""
	}

	now := time.Now()

	d.mu.Lock()
	e, cached := d.entries[addr]
	if cached && now.Before(e.expires) {
		d.mu.Unlock()
		return e.name
	}

	// Somebody is already asking. Wait on their answer rather than starting a
	// second lookup for the same device.
	if ch, busy := d.inflight[addr]; busy {
		d.mu.Unlock()
		if d.wait > 0 && e.name == "" {
			return d.hold(ctx, addr, ch)
		}
		return e.name
	}

	if d.closing || len(d.inflight) >= maxDiscoveryInflight {
		d.mu.Unlock()
		return e.name
	}

	done := make(chan struct{})
	d.inflight[addr] = done
	d.wg.Add(1) // under d.mu and only while not closing, so drain cannot race it
	d.mu.Unlock()

	// The lookup outlives the query that triggered it either way, so it must not
	// be cancelled when that query's context is torn down. It does still need
	// the context values, in particular the server the internal resolver
	// dispatches through.
	go d.lookup(context.WithoutCancel(ctx), addr, local, done)

	// Hold only when there is nothing to serve. Handing out a stale name at once
	// beats delaying a query for a fresher one.
	if d.wait <= 0 || e.name != "" {
		return e.name
	}
	return d.hold(ctx, addr, done)
}

// hold blocks until the lookup for addr lands, the wait elapses, or the caller
// gives up, then returns whatever name ended up on record.
func (d *discoverer) hold(ctx context.Context, addr netip.Addr, done <-chan struct{}) string {
	t := time.NewTimer(d.wait)
	defer t.Stop()

	select {
	case <-done:
	case <-t.C:
		// Not back in time. The lookup carries on regardless, so the next query
		// from this device will have the name.
		discoveryWaits.WithLabelValues("timeout").Inc()
		return ""
	case <-ctx.Done():
		discoveryWaits.WithLabelValues("cancelled").Inc()
		return ""
	}

	d.mu.Lock()
	name := d.entries[addr].name
	d.mu.Unlock()

	discoveryWaits.WithLabelValues("resolved").Inc()
	return name
}

// lookup performs one reverse lookup and records the result. done is closed
// once the result is stored, releasing any queries held in hold.
func (d *discoverer) lookup(ctx context.Context, addr netip.Addr, local net.Addr, done chan struct{}) {
	defer d.wg.Done()
	// Registered before the cleanup below, so it runs after it: by the time the
	// waiters are released the entry is already stored.
	defer close(done)
	defer func() {
		d.mu.Lock()
		delete(d.inflight, addr)
		d.mu.Unlock()

		// Nothing up the stack can recover for this goroutine, and an
		// unrecovered panic in it would take down the whole resolver over a
		// device name. CoreDNS recovers panics raised inside its own
		// Server.ServeDNS, which covers the internal resolver, but not the
		// external one and not this function's own body.
		if rec := recover(); rec != nil {
			log.Errorf("Recovered from panic in device discovery for %s: %v\n%s", addr, rec, debug.Stack())
			discoveryLookups.WithLabelValues("panic").Inc()
			d.store(addr, "", d.retry)
		}
	}()

	arpa, err := dns.ReverseAddr(addr.String())
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(withDiscovery(ctx), d.timeout)
	defer cancel()

	// The lookup is made on the device's behalf, so it presents the device's
	// address: a view that routes by client IP routes this the same way it
	// routes that device's real queries.
	w := discoveryWriter{local: local, remote: &net.UDPAddr{IP: addr.AsSlice()}}

	name, err := d.resolve(ctx, arpa, w)
	ttl, result := d.ttl, "found"
	switch {
	case err != nil:
		name, ttl, result = "", d.retry, "error"
	case name == "":
		ttl, result = d.retry, "notfound"
	}
	discoveryLookups.WithLabelValues(result).Inc()

	d.store(addr, name, ttl)
}

func (d *discoverer) store(addr netip.Addr, name string, ttl time.Duration) {
	d.mu.Lock()
	if _, exists := d.entries[addr]; !exists && len(d.entries) >= d.max {
		// The table is keyed by client address, so its size is not entirely up
		// to us. Drop an arbitrary entry rather than growing without bound; the
		// worst case is one extra lookup for whoever got dropped.
		for k := range d.entries {
			delete(d.entries, k)
			break
		}
	}
	d.entries[addr] = discoveryEntry{name: name, expires: time.Now().Add(ttl)}
	n := len(d.entries)
	d.mu.Unlock()

	d.labels.set(discoveryEntries, float64(n))
}

// drain blocks until the in-flight lookups finish, or until max elapses. The
// bound matters because a lookup can only be as slow as its own timeout, but
// shutdown should not be hostage to a resolver that never answers at all.
func (d *discoverer) drain(max time.Duration) {
	if d == nil {
		return
	}

	// Stop admitting lookups first. Every Add happens under this lock with
	// closing false, so setting it here establishes that no Add can begin after
	// the Wait below does.
	d.mu.Lock()
	d.closing = true
	d.mu.Unlock()

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(max):
		log.Warningf("Device discovery lookups still running after %s, abandoning them", max)
	}
}

// internalResolver resolves through CoreDNS itself, so the reverse lookup goes
// down the same plugin chain as any other query and picks up whatever already
// serves the reverse zone.
func internalResolver() resolveFunc {
	up := upstream.New()

	return func(ctx context.Context, arpa string, w dns.ResponseWriter) (string, error) {
		req := new(dns.Msg)
		req.SetQuestion(arpa, dns.TypePTR)

		state := request.Request{W: w, Req: req}
		m, err := up.Lookup(ctx, state, arpa, dns.TypePTR)
		if err != nil {
			return "", err
		}
		return ptrName(m)
	}
}

// externalResolver resolves against explicit addresses, for when the reverse
// zone is served by something CoreDNS itself does not know about.
func externalResolver(addrs []string) resolveFunc {
	c := &dns.Client{Net: "udp"}
	tcp := &dns.Client{Net: "tcp"}

	return func(ctx context.Context, arpa string, _ dns.ResponseWriter) (string, error) {
		req := new(dns.Msg)
		req.SetQuestion(arpa, dns.TypePTR)
		req.RecursionDesired = true

		var lastErr error
		for _, addr := range addrs {
			m, _, err := c.ExchangeContext(ctx, req, addr)
			if err != nil {
				lastErr = err
				continue
			}
			if m.Truncated {
				if m2, _, err := tcp.ExchangeContext(ctx, req, addr); err == nil {
					m = m2
				}
			}
			// A resolver that answers SERVFAIL has not answered the question, so
			// move on to the next one. ptrName treats a genuine NXDOMAIN as an
			// answer — this address has no name — and does not fail over on it.
			name, err := ptrName(m)
			if err != nil {
				lastErr = err
				continue
			}
			return name, nil
		}
		if lastErr == nil {
			lastErr = errors.New("no resolver answered")
		}
		return "", lastErr
	}
}

// ptrName pulls the first PTR target out of a reply.
func ptrName(m *dns.Msg) (string, error) {
	if m == nil {
		return "", errors.New("no response")
	}
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return "", errors.New("reverse lookup failed: " + dns.RcodeToString[m.Rcode])
	}
	for _, rr := range m.Answer {
		if ptr, ok := rr.(*dns.PTR); ok {
			return ptr.Ptr, nil
		}
	}
	return "", nil
}

// discoveryWriter is the dns.ResponseWriter for a reverse lookup this plugin
// issues. The lookup runs after the query that triggered it has already been
// answered, so it cannot borrow that query's writer — the server is free to
// have recycled it. This carries a snapshot of the addresses instead and
// discards anything written to it.
type discoveryWriter struct {
	local, remote net.Addr
}

func (w discoveryWriter) LocalAddr() net.Addr         { return w.local }
func (w discoveryWriter) RemoteAddr() net.Addr        { return w.remote }
func (w discoveryWriter) WriteMsg(*dns.Msg) error     { return nil }
func (w discoveryWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w discoveryWriter) Close() error                { return nil }
func (w discoveryWriter) TsigStatus() error           { return nil }
func (w discoveryWriter) TsigTimersOnly(bool)         {}
func (w discoveryWriter) Hijack()                     {}
