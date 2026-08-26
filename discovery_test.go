package nextdns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// lookupIP builds the ClientInfo for a client address, the way ServeDNS would.
func lookupIP(d *deviceDB, ip, profile string) ClientInfo {
	w := discoveryWriter{
		local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53},
		remote: &net.UDPAddr{IP: net.ParseIP(ip), Port: 40000},
	}
	state := &request.Request{W: w, Req: query("example.org.", dns.TypeA)}
	return d.lookup(context.Background(), state, profile)
}

// stubResolver is a resolveFunc that records what it was asked and answers from
// a fixed table, blocking until released when a gate is supplied.
type stubResolver struct {
	names map[string]string
	err   error
	calls atomic.Int64
	gate  chan struct{}
}

func (s *stubResolver) resolve(ctx context.Context, arpa string, _ dns.ResponseWriter) (string, error) {
	s.calls.Add(1)
	if s.gate != nil {
		select {
		case <-s.gate:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if s.err != nil {
		return "", s.err
	}
	return s.names[arpa], nil
}

// newTestDiscoverer returns a discoverer wired to a stub, with timings short
// enough to test against.
func newTestDiscoverer(s *stubResolver) *discoverer {
	d := newDiscoverer()
	d.resolve = s.resolve
	d.ttl = 50 * time.Millisecond
	d.retry = 20 * time.Millisecond
	d.timeout = time.Second
	return d
}

// settle waits for the background lookups to finish.
func settle(t *testing.T, d *discoverer) {
	t.Helper()
	for i := 0; i < 200; i++ {
		d.mu.Lock()
		n := len(d.inflight)
		d.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("discovery lookups did not finish")
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

var testLocal = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}

// The lookup happens off the query path: the first query gets no name, and by
// the time the device asks again the name is there.
func TestDiscoveryIsAsynchronous(t *testing.T) {
	s := &stubResolver{names: map[string]string{"5.1.168.192.in-addr.arpa.": "laptop.lan."}}
	d := newTestDiscoverer(s)

	if got := d.name(context.Background(), addr("192.168.1.5"), testLocal); got != "" {
		t.Errorf("cold miss returned %q, want nothing while the lookup runs", got)
	}
	settle(t, d)

	if got := d.name(context.Background(), addr("192.168.1.5"), testLocal); got != "laptop.lan." {
		t.Errorf("warm lookup = %q, want laptop.lan.", got)
	}
	if s.calls.Load() != 1 {
		t.Errorf("resolver called %d times, want 1", s.calls.Load())
	}
}

func TestDiscoveryDoesNotBlock(t *testing.T) {
	s := &stubResolver{gate: make(chan struct{})}
	d := newTestDiscoverer(s)
	defer close(s.gate)

	done := make(chan struct{})
	go func() {
		d.name(context.Background(), addr("192.168.1.5"), testLocal)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("name blocked on a slow resolver")
	}
}

// Many queries arriving from one device at once must produce one lookup.
func TestDiscoverySingleFlight(t *testing.T) {
	s := &stubResolver{
		names: map[string]string{"5.1.168.192.in-addr.arpa.": "laptop.lan."},
		gate:  make(chan struct{}),
	}
	d := newTestDiscoverer(s)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.name(context.Background(), addr("192.168.1.5"), testLocal)
		}()
	}
	wg.Wait()
	close(s.gate)
	settle(t, d)

	if got := s.calls.Load(); got != 1 {
		t.Errorf("resolver called %d times for one address, want 1", got)
	}
}

func TestDiscoveryExpiry(t *testing.T) {
	s := &stubResolver{names: map[string]string{"5.1.168.192.in-addr.arpa.": "laptop.lan."}}
	d := newTestDiscoverer(s)

	d.name(context.Background(), addr("192.168.1.5"), testLocal)
	settle(t, d)
	if got := d.name(context.Background(), addr("192.168.1.5"), testLocal); got != "laptop.lan." {
		t.Fatalf("got %q, want the cached name", got)
	}

	// Age the entry out.
	d.mu.Lock()
	d.entries[addr("192.168.1.5")] = discoveryEntry{name: "laptop.lan.", expires: time.Now().Add(-time.Second)}
	d.mu.Unlock()

	// An expired entry is still served while its refresh runs, rather than the
	// device losing its name for the duration of a lookup.
	if got := d.name(context.Background(), addr("192.168.1.5"), testLocal); got != "laptop.lan." {
		t.Errorf("got %q during refresh, want the stale name", got)
	}
	settle(t, d)
	if got := s.calls.Load(); got != 2 {
		t.Errorf("resolver called %d times, want a refresh after expiry", got)
	}
}

// An address with no PTR must not be looked up again on every single query.
func TestDiscoveryNegativeResultIsCached(t *testing.T) {
	s := &stubResolver{names: map[string]string{}}
	d := newTestDiscoverer(s)
	d.retry = time.Hour

	for i := 0; i < 5; i++ {
		d.name(context.Background(), addr("192.168.1.9"), testLocal)
		settle(t, d)
	}
	if got := s.calls.Load(); got != 1 {
		t.Errorf("resolver called %d times for an address with no PTR, want 1", got)
	}

	// ...but it is retried once the retry interval passes.
	d.mu.Lock()
	d.entries[addr("192.168.1.9")] = discoveryEntry{expires: time.Now().Add(-time.Second)}
	d.mu.Unlock()
	d.name(context.Background(), addr("192.168.1.9"), testLocal)
	settle(t, d)
	if got := s.calls.Load(); got != 2 {
		t.Errorf("resolver called %d times, want a retry after the interval", got)
	}
}

func TestDiscoveryResolverError(t *testing.T) {
	s := &stubResolver{err: errors.New("boom")}
	d := newTestDiscoverer(s)

	d.name(context.Background(), addr("192.168.1.5"), testLocal)
	settle(t, d)

	if got := d.name(context.Background(), addr("192.168.1.5"), testLocal); got != "" {
		t.Errorf("got %q, want no name after a failed lookup", got)
	}
}

// The table is keyed by client address, which is not something the plugin
// controls, so it has to be bounded.
func TestDiscoveryTableIsBounded(t *testing.T) {
	s := &stubResolver{names: map[string]string{}}
	d := newTestDiscoverer(s)
	d.max = 10

	for i := 0; i < 100; i++ {
		d.store(addr(netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)}).String()), "x", time.Minute)
	}
	d.mu.Lock()
	n := len(d.entries)
	d.mu.Unlock()
	if n > 10 {
		t.Errorf("table holds %d entries, want at most 10", n)
	}
}

func TestDiscoveryInflightIsBounded(t *testing.T) {
	s := &stubResolver{gate: make(chan struct{})}
	d := newTestDiscoverer(s)
	defer close(s.gate)

	for i := 0; i < maxDiscoveryInflight+50; i++ {
		d.name(context.Background(), addr(netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)}).String()), testLocal)
	}

	d.mu.Lock()
	n := len(d.inflight)
	d.mu.Unlock()
	if n > maxDiscoveryInflight {
		t.Errorf("%d lookups in flight, want at most %d", n, maxDiscoveryInflight)
	}
}

func TestDiscoveryDisabled(t *testing.T) {
	var d *discoverer
	if got := d.name(context.Background(), addr("192.168.1.5"), testLocal); got != "" {
		t.Errorf("nil discoverer returned %q", got)
	}
	if got := newDiscoverer().name(context.Background(), addr("192.168.1.5"), testLocal); got != "" {
		t.Errorf("unconfigured discoverer returned %q", got)
	}
}

// Reverse DNS is the last resort: it must not cost a query when a lease file or
// the Corefile already named the device.
func TestDiscoveryOnlyWhenUnnamed(t *testing.T) {
	s := &stubResolver{names: map[string]string{"1.0.0.10.in-addr.arpa.": "from-ptr.lan."}}
	d := newDeviceDB()
	d.discovery = newTestDiscoverer(s)
	d.static[addr("10.0.0.1")] = "From-Corefile"
	d.learned = map[netip.Addr]deviceInfo{addr("10.0.0.2"): {name: "from-lease"}}

	if got := lookupIP(d, "10.0.0.1", "abc123"); got.Name != "From-Corefile" {
		t.Errorf("Name = %q, want the Corefile name", got.Name)
	}
	if got := lookupIP(d, "10.0.0.2", "abc123"); got.Name != "from-lease" {
		t.Errorf("Name = %q, want the lease name", got.Name)
	}
	if got := s.calls.Load(); got != 0 {
		t.Errorf("resolver called %d times for already-named devices, want 0", got)
	}

	// An unnamed device does get looked up, and the result is normalised the
	// same way any other discovered name is.
	s.names["3.0.0.10.in-addr.arpa."] = "from-ptr.lan."
	lookupIP(d, "10.0.0.3", "abc123")
	settle(t, d.discovery)

	if got := lookupIP(d, "10.0.0.3", "abc123"); got.Name != "from-ptr" {
		t.Errorf("Name = %q, want the PTR target with its domain stripped", got.Name)
	}
}

// Without a guard, the reverse lookup would re-enter this plugin, which would
// try to discover the name of the client that asked it, forever.
func TestDiscoveryQueryIsNotForwarded(t *testing.T) {
	c, cap := fakeNextDNS(t, "example.org. 300 IN A 127.0.0.1")
	n := newTestPlugin(t, c, "abc123")

	ctx := withDiscovery(context.Background())
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	rcode, err := n.ServeDNS(ctx, rec, query("5.1.168.192.in-addr.arpa.", dns.TypePTR))
	if err != nil {
		t.Fatal(err)
	}
	if rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want success", rcode)
	}
	if rec.Msg == nil || rec.Msg.Rcode != dns.RcodeNameError {
		t.Errorf("got %v, want NXDOMAIN", rec.Msg)
	}
	if cap.calls.Load() != 0 {
		t.Error("a discovery lookup was sent to NextDNS")
	}
}

// The guard has to survive the trip through the resolver, or the recursion is
// only one level deeper.
func TestDiscoveryMarksItsOwnContext(t *testing.T) {
	seen := make(chan bool, 1)
	d := newDiscoverer()
	d.resolve = func(ctx context.Context, arpa string, _ dns.ResponseWriter) (string, error) {
		seen <- isDiscovery(ctx)
		return "", nil
	}

	if isDiscovery(context.Background()) {
		t.Fatal("a plain context should not look like a discovery lookup")
	}

	d.name(context.Background(), addr("192.168.1.5"), testLocal)
	select {
	case marked := <-seen:
		if !marked {
			t.Error("the reverse lookup ran on an unmarked context")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resolver was never called")
	}
}

// The lookup outlives the query that triggered it, so cancelling that query
// must not cancel the lookup.
func TestDiscoverySurvivesRequestCancellation(t *testing.T) {
	s := &stubResolver{names: map[string]string{"5.1.168.192.in-addr.arpa.": "laptop.lan."}}
	d := newTestDiscoverer(s)

	ctx, cancel := context.WithCancel(context.Background())
	d.name(ctx, addr("192.168.1.5"), testLocal)
	cancel() // the client's query is answered and its context torn down
	settle(t, d)

	if got := d.name(context.Background(), addr("192.168.1.5"), testLocal); got != "laptop.lan." {
		t.Errorf("got %q, want the lookup to have completed anyway", got)
	}
}

func TestDiscoveryWriterPresentsTheDevice(t *testing.T) {
	got := make(chan dns.ResponseWriter, 1)
	d := newDiscoverer()
	d.resolve = func(_ context.Context, _ string, w dns.ResponseWriter) (string, error) {
		got <- w
		return "", nil
	}

	d.name(context.Background(), addr("192.168.1.5"), testLocal)

	select {
	case w := <-got:
		state := request.Request{W: w, Req: query("5.1.168.192.in-addr.arpa.", dns.TypePTR)}
		if state.IP() != "192.168.1.5" {
			t.Errorf("client IP = %q, want the device the lookup is for", state.IP())
		}
		if w.LocalAddr() == nil {
			t.Error("no local address; a view filtering on server_ip would panic")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resolver was never called")
	}
}

func TestPTRName(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("5.1.168.192.in-addr.arpa.", dns.TypePTR)
	rr, _ := dns.NewRR("5.1.168.192.in-addr.arpa. 3600 IN PTR laptop.lan.")
	m.Answer = []dns.RR{rr}
	if got, err := ptrName(m); err != nil || got != "laptop.lan." {
		t.Errorf("got %q, %v", got, err)
	}

	// NXDOMAIN is a real answer: this address has no name.
	nx := new(dns.Msg)
	nx.SetRcode(m, dns.RcodeNameError)
	if got, err := ptrName(nx); err != nil || got != "" {
		t.Errorf("NXDOMAIN: got %q, %v, want no name and no error", got, err)
	}

	// SERVFAIL is not: it should be retried sooner.
	sf := new(dns.Msg)
	sf.SetRcode(m, dns.RcodeServerFailure)
	if _, err := ptrName(sf); err == nil {
		t.Error("SERVFAIL should be reported as an error")
	}

	if _, err := ptrName(nil); err == nil {
		t.Error("a missing response should be an error")
	}
}

// A panic in a detached lookup has no caller left to recover it, and would
// otherwise take the whole resolver down over a device name.
func TestDiscoveryPanicIsContained(t *testing.T) {
	d := newDiscoverer()
	d.retry = 50 * time.Millisecond
	d.resolve = func(context.Context, string, dns.ResponseWriter) (string, error) {
		panic("resolver exploded")
	}

	d.name(context.Background(), addr("192.168.1.5"), testLocal)
	settle(t, d)

	// Survived, released its in-flight slot, and negative-cached so a panicking
	// resolver cannot be re-entered on every single query.
	d.mu.Lock()
	inflight, entries := len(d.inflight), len(d.entries)
	d.mu.Unlock()
	if inflight != 0 {
		t.Errorf("in-flight slot leaked after a panic: %d", inflight)
	}
	if entries != 1 {
		t.Errorf("got %d entries, want the failure recorded so it is not retried immediately", entries)
	}
}

// Shutdown must join detached lookups, not abandon them.
func TestDiscoveryWaitJoinsInflight(t *testing.T) {
	release := make(chan struct{})
	finished := make(chan struct{})
	d := newDiscoverer()
	d.timeout = 5 * time.Second
	d.resolve = func(context.Context, string, dns.ResponseWriter) (string, error) {
		<-release
		close(finished)
		return "", nil
	}

	d.name(context.Background(), addr("192.168.1.5"), testLocal)

	// Nothing finished yet, so wait must not return early.
	start := time.Now()
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(release)
	}()
	d.wait(5 * time.Second)

	select {
	case <-finished:
	default:
		t.Fatal("wait returned before the in-flight lookup finished")
	}
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
		t.Errorf("wait returned after %v, want it to block until the lookup finished", elapsed)
	}
}

// ...but a resolver that never returns must not hold shutdown open forever.
func TestDiscoveryWaitIsBounded(t *testing.T) {
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })

	d := newDiscoverer()
	d.timeout = time.Hour
	d.resolve = func(context.Context, string, dns.ResponseWriter) (string, error) {
		<-stuck
		return "", nil
	}
	d.name(context.Background(), addr("192.168.1.5"), testLocal)

	start := time.Now()
	d.wait(100 * time.Millisecond)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("wait blocked for %v, want it bounded by its grace period", elapsed)
	}
}

func TestDiscoveryWaitOnNilIsSafe(t *testing.T) {
	var d *discoverer
	d.wait(time.Second) // discovery not configured
}

// Queries can still be in flight when the server shuts down. A lookup starting
// then would call wg.Add concurrently with wg.Wait, which panics inside Done —
// past the point lookup's recover can help, so it kills the process.
func TestDiscoveryRefusesNewLookupsWhileShuttingDown(t *testing.T) {
	release := make(chan struct{})
	s := &stubResolver{gate: release}
	d := newTestDiscoverer(s)
	d.timeout = 5 * time.Second

	d.name(context.Background(), addr("192.168.1.5"), testLocal) // one in flight

	waited := make(chan struct{})
	go func() {
		d.wait(5 * time.Second)
		close(waited)
	}()

	// Let wait mark the discoverer as closing.
	for i := 0; i < 200; i++ {
		d.mu.Lock()
		closing := d.closing
		d.mu.Unlock()
		if closing {
			break
		}
		time.Sleep(time.Millisecond)
	}

	// A brand new address must not start a lookup now.
	before := s.calls.Load()
	for i := 0; i < 100; i++ {
		d.name(context.Background(), addr(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}).String()), testLocal)
	}
	if got := s.calls.Load(); got != before {
		t.Errorf("%d lookups started after shutdown began, want 0", got-before)
	}

	close(release)
	<-waited
}

// The same thing hammered, shaped to hit the actual race: a waiter is
// registered while one lookup is genuinely in flight, then that lookup finishes
// at the same moment new lookups try to start. Before the closing guard, an Add
// landing in the window where Done takes the counter to zero with a waiter
// present panics with "WaitGroup misuse" — inside Done, past the point lookup's
// recover can help, so it takes the process down. The runtime reports it as
// "sync: WaitGroup is reused before previous Wait has returned".
func TestDiscoveryShutdownUnderLoad(t *testing.T) {
	for round := 0; round < 300; round++ {
		release := make(chan struct{})
		s := &stubResolver{names: map[string]string{}, gate: release}
		d := newTestDiscoverer(s)
		d.timeout = 5 * time.Second

		// One lookup in flight, so wait registers as a waiter rather than
		// returning straight away.
		d.name(context.Background(), addr("192.168.1.5"), testLocal)

		waiting := make(chan struct{})
		go func() {
			close(waiting)
			d.wait(5 * time.Second)
		}()
		<-waiting

		// Release the in-flight lookup and start new ones at the same instant.
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-waiting
				for j := 0; j < 25; j++ {
					d.name(context.Background(),
						addr(netip.AddrFrom4([4]byte{10, byte(round), byte(i), byte(j)}).String()), testLocal)
				}
			}(i)
		}
		close(release)
		wg.Wait()
		d.wait(2 * time.Second) // shutdown may run more than once
	}
}

// startPTRServer runs a real DNS server on localhost for the external resolver
// tests, since externalResolver is otherwise never executed.
func startPTRServer(t *testing.T, h dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: h}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go srv.ActivateAndServe()
	<-started
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func ptrHandler(rcode int, name string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, rcode)
		if name != "" {
			rr, _ := dns.NewRR(r.Question[0].Name + " 300 IN PTR " + name)
			m.Answer = []dns.RR{rr}
		}
		w.WriteMsg(m)
	}
}

// A resolver answering SERVFAIL has not answered the question; the next
// configured address must get a turn.
func TestExternalResolverFailsOverOnBadRcode(t *testing.T) {
	broken := startPTRServer(t, ptrHandler(dns.RcodeServerFailure, ""))
	good := startPTRServer(t, ptrHandler(dns.RcodeSuccess, "laptop.lan."))

	resolve := externalResolver([]string{broken, good})
	name, err := resolve(context.Background(), "5.1.168.192.in-addr.arpa.", nil)
	if err != nil {
		t.Fatalf("failover did not happen: %v", err)
	}
	if name != "laptop.lan." {
		t.Errorf("name = %q, want the second resolver's answer", name)
	}
}

// NXDOMAIN is a real answer — this address has no name — so it must not fail
// over to another resolver that might invent one.
func TestExternalResolverAcceptsNXDOMAIN(t *testing.T) {
	var secondCalled atomic.Bool
	nx := startPTRServer(t, ptrHandler(dns.RcodeNameError, ""))
	second := startPTRServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		secondCalled.Store(true)
		ptrHandler(dns.RcodeSuccess, "invented.lan.")(w, r)
	})

	resolve := externalResolver([]string{nx, second})
	name, err := resolve(context.Background(), "5.1.168.192.in-addr.arpa.", nil)
	if err != nil {
		t.Fatalf("NXDOMAIN should be an answer, not an error: %v", err)
	}
	if name != "" {
		t.Errorf("name = %q, want none", name)
	}
	if secondCalled.Load() {
		t.Error("failed over past a valid NXDOMAIN")
	}
}

func TestExternalResolverAllFail(t *testing.T) {
	broken := startPTRServer(t, ptrHandler(dns.RcodeServerFailure, ""))
	resolve := externalResolver([]string{broken})
	if _, err := resolve(context.Background(), "5.1.168.192.in-addr.arpa.", nil); err == nil {
		t.Error("expected an error when every resolver fails")
	}
}

// internalResolver needs the server on the context; without it upstream.Lookup
// returns a nil message rather than an error, so ptrName has to catch it.
func TestInternalResolverWithoutServer(t *testing.T) {
	resolve := internalResolver()
	w := discoveryWriter{
		local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53},
		remote: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1)},
	}
	if _, err := resolve(context.Background(), "1.0.0.10.in-addr.arpa.", w); err == nil {
		t.Error("expected an error with no server on the context")
	}
}
