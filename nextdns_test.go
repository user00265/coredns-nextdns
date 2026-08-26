package nextdns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// capture records what a fake NextDNS endpoint saw.
type capture struct {
	path    string
	headers http.Header
	calls   atomic.Int64
}

// fakeNextDNS stands up an HTTPS endpoint that speaks the NextDNS DoH protocol
// and answers every query with answer.
func fakeNextDNS(t *testing.T, answer string) (*dohClient, *capture) {
	t.Helper()
	cap := &capture{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.calls.Add(1)
		cap.path = r.URL.Path
		cap.headers = r.Header.Clone()

		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		m := new(dns.Msg)
		m.SetReply(q)
		if answer != "" {
			rr, err := dns.NewRR(answer)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			m.Answer = []dns.RR{rr}
		}
		wire, _ := m.Pack()

		w.Header().Set("Content-Type", dnsMessageMIME)
		w.Write(wire)
	}))
	t.Cleanup(ts.Close)

	c, err := newDOHClient(dohOptions{endpoints: []string{ts.URL}, timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c.hc = ts.Client()
	return c, cap
}

func newTestPlugin(t *testing.T, c *dohClient, profile string) *NextDNS {
	t.Helper()
	n := New()
	n.profile = profile
	n.client = c
	n.Next = test.ErrorHandler()
	return n
}

func query(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	return m
}

func TestServeDNS(t *testing.T) {
	c, cap := fakeNextDNS(t, "example.org. 300 IN A 127.0.0.1")
	n := newTestPlugin(t, c, "abc123")
	n.devices.static[mustAddr("10.240.0.1")] = "Test-Device"

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	rcode, err := n.ServeDNS(context.Background(), rec, query("example.org.", dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want success", rcode)
	}
	if rec.Msg == nil || len(rec.Msg.Answer) != 1 {
		t.Fatalf("got %v, want one answer", rec.Msg)
	}

	// The profile is the URL path, which is how NextDNS attributes the query.
	if cap.path != "/abc123" {
		t.Errorf("path = %q, want /abc123", cap.path)
	}
	if got := cap.headers.Get("X-Device-Name"); got != "Test-Device" {
		t.Errorf("X-Device-Name = %q, want Test-Device", got)
	}
	if got := cap.headers.Get("X-Device-Ip"); got != "10.240.0.1" {
		t.Errorf("X-Device-Ip = %q, want 10.240.0.1", got)
	}
	if got := cap.headers.Get("X-Device-Id"); got != shortID("abc123", mustAddr("10.240.0.1").AsSlice()) {
		t.Errorf("X-Device-Id = %q, want the derived short ID", got)
	}
	if got := cap.headers.Get("Content-Type"); got != dnsMessageMIME {
		t.Errorf("Content-Type = %q, want %q", got, dnsMessageMIME)
	}
}

func TestServeDNSPreservesQueryID(t *testing.T) {
	c, _ := fakeNextDNS(t, "example.org. 300 IN A 127.0.0.1")
	n := newTestPlugin(t, c, "abc123")

	q := query("example.org.", dns.TypeA)
	q.Id = 4242

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := n.ServeDNS(context.Background(), rec, q); err != nil {
		t.Fatal(err)
	}
	if rec.Msg.Id != 4242 {
		t.Errorf("reply ID = %d, want the client's 4242", rec.Msg.Id)
	}
}

func TestServeDNSUpstreamFailure(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	c, err := newDOHClient(dohOptions{endpoints: []string{ts.URL}, timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c.hc = ts.Client()

	n := newTestPlugin(t, c, "abc123")
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	rcode, err := n.ServeDNS(context.Background(), rec, query("example.org.", dns.TypeA))
	if err == nil {
		t.Fatal("expected an error")
	}
	if rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %d, want SERVFAIL", rcode)
	}
}

func TestExchangeFailsOverToNextEndpoint(t *testing.T) {
	dead := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer dead.Close()

	good, cap := fakeNextDNS(t, "example.org. 300 IN A 127.0.0.1")
	// Reuse the working client's transport but put the dead endpoint first.
	ep, err := parseEndpoint(dead.URL)
	if err != nil {
		t.Fatal(err)
	}
	good.endpoints = append([]*endpoint{ep}, good.endpoints...)
	good.hc.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true

	m, err := good.exchange(context.Background(), "abc123", query("example.org.", dns.TypeA), ClientInfo{})
	if err != nil {
		t.Fatalf("failover did not happen: %v", err)
	}
	if len(m.Answer) != 1 {
		t.Errorf("got %v, want the healthy endpoint's answer", m)
	}
	if cap.calls.Load() != 1 {
		t.Errorf("healthy endpoint got %d calls, want 1", cap.calls.Load())
	}
}

func TestProfileSelection(t *testing.T) {
	c, _ := fakeNextDNS(t, "")
	n := newTestPlugin(t, c, "default1")
	n.viewProfiles["guests"] = "guests1"
	n.clientProfiles = []clientProfile{
		{prefix: mustPrefix("10.240.0.1/32"), profile: "host111"},
		{prefix: mustPrefix("10.240.0.0/16"), profile: "subnet1"},
	}

	state := &request.Request{W: &test.ResponseWriter{}, Req: query("example.org.", dns.TypeA)}

	// Client subnet overrides the default; longest prefix wins.
	if got := n.profileFor(context.Background(), state); got != "host111" {
		t.Errorf("profile = %q, want host111", got)
	}

	// A view overrides the client subnet.
	ctx := metadata.ContextWithMetadata(context.Background())
	metadata.SetValueFunc(ctx, "view/name", func() string { return "guests" })
	if got := n.profileFor(ctx, state); got != "guests1" {
		t.Errorf("profile = %q, want guests1", got)
	}

	// An explicit metadata label overrides everything.
	metadata.SetValueFunc(ctx, profileLabel, func() string { return "meta111" })
	if got := n.profileFor(ctx, state); got != "meta111" {
		t.Errorf("profile = %q, want meta111", got)
	}

	// An unknown view falls through to the client subnet rules.
	ctx2 := metadata.ContextWithMetadata(context.Background())
	metadata.SetValueFunc(ctx2, "view/name", func() string { return "nosuchview" })
	if got := n.profileFor(ctx2, state); got != "host111" {
		t.Errorf("profile = %q, want host111", got)
	}
}

func TestPassthroughProfile(t *testing.T) {
	c, cap := fakeNextDNS(t, "")
	n := newTestPlugin(t, c, "default1")
	n.viewProfiles["internal"] = passthrough

	called := false
	n.Next = plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		called = true
		m := new(dns.Msg)
		m.SetReply(r)
		w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	})

	ctx := metadata.ContextWithMetadata(context.Background())
	metadata.SetValueFunc(ctx, "view/name", func() string { return "internal" })

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := n.ServeDNS(ctx, rec, query("internal.example.", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("query was not handed to the next plugin")
	}
	if cap.calls.Load() != 0 {
		t.Error("query reached NextDNS despite the passthrough profile")
	}
}

func TestMetadataPublished(t *testing.T) {
	c, _ := fakeNextDNS(t, "example.org. 300 IN A 127.0.0.1")
	n := newTestPlugin(t, c, "abc123")
	n.devices.static[mustAddr("10.240.0.1")] = "Test-Device"

	ctx := metadata.ContextWithMetadata(context.Background())
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := n.ServeDNS(ctx, rec, query("example.org.", dns.TypeA)); err != nil {
		t.Fatal(err)
	}

	for label, want := range map[string]string{
		"nextdns/profile-used": "abc123",
		"nextdns/device-name":  "Test-Device",
		"nextdns/device-ip":    "10.240.0.1",
	} {
		f := metadata.ValueFunc(ctx, label)
		if f == nil {
			t.Errorf("%s not published", label)
			continue
		}
		if got := f(); got != want {
			t.Errorf("%s = %q, want %q", label, got, want)
		}
	}

	// Nothing supplied a model here, so the label must be absent rather than
	// empty: the log plugin renders a missing label as "-" and an empty one as a
	// blank field.
	if f := metadata.ValueFunc(ctx, "nextdns/device-model"); f != nil {
		t.Errorf("nextdns/device-model published as %q, want the label omitted", f())
	}
}

func TestMaxConcurrent(t *testing.T) {
	release := make(chan struct{})
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		q.Unpack(body)
		m := new(dns.Msg)
		m.SetReply(q)
		wire, _ := m.Pack()
		w.Write(wire)
	}))
	defer ts.Close()
	defer close(release)

	c, err := newDOHClient(dohOptions{endpoints: []string{ts.URL}, timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c.hc = ts.Client()

	n := newTestPlugin(t, c, "abc123")
	n.maxConcurrent = 1

	started := make(chan struct{})
	go func() {
		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		close(started)
		n.ServeDNS(context.Background(), rec, query("slow.example.", dns.TypeA))
	}()
	<-started

	// Wait for the first query to be counted as in flight.
	for i := 0; i < 100 && atomicLoad(n) == 0; i++ {
		time.Sleep(time.Millisecond)
	}

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	rcode, err := n.ServeDNS(context.Background(), rec, query("second.example.", dns.TypeA))
	if err != ErrMaxConcurrent {
		t.Fatalf("err = %v, want ErrMaxConcurrent", err)
	}
	if rcode != dns.RcodeRefused {
		t.Errorf("rcode = %d, want REFUSED", rcode)
	}
}

func atomicLoad(n *NextDNS) int64 { return atomic.LoadInt64(&n.concurrent) }

// An endpoint that declared bootstrap addresses must never fall back to a
// hostname dial when they all fail: on a machine resolving through this server,
// that fallback queries this server for the endpoint's own name.
func TestBootstrapDialDoesNotFallBack(t *testing.T) {
	// A real listener the plain fallback dial would happily have connected to.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	c, err := newDOHClient(dohOptions{
		// localhost resolves, and the listener is up — only the bootstrap
		// address is unreachable.
		endpoints: []string{"https://localhost:" + port + "#203.0.113.1"},
		timeout:   200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.dial(context.Background(), "tcp", "localhost:"+port); err == nil {
		t.Fatal("dial succeeded; it fell back to the system resolver instead of failing")
	} else if !strings.Contains(err.Error(), "refusing to fall back") {
		t.Errorf("err = %v, want it to name the refused fallback", err)
	}

	// A host that declared nothing still gets a plain dial — that is all we have.
	c2, err := newDOHClient(dohOptions{
		endpoints: []string{"https://localhost:" + port},
		timeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := c2.dial(context.Background(), "tcp", "localhost:"+port)
	if err != nil {
		t.Fatalf("host with no bootstrap should still dial normally: %v", err)
	}
	conn.Close()
}

// A NextDNS hostname written without bootstrap addresses still gets them, so
// the ordinary configuration does not quietly depend on another resolver.
func TestWellKnownBootstrapIsFilledIn(t *testing.T) {
	c, err := newDOHClient(dohOptions{endpoints: []string{
		"https://dns.nextdns.io",
		"https://dns1.nextdns.io",
		"https://dns2.nextdns.io",
		"https://doh.example.org",
	}})
	if err != nil {
		t.Fatal(err)
	}

	want := map[string][]string{
		"dns.nextdns.io":  {"45.90.28.0", "2a07:a8c0::", "45.90.30.0", "2a07:a8c1::"},
		"dns1.nextdns.io": {"45.90.28.0", "2a07:a8c0::"},
		"dns2.nextdns.io": {"45.90.30.0", "2a07:a8c1::"},
		"doh.example.org": nil, // not ours to guess
	}
	for _, ep := range c.endpoints {
		if got := ep.bootstrap; !slices.Equal(got, want[ep.host]) {
			t.Errorf("%s bootstrap = %v, want %v", ep.host, got, want[ep.host])
		}
	}

	// Explicit configuration still wins over the table.
	c, err = newDOHClient(dohOptions{endpoints: []string{"https://dns.nextdns.io#203.0.113.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.endpoints[0].bootstrap; len(got) != 1 || got[0] != "203.0.113.1" {
		t.Errorf("bootstrap = %v, want the explicitly configured address", got)
	}
}

// Two endpoints may share a hostname; the transport only tells dial the host,
// so it has to consider every endpoint that could have produced the request.
func TestBootstrapUnionAcrossSharedHost(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())

	// First endpoint's bootstrap is dead, second endpoint's is the live listener.
	c, err := newDOHClient(dohOptions{
		endpoints: []string{
			"https://localhost:" + port + "#203.0.113.1",
			"https://localhost:" + port + "/alt#" + host,
		},
		timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := c.dial(context.Background(), "tcp", "localhost:"+port)
	if err != nil {
		t.Fatalf("dial failed even though a sibling endpoint listed a working address: %v", err)
	}
	conn.Close()
}

func TestEndpointAddrsFilterByNetwork(t *testing.T) {
	ep, err := parseEndpoint("https://dns.nextdns.io#45.90.28.0,2a07:a8c0::")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ network, want string }{
		{"tcp4", "45.90.28.0"},
		{"tcp6", "2a07:a8c0::"},
	} {
		got := ep.addrs(tc.network)
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("addrs(%q) = %v, want [%s]", tc.network, got, tc.want)
		}
	}
	if got := ep.addrs("tcp"); len(got) != 2 {
		t.Errorf(`addrs("tcp") = %v, want both`, got)
	}
}

func TestEndpointRotates(t *testing.T) {
	ep, err := parseEndpoint("https://dns.nextdns.io#1.1.1.1,2.2.2.2,3.3.3.3")
	if err != nil {
		t.Fatal(err)
	}
	first := ep.addrs("tcp4")[0]
	second := ep.addrs("tcp4")[0]
	if first == second {
		t.Errorf("bootstrap addresses are not rotating, got %q twice", first)
	}
}

func TestUpdateLastMod(t *testing.T) {
	c, _ := fakeNextDNS(t, "")

	c.updateLastMod("abc123", "Mon, 02 Jan 2006 15:04:05 UTC")
	first := c.confChangedAt("abc123")
	if first.IsZero() {
		t.Fatal("last modified not recorded")
	}

	// Older timestamps must not move it backwards.
	c.updateLastMod("abc123", "Sun, 01 Jan 2006 15:04:05 UTC")
	if !c.confChangedAt("abc123").Equal(first) {
		t.Error("an older timestamp moved the configuration change time backwards")
	}

	c.updateLastMod("abc123", "not a date")
	if !c.confChangedAt("abc123").Equal(first) {
		t.Error("an unparsable header changed the configuration change time")
	}

	if !c.confChangedAt("other1").IsZero() {
		t.Error("last modified leaked across profiles")
	}
}

func TestParseEndpointErrors(t *testing.T) {
	for _, in := range []string{
		"http://dns.nextdns.io",
		"dns.nextdns.io",
		"https://dns.nextdns.io#1.2.3",
		"https://",
	} {
		if _, err := parseEndpoint(in); err == nil {
			t.Errorf("expected an error for %q", in)
		}
	}
}

func TestUserAgent(t *testing.T) {
	c, cap := fakeNextDNS(t, "")
	if _, err := c.exchange(context.Background(), "abc123", query("example.org.", dns.TypeA), ClientInfo{}); err != nil {
		t.Fatal(err)
	}
	if ua := cap.headers.Get("User-Agent"); !strings.HasPrefix(ua, "coredns-nextdns/") {
		t.Errorf("User-Agent = %q", ua)
	}
	if cap.headers.Get("X-Conf-Last-Modified") != "true" {
		t.Error("X-Conf-Last-Modified not requested; profile changes would not invalidate the cache")
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// Go copies custom headers across a redirect to a different host, stripping
// only Authorization and Cookie. Following one here would hand the device's LAN
// IP, name and ID to whatever host the redirect names.
func TestExchangeDoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Int64
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Device-Name") != "" || r.Header.Get("X-Device-Ip") != "" {
			leaked.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()

	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL+"/steal", http.StatusFound)
	}))
	defer redirector.Close()

	c, err := newDOHClient(dohOptions{endpoints: []string{redirector.URL}, timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c.hc.Transport = redirector.Client().Transport
	c.hc.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true

	ci := ClientInfo{ID: "ABCDE", IP: "10.0.0.1", Name: "laptop"}
	if _, err := c.exchange(context.Background(), "abc123", query("example.org.", dns.TypeA), ci); err == nil {
		t.Error("a redirected DoH request should be an error, not a followed hop")
	}
	if n := leaked.Load(); n != 0 {
		t.Errorf("device headers reached the redirect target %d times", n)
	}
}

// The metadata label is set at request time by another plugin, so unlike the
// Corefile values it has never been checked. It is interpolated into a URL path
// and used as a Prometheus label.
func TestMetadataProfileIsValidated(t *testing.T) {
	c, _ := fakeNextDNS(t, "")
	n := newTestPlugin(t, c, "default1")
	state := &request.Request{W: &test.ResponseWriter{}, Req: query("example.org.", dns.TypeA)}

	for _, bad := range []string{
		"../../v1/admin",         // escapes the profile path segment
		"abc123?foo=bar",         // turns the rest into a query string
		"/evil.example/x",        // changes the request target
		"abc 123",                // not a legal URL path segment
		strings.Repeat("a", 200), // unbounded metric label
	} {
		ctx := metadata.ContextWithMetadata(context.Background())
		metadata.SetValueFunc(ctx, profileLabel, func() string { return bad })
		if got := n.profileFor(ctx, state); got != "default1" {
			t.Errorf("profile %q was accepted, got %q; want the configured fallback", bad, got)
		}
	}

	// Well-formed values still work, including the passthrough marker.
	for _, good := range []string{"abc123", passthrough} {
		ctx := metadata.ContextWithMetadata(context.Background())
		metadata.SetValueFunc(ctx, profileLabel, func() string { return good })
		if got := n.profileFor(ctx, state); got != good {
			t.Errorf("profile %q = %q, want it honoured", good, got)
		}
	}
}

// reply no longer sizes or truncates: the server wraps every plugin's writer in
// a ScrubWriter that does both. Restoring the client's ID is still this
// plugin's job, because the query goes upstream with ID 0.
func TestServeDNSLeavesScrubbingToTheServer(t *testing.T) {
	// An answer comfortably over the 512 byte limit a bare UDP client advertises.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		m := new(dns.Msg)
		m.SetReply(q)
		for i := 0; i < 40; i++ {
			rr, err := dns.NewRR(fmt.Sprintf("big.example. 300 IN A 10.0.%d.%d", i/256, i%256))
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			m.Answer = append(m.Answer, rr)
		}
		wire, _ := m.Pack()
		w.Write(wire)
	}))
	defer ts.Close()

	c, err := newDOHClient(dohOptions{endpoints: []string{ts.URL}, timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c.hc = ts.Client()
	n := newTestPlugin(t, c, "abc123")

	q := query("big.example.", dns.TypeA)
	q.Id = 4242

	// The server hands plugins a ScrubWriter; reproduce that here.
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := n.ServeDNS(context.Background(), request.NewScrubWriter(q, rec), q); err != nil {
		t.Fatal(err)
	}

	if rec.Msg.Id != 4242 {
		t.Errorf("reply ID = %d, want the client's 4242", rec.Msg.Id)
	}
	if !rec.Msg.Truncated {
		t.Error("oversized reply was not truncated; the server's ScrubWriter should have done it")
	}
	if size := rec.Msg.Len(); size > 512 {
		t.Errorf("reply is %d bytes, want it scrubbed to the client's 512 byte buffer", size)
	}
}

// The warning is bounded to once, but once per plugin instance — a package
// level sync.Once would let one server block permanently silence the
// diagnostic for every other block and for every later reload.
func TestInvalidProfileWarningIsPerInstance(t *testing.T) {
	var buf bytes.Buffer
	stdlog.SetOutput(&buf)
	t.Cleanup(func() { stdlog.SetOutput(os.Stderr) })

	c, _ := fakeNextDNS(t, "")
	state := &request.Request{W: &test.ResponseWriter{}, Req: query("example.org.", dns.TypeA)}

	warn := func(n *NextDNS) {
		ctx := metadata.ContextWithMetadata(context.Background())
		metadata.SetValueFunc(ctx, profileLabel, func() string { return "not a profile" })
		if got := n.profileFor(ctx, state); got != "default1" {
			t.Fatalf("profile = %q, want the configured fallback", got)
		}
	}

	first := newTestPlugin(t, c, "default1")
	warn(first)
	warn(first) // bounded: the second occurrence must not log again
	if got := strings.Count(buf.String(), "Ignoring invalid"); got != 1 {
		t.Errorf("one instance logged %d times, want exactly 1", got)
	}

	// A second instance has its own budget.
	warn(newTestPlugin(t, c, "default1"))
	if got := strings.Count(buf.String(), "Ignoring invalid"); got != 2 {
		t.Errorf("logged %d times across two instances, want 2 — the second instance was silenced by the first", got)
	}
}

// An upstream answering a question we did not ask is not usable. It must not
// reach the cache, and it must be visible — it was previously silent in both
// logs and metrics.
func TestServeDNSCountsMismatchedReplies(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		q.Unpack(body)

		// Answer a different question than the one asked.
		m := new(dns.Msg)
		m.SetQuestion("somethingelse.example.", dns.TypeA)
		m.Response = true
		m.Id = q.Id
		wire, _ := m.Pack()
		w.Write(wire)
	}))
	defer ts.Close()

	c, err := newDOHClient(dohOptions{endpoints: []string{ts.URL}, timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c.hc = ts.Client()

	n := newTestPlugin(t, c, "abc123")
	n.cache = newMsgCache(100, c)

	before := testutil.ToFloat64(mismatchCount.WithLabelValues(""))

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	rcode, err := n.ServeDNS(context.Background(), rec, query("example.org.", dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want success (the response was written here)", rcode)
	}
	if rec.Msg == nil || rec.Msg.Rcode != dns.RcodeFormatError {
		t.Errorf("got %v, want FORMERR", rec.Msg)
	}
	if got := testutil.ToFloat64(mismatchCount.WithLabelValues("")) - before; got != 1 {
		t.Errorf("mismatch counter moved by %v, want 1", got)
	}
	if n.cache.c.Len() != 0 {
		t.Error("a mismatched reply reached the cache")
	}
}

// request.IP returns the interface zone verbatim for a link-local client, and
// netip.Prefix.Contains is false for any address carrying one — so a zoned
// client used to match no client_profile and no device_name, and shipped the
// zone to NextDNS in X-Device-Ip.
func TestZonedAndMappedClientAddresses(t *testing.T) {
	for _, tc := range []struct{ remote, want string }{
		{"[fe80::1%eth0]:5353", "fe80::1"},
		{"[fe80::1]:5353", "fe80::1"},
		{"[::ffff:10.0.0.7]:5353", "10.0.0.7"},
		{"10.0.0.7:5353", "10.0.0.7"},
	} {
		addr, ok := clientAddr(hostOf(tc.remote))
		if !ok {
			t.Errorf("%s: not parsed", tc.remote)
			continue
		}
		if addr.String() != tc.want {
			t.Errorf("%s -> %q, want %q", tc.remote, addr.String(), tc.want)
		}
	}

	c, cap := fakeNextDNS(t, "")
	n := newTestPlugin(t, c, "default1")
	n.clientProfiles = []clientProfile{{prefix: mustPrefix("fe80::/10"), profile: "linklo"}}
	n.devices.static[mustAddr("fe80::1")] = "Zoned-Device"

	w := discoveryWriter{
		local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53},
		remote: &net.UDPAddr{IP: net.ParseIP("fe80::1"), Zone: "eth0", Port: 5353},
	}
	q := query("example.org.", dns.TypeA)
	state := &request.Request{W: w, Req: q}

	if got := n.profileFor(context.Background(), state); got != "linklo" {
		t.Errorf("profile = %q, want linklo — the zone stopped the prefix matching", got)
	}

	ci := n.devices.lookup(context.Background(), state, "abc123")
	if ci.IP != "fe80::1" {
		t.Errorf("X-Device-Ip = %q, want the zone stripped", ci.IP)
	}
	if ci.Name != "Zoned-Device" {
		t.Errorf("device name = %q, want the pinned name to match a zoned client", ci.Name)
	}
	_ = cap
}

func hostOf(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return h
}

// The concurrency limit exists to protect the upstream. A cache hit never
// reaches it, so a burst of hits must not be refused because slow upstream
// queries are holding every slot.
func TestMaxConcurrentDoesNotRefuseCacheHits(t *testing.T) {
	release := make(chan struct{})
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		q.Unpack(body)
		m := new(dns.Msg)
		m.SetReply(q)
		if rr, err := dns.NewRR("cached.example. 300 IN A 127.0.0.1"); err == nil && q.Question[0].Name == "cached.example." {
			m.Answer = []dns.RR{rr}
		} else {
			<-release // everything else stalls, holding a slot
		}
		wire, _ := m.Pack()
		w.Write(wire)
	}))
	defer ts.Close()
	defer close(release)

	c, err := newDOHClient(dohOptions{endpoints: []string{ts.URL}, timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c.hc = ts.Client()

	n := newTestPlugin(t, c, "abc123")
	n.cache = newMsgCache(100, c)
	n.maxConcurrent = 1

	// Populate the cache with one name.
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := n.ServeDNS(context.Background(), rec, query("cached.example.", dns.TypeA)); err != nil {
		t.Fatal(err)
	}

	// Saturate the single slot with a stalled upstream query.
	started := make(chan struct{})
	go func() {
		close(started)
		n.ServeDNS(context.Background(), dnstest.NewRecorder(&test.ResponseWriter{}), query("slow.example.", dns.TypeA))
	}()
	<-started
	for i := 0; i < 200 && atomicLoad(n) == 0; i++ {
		time.Sleep(time.Millisecond)
	}

	// The cached name must still be served.
	rec = dnstest.NewRecorder(&test.ResponseWriter{})
	rcode, err := n.ServeDNS(context.Background(), rec, query("cached.example.", dns.TypeA))
	if err != nil {
		t.Fatalf("cache hit was refused while the limiter was saturated: %v", err)
	}
	if rcode != dns.RcodeSuccess || len(rec.Msg.Answer) != 1 {
		t.Errorf("rcode = %d, msg = %v, want the cached answer", rcode, rec.Msg)
	}
}
