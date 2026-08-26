package nextdns

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

func TestBootstrapDial(t *testing.T) {
	// A bootstrap address that cannot be reached must not stop the client from
	// falling back to a normal dial.
	c, err := newDOHClient(dohOptions{
		endpoints: []string{"https://dns.nextdns.io#203.0.113.1"},
		timeout:   100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.endpoints[0].bootstrap; len(got) != 1 || got[0] != "203.0.113.1" {
		t.Fatalf("bootstrap = %v", got)
	}
	if c.endpoints[0].base != "https://dns.nextdns.io" {
		t.Errorf("base = %q", c.endpoints[0].base)
	}
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
