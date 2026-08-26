package nextdns

import (
	"context"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

func testState(qname string, qtype uint16) *request.Request {
	return &request.Request{W: &test.ResponseWriter{}, Req: query(qname, qtype)}
}

func reply(qname, answer string) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(query(qname, dns.TypeA))
	rr, err := dns.NewRR(answer)
	if err != nil {
		panic(err)
	}
	m.Answer = []dns.RR{rr}
	return m
}

func TestCacheRoundTrip(t *testing.T) {
	c, _ := fakeNextDNS(t, "")
	mc := newMsgCache(100, c)

	state := testState("example.org.", dns.TypeA)
	if _, ok := mc.get("abc123", state); ok {
		t.Fatal("empty cache returned a hit")
	}

	mc.put("abc123", state, reply("example.org.", "example.org. 300 IN A 127.0.0.1"))

	m, ok := mc.get("abc123", state)
	if !ok {
		t.Fatal("expected a hit")
	}
	if len(m.Answer) != 1 || m.Answer[0].Header().Ttl == 0 {
		t.Errorf("got %v, want an answer with a non-zero TTL", m)
	}
}

// The whole point of this cache: two profiles can legitimately have different
// answers for the same question, because they can have different blocklists.
func TestCacheIsProfileScoped(t *testing.T) {
	c, _ := fakeNextDNS(t, "")
	mc := newMsgCache(100, c)
	state := testState("ads.example.org.", dns.TypeA)

	mc.put("abc123", state, reply("ads.example.org.", "ads.example.org. 300 IN A 127.0.0.1"))

	if _, ok := mc.get("def456", state); ok {
		t.Fatal("one profile's answer was served to another profile")
	}
	if _, ok := mc.get("abc123", state); !ok {
		t.Error("the profile that stored the entry did not get a hit")
	}
}

func TestCacheKeyDistinguishesQuestions(t *testing.T) {
	a := cacheKey("abc123", testState("example.org.", dns.TypeA))

	for name, other := range map[string]uint64{
		"different profile": cacheKey("def456", testState("example.org.", dns.TypeA)),
		"different qname":   cacheKey("abc123", testState("example.com.", dns.TypeA)),
		"different qtype":   cacheKey("abc123", testState("example.org.", dns.TypeAAAA)),
	} {
		if a == other {
			t.Errorf("cache key collides on %s", name)
		}
	}

	// The same question under the same profile must hit the same key.
	if a != cacheKey("abc123", testState("example.org.", dns.TypeA)) {
		t.Error("cache key is not stable")
	}
}

func TestCacheKeyIncludesDOBit(t *testing.T) {
	plain := testState("example.org.", dns.TypeA)

	withDO := testState("example.org.", dns.TypeA)
	withDO.Req.SetEdns0(4096, true)

	if cacheKey("abc123", plain) == cacheKey("abc123", withDO) {
		t.Error("DO bit does not affect the cache key; DNSSEC records would be served to clients that did not ask for them")
	}
}

func TestCacheTTLCountsDown(t *testing.T) {
	c, _ := fakeNextDNS(t, "")
	mc := newMsgCache(100, c)
	state := testState("example.org.", dns.TypeA)

	mc.put("abc123", state, reply("example.org.", "example.org. 300 IN A 127.0.0.1"))

	// Pretend 100 seconds went by.
	e, _ := mc.c.Get(cacheKey("abc123", state))
	e.stored = e.stored.Add(-100 * time.Second)

	m, ok := mc.get("abc123", state)
	if !ok {
		t.Fatal("expected a hit")
	}
	if ttl := m.Answer[0].Header().Ttl; ttl != 200 {
		t.Errorf("TTL = %d, want 200", ttl)
	}

	// And past the end of its life it is gone.
	e.stored = e.stored.Add(-300 * time.Second)
	if _, ok := mc.get("abc123", state); ok {
		t.Error("expired entry was served")
	}
}

func TestCacheTTLClamped(t *testing.T) {
	c, _ := fakeNextDNS(t, "")
	mc := newMsgCache(100, c)
	mc.minTTL, mc.maxTTL = 10*time.Second, 60*time.Second

	state := testState("short.example.", dns.TypeA)
	mc.put("abc123", state, reply("short.example.", "short.example. 1 IN A 127.0.0.1"))
	if e, _ := mc.c.Get(cacheKey("abc123", state)); e.ttl != 10*time.Second {
		t.Errorf("ttl = %v, want it raised to the minimum", e.ttl)
	}

	state = testState("long.example.", dns.TypeA)
	mc.put("abc123", state, reply("long.example.", "long.example. 86400 IN A 127.0.0.1"))
	if e, _ := mc.c.Get(cacheKey("abc123", state)); e.ttl != 60*time.Second {
		t.Errorf("ttl = %v, want it capped at the maximum", e.ttl)
	}
}

// A profile configuration change (a blocklist edit, say) must take effect
// without waiting for TTLs to run out.
func TestCacheInvalidatedByProfileChange(t *testing.T) {
	c, _ := fakeNextDNS(t, "")
	mc := newMsgCache(100, c)
	state := testState("example.org.", dns.TypeA)

	mc.put("abc123", state, reply("example.org.", "example.org. 300 IN A 127.0.0.1"))
	if _, ok := mc.get("abc123", state); !ok {
		t.Fatal("expected a hit before the configuration change")
	}

	c.mu.Lock()
	c.lastMod["abc123"] = time.Now().Add(time.Second)
	c.mu.Unlock()

	if _, ok := mc.get("abc123", state); ok {
		t.Error("stale entry served after the profile configuration changed")
	}
	// Other profiles are unaffected.
	mc.put("def456", state, reply("example.org.", "example.org. 300 IN A 127.0.0.1"))
	if _, ok := mc.get("def456", state); !ok {
		t.Error("an unrelated profile's entries were invalidated")
	}
}

func TestCacheSkipsUncacheable(t *testing.T) {
	c, _ := fakeNextDNS(t, "")
	mc := newMsgCache(100, c)

	// PTR: RFC 1035 section 7.4 says inverse query results are not cached.
	ptr := testState("1.0.0.10.in-addr.arpa.", dns.TypePTR)
	m := new(dns.Msg)
	m.SetReply(ptr.Req)
	mc.put("abc123", ptr, m)
	if _, ok := mc.get("abc123", ptr); ok {
		t.Error("PTR response was cached")
	}

	// SERVFAIL and friends are not answers worth remembering.
	state := testState("broken.example.", dns.TypeA)
	fail := new(dns.Msg)
	fail.SetRcode(state.Req, dns.RcodeServerFailure)
	mc.put("abc123", state, fail)
	if _, ok := mc.get("abc123", state); ok {
		t.Error("SERVFAIL was cached")
	}

	// Truncated messages are incomplete by definition.
	state = testState("truncated.example.", dns.TypeA)
	trunc := reply("truncated.example.", "truncated.example. 300 IN A 127.0.0.1")
	trunc.Truncated = true
	mc.put("abc123", state, trunc)
	if _, ok := mc.get("abc123", state); ok {
		t.Error("truncated response was cached")
	}
}

func TestCacheStoresNXDOMAIN(t *testing.T) {
	c, _ := fakeNextDNS(t, "")
	mc := newMsgCache(100, c)
	state := testState("nope.example.", dns.TypeA)

	m := new(dns.Msg)
	m.SetRcode(state.Req, dns.RcodeNameError)
	soa, _ := dns.NewRR("example. 60 IN SOA ns.example. hostmaster.example. 1 7200 3600 1209600 60")
	m.Ns = []dns.RR{soa}

	mc.put("abc123", state, m)
	got, ok := mc.get("abc123", state)
	if !ok {
		t.Fatal("negative response was not cached")
	}
	if got.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %d, want NXDOMAIN", got.Rcode)
	}
}

// The cached message must not be handed out by reference: the copy returned to
// one client is truncated and rewritten on its way out.
func TestCacheReturnsCopies(t *testing.T) {
	c, _ := fakeNextDNS(t, "")
	mc := newMsgCache(100, c)
	state := testState("example.org.", dns.TypeA)

	mc.put("abc123", state, reply("example.org.", "example.org. 300 IN A 127.0.0.1"))

	first, _ := mc.get("abc123", state)
	first.Answer[0].Header().Ttl = 1
	first.Rcode = dns.RcodeRefused

	second, _ := mc.get("abc123", state)
	if second.Answer[0].Header().Ttl == 1 || second.Rcode == dns.RcodeRefused {
		t.Error("mutating a returned message corrupted the cached entry")
	}
}

func TestServeDNSUsesCache(t *testing.T) {
	c, cap := fakeNextDNS(t, "example.org. 300 IN A 127.0.0.1")
	n := newTestPlugin(t, c, "abc123")
	n.cache = newMsgCache(100, c)

	for i := 0; i < 3; i++ {
		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		if _, err := n.ServeDNS(context.Background(), rec, query("example.org.", dns.TypeA)); err != nil {
			t.Fatal(err)
		}
		if len(rec.Msg.Answer) != 1 {
			t.Fatalf("query %d: got %v, want one answer", i, rec.Msg)
		}
	}
	if got := cap.calls.Load(); got != 1 {
		t.Errorf("upstream was called %d times, want 1", got)
	}
}

// Two clients in the same server block routed to different profiles must not
// see each other's answers.
func TestServeDNSCacheSeparatesProfiles(t *testing.T) {
	c, cap := fakeNextDNS(t, "example.org. 300 IN A 127.0.0.1")
	n := newTestPlugin(t, c, "abc123")
	n.cache = newMsgCache(100, c)
	n.clientProfiles = []clientProfile{
		{prefix: mustPrefix("10.240.0.1/32"), profile: "other1"},
	}

	// test.ResponseWriter reports 10.240.0.1, which matches the override.
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := n.ServeDNS(context.Background(), rec, query("example.org.", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	if cap.path != "/other1" {
		t.Fatalf("path = %q, want /other1", cap.path)
	}

	// Same question, different profile: must go upstream again.
	n.clientProfiles = nil
	rec = dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := n.ServeDNS(context.Background(), rec, query("example.org.", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	if cap.path != "/abc123" {
		t.Errorf("path = %q, want /abc123", cap.path)
	}
	if got := cap.calls.Load(); got != 2 {
		t.Errorf("upstream was called %d times, want 2", got)
	}
}

// Capacity is spread across shards, so it has to round up rather than floor —
// a floor plus a per-shard minimum used to turn "cache 100" into room for 1024.
func TestStoreCapacity(t *testing.T) {
	for _, tc := range []struct{ ask, want int }{
		{10000, 10240}, // 40 per shard, rounded up from 39.06
		{8192, 8192},   // exact multiple
		{256, 256},     // exactly one per shard
		{100, 256},     // below one per shard: floored at the shard count
		{1, 256},
	} {
		if got := newStore(tc.ask).capacity(); got != tc.want {
			t.Errorf("newStore(%d) capacity = %d, want %d", tc.ask, got, tc.want)
		}
	}

	// The old floor of 4 per shard is what made small caches 10x too big.
	if got := newStore(100).capacity(); got >= 1024 {
		t.Errorf("newStore(100) capacity = %d, want well under the old 1024", got)
	}
}

func TestStoreEviction(t *testing.T) {
	s := newStore(shards * 4) // 4 entries per shard

	// All these keys land in shard 0.
	for i := 0; i < 20; i++ {
		s.Add(uint64(i)*shards, &cacheEntry{})
	}
	if got := s.Len(); got > 4 {
		t.Errorf("shard holds %d entries, want at most 4", got)
	}

	// Replacing an existing key must not change the count.
	s2 := newStore(shards * 4)
	s2.Add(1, &cacheEntry{})
	s2.Add(1, &cacheEntry{})
	if got := s2.Len(); got != 1 {
		t.Errorf("Len = %d, want 1", got)
	}
}

// The cache key is a 64-bit non-cryptographic hash, so two different questions
// can land on the same key. A hit must be verified against the question that
// was actually asked, not trusted — otherwise the wrong answer is served, and
// served convincingly, because the reply echoes back whatever was asked.
func TestCacheVerifiesHitsAgainstTheQuestion(t *testing.T) {
	c, _ := fakeNextDNS(t, "")
	mc := newMsgCache(100, c)

	victim := testState("bank.example.", dns.TypeA)
	attacker := testState("attacker.example.", dns.TypeA)

	// Force the collision the hash could produce on its own: store the
	// attacker's answer directly under the victim's key.
	mc.c.Add(cacheKey("abc123", victim), &cacheEntry{
		stored:  time.Now(),
		ttl:     time.Hour,
		msg:     reply("attacker.example.", "attacker.example. 300 IN A 6.6.6.6"),
		profile: "abc123",
		qname:   attacker.Name(),
		qtype:   attacker.QType(),
		qclass:  attacker.QClass(),
	})

	if m, ok := mc.get("abc123", victim); ok {
		t.Fatalf("colliding entry was served for a different question: %v", m.Answer)
	}
}

func TestCacheEntryMatches(t *testing.T) {
	state := testState("example.org.", dns.TypeA)
	base := &cacheEntry{
		profile: "abc123",
		qname:   state.Name(),
		qtype:   state.QType(),
		qclass:  state.QClass(),
	}
	if !base.matches("abc123", state) {
		t.Fatal("an entry should match the question it was stored for")
	}

	for name, mutate := range map[string]func(e *cacheEntry){
		"profile": func(e *cacheEntry) { e.profile = "def456" },
		"qname":   func(e *cacheEntry) { e.qname = "other.example." },
		"qtype":   func(e *cacheEntry) { e.qtype = dns.TypeAAAA },
		"qclass":  func(e *cacheEntry) { e.qclass = dns.ClassCHAOS },
		"do":      func(e *cacheEntry) { e.do = true },
		"cd":      func(e *cacheEntry) { e.cd = true },
	} {
		e := *base
		mutate(&e)
		if e.matches("abc123", state) {
			t.Errorf("entry differing in %s was accepted", name)
		}
	}
}

// A stored entry must still be served for the question it belongs to, including
// when the client varies the case (0x20 encoding).
func TestCacheMatchesAreCaseInsensitive(t *testing.T) {
	c, _ := fakeNextDNS(t, "")
	mc := newMsgCache(100, c)

	mc.put("abc123", testState("example.org.", dns.TypeA),
		reply("example.org.", "example.org. 300 IN A 127.0.0.1"))

	mixed := testState("ExAmPlE.OrG.", dns.TypeA)
	m, ok := mc.get("abc123", mixed)
	if !ok {
		t.Fatal("0x20-encoded question missed its own cache entry")
	}
	if m.Question[0].Name != "ExAmPlE.OrG." {
		t.Errorf("question = %q, want the case the client sent", m.Question[0].Name)
	}
}
