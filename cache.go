package nextdns

import (
	"encoding/binary"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	"github.com/coredns/coredns/plugin/pkg/response"
	"github.com/coredns/coredns/request"

	"github.com/cespare/xxhash/v2"
	"github.com/miekg/dns"
)

// msgCache is a profile-aware response cache.
//
// It exists because the stock cache plugin keys on the question alone. That is
// correct when a server block resolves to a single NextDNS profile — the usual
// case, including one server block per view — but wrong the moment a single
// block routes different clients to different profiles: two profiles can have
// different blocklists, so the same question legitimately has two different
// answers. Keying on the profile as well keeps them apart.
//
// Entries are also invalidated when NextDNS reports that a profile's
// configuration changed, so blocklist edits take effect without waiting out
// the TTLs.
type msgCache struct {
	c      *store
	client *dohClient
	labels metricLabels

	minTTL time.Duration
	maxTTL time.Duration
}

type cacheEntry struct {
	stored time.Time
	ttl    time.Duration
	msg    *dns.Msg

	// The identity of the entry, kept so that a hit can be verified rather than
	// trusted. cacheKey is a 64-bit non-cryptographic hash, so two different
	// questions can land on the same key; without this the wrong answer would be
	// served, and served convincingly, because the reply echoes back whatever
	// question was asked. CoreDNS's own cache does the same check.
	profile string
	qname   string // lower case, as request.Name returns it
	qtype   uint16
	qclass  uint16
	do      bool
	cd      bool
}

// matches reports whether this entry actually answers the question asked, as
// opposed to merely hashing to the same key.
func (e *cacheEntry) matches(profile string, state *request.Request) bool {
	return e.profile == profile &&
		e.qname == state.Name() &&
		e.qtype == state.QType() &&
		e.qclass == state.QClass() &&
		e.do == state.Do() &&
		e.cd == state.Req.CheckingDisabled
}

const (
	defaultCacheCapacity = 10000
	defaultCacheMinTTL   = 5 * time.Second
	defaultCacheMaxTTL   = 1 * time.Hour
)

func newMsgCache(capacity int, client *dohClient) *msgCache {
	if capacity <= 0 {
		capacity = defaultCacheCapacity
	}
	return &msgCache{
		c:      newStore(capacity),
		client: client,
		minTTL: defaultCacheMinTTL,
		maxTTL: defaultCacheMaxTTL,
	}
}

// cacheKey hashes the question together with the profile and the flags that
// change what a valid answer looks like.
func cacheKey(profile string, state *request.Request) uint64 {
	qname := state.Name() // already lower cased and fully qualified
	buf := make([]byte, 0, len(profile)+len(qname)+8)
	buf = append(buf, profile...)
	buf = append(buf, 0)
	buf = append(buf, qname...)
	buf = binary.BigEndian.AppendUint16(buf, state.QType())
	buf = binary.BigEndian.AppendUint16(buf, state.QClass())
	var flags byte
	if state.Do() {
		flags |= 1
	}
	if state.Req.CheckingDisabled {
		flags |= 2
	}
	return xxhash.Sum64(append(buf, flags))
}

// get returns a copy of the cached reply for this question, with TTLs counted
// down, or false when there is nothing usable cached.
func (mc *msgCache) get(profile string, state *request.Request) (*dns.Msg, bool) {
	// RFC 1035 section 7.4: results of an inverse query are not cached.
	if state.QType() == dns.TypePTR {
		return nil, false
	}

	e, ok := mc.c.Get(cacheKey(profile, state))
	if !ok {
		return nil, false
	}
	if !e.matches(profile, state) {
		cacheCollisions.Inc()
		return nil, false
	}

	now := time.Now()
	if e.stored.Before(mc.client.confChangedAt(profile)) {
		return nil, false
	}
	remaining := e.ttl - now.Sub(e.stored)
	if remaining <= 0 {
		return nil, false
	}

	// Round up: a sub-second remainder is still a live entry, and handing out a
	// TTL of 0 stops downstream resolvers caching it at all.
	ttl := uint32((remaining + time.Second - 1) / time.Second)

	m := e.msg.Copy()
	setTTL(m, ttl)
	// Echo the question exactly as it was asked. The key is case insensitive but
	// the reply is not: a client using 0x20 encoding checks the case it sent.
	if len(state.Req.Question) > 0 {
		m.Question = []dns.Question{state.Req.Question[0]}
	}
	return m, true
}

// put stores a reply. It stores a copy, because the message handed back to the
// client is truncated and rewritten on the way out.
func (mc *msgCache) put(profile string, state *request.Request, m *dns.Msg) {
	if state.QType() == dns.TypePTR || m.Truncated {
		return
	}
	switch m.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		return
	}

	now := time.Now()
	mt, _ := response.Typify(m, now)
	ttl := dnsutil.MinimalTTL(m, mt)
	if ttl < mc.minTTL {
		ttl = mc.minTTL
	}
	if ttl > mc.maxTTL {
		ttl = mc.maxTTL
	}

	mc.c.Add(cacheKey(profile, state), &cacheEntry{
		stored:  now,
		ttl:     ttl,
		msg:     m.Copy(),
		profile: profile,
		qname:   state.Name(),
		qtype:   state.QType(),
		qclass:  state.QClass(),
		do:      state.Do(),
		cd:      state.Req.CheckingDisabled,
	})
	mc.labels.set(cacheSize, float64(mc.c.Len()))
}

// setTTL rewrites every record TTL to ttl, leaving OPT alone: its TTL field
// carries the extended rcode and flags, not a lifetime.
func setTTL(m *dns.Msg, ttl uint32) {
	for _, rrs := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range rrs {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			rr.Header().Ttl = ttl
		}
	}
}
