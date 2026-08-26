// Package nextdns implements a CoreDNS plugin that resolves queries through the
// NextDNS DNS-over-HTTPS endpoint.
//
// Every query is enriched with the identity of the client that asked it — the
// device name (when it can be discovered), a stable per-profile device ID, the
// device model and the device's LAN IP — so that queries show up attributed to
// the right device in the NextDNS logs and analytics instead of collapsing into
// a single "unnamed device" for the whole resolver.
//
// The profile a query is sent to can be overridden per view, per client subnet,
// or by any plugin that publishes the "nextdns/profile" metadata label.
package nextdns

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/rcode"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

const pluginName = "nextdns"

// version is reported in the User-Agent sent to NextDNS.
const version = "0.1.0"

// passthrough is the profile value that means "do not resolve this through
// NextDNS, hand the query to the next plugin instead".
const passthrough = "-"

// profileLabel is the metadata label another plugin can set to override the
// profile used for a query. It wins over every other selection mechanism.
const profileLabel = "nextdns/profile"

var log = clog.NewWithPlugin(pluginName)

// ErrMaxConcurrent is returned when max_concurrent in-flight queries is exceeded.
var ErrMaxConcurrent = errors.New("maximum concurrent queries exceeded")

// clientProfile maps a client subnet to a profile.
type clientProfile struct {
	prefix  netip.Prefix
	profile string
}

// NextDNS is the plugin handler.
type NextDNS struct {
	concurrent int64 // atomic, keep first for alignment on 32 bit

	// profile is the default NextDNS profile ID, used when no override matches.
	profile string
	// viewProfiles maps a CoreDNS view name to a profile ID.
	viewProfiles map[string]string
	// clientProfiles maps client subnets to profile IDs, longest prefix first.
	clientProfiles []clientProfile

	client  *dohClient
	devices *deviceDB
	cache   *msgCache

	// labels identify this instance in the gauges it writes; see metricLabels.
	labels metricLabels

	// badProfile bounds the warning for an invalid profile from metadata: the
	// value is set per query, so logging every occurrence would let a
	// misbehaving plugin flood the log. Per instance rather than per process,
	// so one server block cannot silence the diagnostic for another, and a
	// reload re-arms it.
	badProfile sync.Once

	maxConcurrent int64

	Next plugin.Handler
}

// New returns a NextDNS with the defaults filled in.
func New() *NextDNS {
	return &NextDNS{
		viewProfiles: map[string]string{},
		devices:      newDeviceDB(),
	}
}

// Name implements plugin.Handler.
func (n *NextDNS) Name() string { return pluginName }

// ServeDNS implements plugin.Handler.
func (n *NextDNS) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	server := metrics.WithServer(ctx)

	// A reverse lookup this plugin issued for device discovery has come back
	// around through the chain. Nothing ahead of us answered it, so offer it to
	// whatever is behind us — a reverse zone is just as legitimately served by a
	// plugin below this one — but never send it to NextDNS, and never enrich it,
	// which is what would make the discovery recurse.
	if isDiscovery(ctx) {
		rc, err := plugin.NextOrFailure(pluginName, n.Next, ctx, w, r)
		if err == nil || plugin.ClientWrite(rc) {
			// It answered, or it wrote a response of its own; either way the
			// query is dealt with and there is nothing here to add.
			return rc, nil
		}
		// Nothing could answer. Say so here rather than letting the error travel
		// up, which would have the errors plugin log every retry interval for as
		// long as the device keeps querying.
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	profile := n.profileFor(ctx, &state)
	if profile == "" || profile == passthrough {
		return plugin.NextOrFailure(pluginName, n.Next, ctx, w, r)
	}

	ci := n.devices.lookup(ctx, &state, profile)
	n.publish(ctx, profile, ci)

	if n.cache != nil {
		if m, ok := n.cache.get(profile, &state); ok {
			cacheHits.WithLabelValues(server).Inc()
			return n.reply(&state, m, server, profile)
		}
		cacheMisses.WithLabelValues(server).Inc()
	}

	// Only the upstream exchange is worth limiting, so the slot is taken after
	// the cache has had its say. Taking it earlier let a burst of cache hits —
	// which never touch the upstream — refuse queries servable from memory.
	if n.maxConcurrent > 0 {
		count := atomic.AddInt64(&n.concurrent, 1)
		defer atomic.AddInt64(&n.concurrent, -1)
		if count > n.maxConcurrent {
			maxConcurrentRejectCount.WithLabelValues(server).Inc()
			return dns.RcodeRefused, ErrMaxConcurrent
		}
	}

	start := time.Now()
	m, err := n.client.exchange(ctx, profile, r, ci)
	requestDuration.WithLabelValues(server, profile).Observe(time.Since(start).Seconds())
	if err != nil {
		return dns.RcodeServerFailure, plugin.Error(pluginName, err)
	}

	// A reply that does not answer the question we asked is not usable, and must
	// never reach the cache. Count it: an upstream or an on-path device answering
	// the wrong question is otherwise invisible in both logs and metrics.
	if !state.Match(m) {
		mismatchCount.WithLabelValues(server).Inc()
		formerr := new(dns.Msg)
		formerr.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(formerr)
		return dns.RcodeSuccess, nil
	}

	if n.cache != nil {
		n.cache.put(profile, &state, m)
	}

	return n.reply(&state, m, server, profile)
}

// reply writes m out as the answer to state.
//
// It does not size or truncate: the server hands every plugin a writer already
// wrapped in request.NewScrubWriter, which does both on the way out. Restoring
// the ID is still ours to do — the query goes upstream with ID 0, and nothing
// downstream puts the client's back.
func (n *NextDNS) reply(state *request.Request, m *dns.Msg, server, profile string) (int, error) {
	responseCount.WithLabelValues(server, profile, rcode.ToString(m.Rcode)).Inc()

	m.Id = state.Req.Id
	state.W.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

// profileFor resolves which NextDNS profile a query belongs to. The order is:
// explicit metadata override, then view, then client subnet, then the default.
func (n *NextDNS) profileFor(ctx context.Context, state *request.Request) string {
	if f := metadata.ValueFunc(ctx, profileLabel); f != nil {
		if p := f(); p != "" {
			// This value arrives at request time from another plugin, so unlike
			// the Corefile ones it has never been checked. It is interpolated
			// into a URL path and used as a Prometheus label, so an unchecked
			// value is both a malformed request and an unbounded label
			// cardinality. Fall back to the configured routing instead.
			if validRoute(p) == nil {
				return p
			}
			invalidProfileCount.Inc()
			n.badProfile.Do(func() {
				log.Warningf("Ignoring invalid %s metadata value %q; expected 4 to 64 alphanumeric characters or %q. "+
					"Further occurrences are counted in %s_%s_invalid_profiles_total, not logged.",
					profileLabel, p, passthrough, plugin.Namespace, pluginName)
			})
		}
	}

	if len(n.viewProfiles) > 0 {
		if v := metrics.WithView(ctx); v != "" {
			if p, ok := n.viewProfiles[v]; ok {
				return p
			}
		}
	}

	if len(n.clientProfiles) > 0 {
		if ip, ok := clientAddr(state.IP()); ok {
			for _, cp := range n.clientProfiles {
				if cp.prefix.Contains(ip) {
					return cp.profile
				}
			}
		}
	}

	return n.profile
}

// publish exposes what this plugin decided about the query to other plugins
// (the log plugin in particular) as metadata. It is a no-op when the metadata
// plugin is not enabled for this server block.
func (n *NextDNS) publish(ctx context.Context, profile string, ci ClientInfo) {
	if metadata.ValueFuncs(ctx) == nil {
		return
	}
	metadata.SetValueFunc(ctx, "nextdns/profile-used", func() string { return profile })

	// Publish only what was actually determined. An empty value would render as
	// a blank in a log line, where the convention — and what is far easier to
	// parse — is a "-" for a label that is not there.
	for label, v := range map[string]string{
		"nextdns/device-id":    ci.ID,
		"nextdns/device-name":  ci.Name,
		"nextdns/device-model": ci.Model,
		"nextdns/device-ip":    ci.IP,
	} {
		if v != "" {
			metadata.SetValueFunc(ctx, label, func() string { return v })
		}
	}
}

// reachableRoutes returns the distinct ways a query can be answered in this
// server block. A route is a profile ID, or passthrough for the queries handed
// to the next plugin — passthrough counts, because an unfiltered answer differs
// from a NextDNS-filtered one exactly as much as two profiles differ from each
// other.
//
// view is the name of the view bound to this block, empty if it has none.
// CoreDNS binds at most one view per block and sets it on every query the block
// handles, and the view a query is matched against comes from nowhere else — so
// when that view names a profile it is the only profile reachable here, and the
// other view_profile entries are dead config. Excluding them rather than
// counting them is what makes a shared snippet imported into several view
// blocks come out single-routed, and it is exact rather than a guess.
func (n *NextDNS) reachableRoutes(view string) []string {
	if view != "" {
		if p, ok := n.viewProfiles[view]; ok {
			return []string{p}
		}
	}

	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}

	add(n.profile)
	for _, cp := range n.clientProfiles {
		add(cp.profile)
	}
	return out
}

// setMetricLabels gives this instance, and everything under it that writes a
// gauge, the labels identifying it. Called before OnStartup so the first
// refresh already writes under them.
func (n *NextDNS) setMetricLabels(l metricLabels) {
	n.labels = l
	n.devices.labels = l
	if n.devices.discovery != nil {
		n.devices.discovery.labels = l
	}
	if n.cache != nil {
		n.cache.labels = l
	}
}

// deleteGauges removes this instance's gauge series. A reload replaces the
// instance, and a block that goes away entirely should not leave a frozen
// value behind.
func (n *NextDNS) deleteGauges() {
	n.labels.delete(devicesKnown)
	n.labels.delete(discoveryEntries)
	n.labels.delete(cacheSize)
}

// republishGauges rewrites this instance's current values, for when a reload
// was abandoned after deleteGauges already ran and this instance keeps serving.
func (n *NextDNS) republishGauges() {
	n.devices.mu.RLock()
	known := len(n.devices.learned)
	n.devices.mu.RUnlock()
	n.labels.set(devicesKnown, float64(known))

	if d := n.devices.discovery; d != nil {
		d.mu.Lock()
		entries := len(d.entries)
		d.mu.Unlock()
		n.labels.set(discoveryEntries, float64(entries))
	}
	if n.cache != nil {
		n.labels.set(cacheSize, float64(n.cache.c.Len()))
	}
}

// OnStartup starts the background device discovery refresh.
func (n *NextDNS) OnStartup() error {
	n.devices.start()
	return nil
}

// OnShutdown stops background work and releases upstream connections.
func (n *NextDNS) OnShutdown() error {
	n.devices.stop()
	n.client.close()
	return nil
}
