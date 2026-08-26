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
	// around through the chain. Nothing ahead of us answered it, so nothing
	// will: answer it here rather than spending a NextDNS query on the reverse
	// name of a LAN address, and do not enrich it, which is what would make the
	// discovery recurse.
	if isDiscovery(ctx) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	profile := n.profileFor(ctx, &state)
	if profile == "" || profile == passthrough {
		return plugin.NextOrFailure(pluginName, n.Next, ctx, w, r)
	}

	if n.maxConcurrent > 0 {
		count := atomic.AddInt64(&n.concurrent, 1)
		defer atomic.AddInt64(&n.concurrent, -1)
		if count > n.maxConcurrent {
			maxConcurrentRejectCount.WithLabelValues(server).Inc()
			return dns.RcodeRefused, ErrMaxConcurrent
		}
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
		if v := viewName(ctx); v != "" {
			if p, ok := n.viewProfiles[v]; ok {
				return p
			}
		}
	}

	if len(n.clientProfiles) > 0 {
		if ip, err := netip.ParseAddr(state.IP()); err == nil {
			ip = ip.Unmap()
			for _, cp := range n.clientProfiles {
				if cp.prefix.Contains(ip) {
					return cp.profile
				}
			}
		}
	}

	return n.profile
}

// viewName returns the name of the view handling this query, if any. The view
// name is put on the context by the DNS server itself, so this works whether or
// not the metadata plugin is enabled; the metadata label is the fallback for
// anything else that wants to name a view.
func viewName(ctx context.Context) string {
	if v := metrics.WithView(ctx); v != "" {
		return v
	}
	if f := metadata.ValueFunc(ctx, "view/name"); f != nil {
		return f()
	}
	return ""
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

// profiles returns every profile ID this instance can route to.
func (n *NextDNS) profiles() []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" || p == passthrough || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	add(n.profile)
	for _, p := range n.viewProfiles {
		add(p)
	}
	for _, cp := range n.clientProfiles {
		add(cp.profile)
	}
	return out
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

// shutdownGrace bounds how long OnShutdown waits for detached device lookups.
const shutdownGrace = 5 * time.Second
