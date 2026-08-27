package nextdns

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// instanceLabels identify the plugin instance a gauge value came from. The
// counters take their server label from the request context, but these gauges
// are written off the request path — from a refresh ticker, from a detached
// lookup — where there is no context to take it from.
var instanceLabels = []string{"server", "zone", "view"}

var (
	requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "request_duration_seconds",
		Buckets:   plugin.TimeBuckets,
		Help:      "Histogram of the time each DoH request took.",
	}, []string{"server", "profile"})

	responseCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "responses_total",
		Help:      "Counter of responses returned per profile and rcode.",
	}, []string{"server", "profile", "rcode"})

	errorCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "errors_total",
		Help:      "Counter of failed DoH requests per endpoint.",
	}, []string{"endpoint"})

	bootstrapFailCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "bootstrap_failures_total",
		Help:      "Counter of failed dials per endpoint bootstrap address.",
	}, []string{"endpoint", "address"})

	maxConcurrentRejectCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "max_concurrent_rejects_total",
		Help:      "Counter of queries rejected because max_concurrent was reached.",
	}, []string{"server"})

	cacheHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "cache_hits_total",
		Help:      "Counter of profile-aware cache hits.",
	}, []string{"server"})

	cacheMisses = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "cache_misses_total",
		Help:      "Counter of profile-aware cache misses.",
	}, []string{"server"})

	cacheSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "cache_entries",
		Help:      "Entries held in the profile-aware cache, including expired ones not yet evicted.",
	}, instanceLabels)

	discoveryLookups = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "discovery_lookups_total",
		Help:      "Counter of reverse DNS device lookups by result.",
	}, []string{"result"})

	discoveryWaits = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "discovery_waits_total",
		Help:      "Counter of queries held for a cold device lookup, by how the hold ended.",
	}, []string{"result"})

	discoveryEntries = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "discovery_entries",
		Help:      "Number of client addresses in the reverse DNS discovery table.",
	}, instanceLabels)

	mismatchCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "mismatches_total",
		Help:      "Counter of upstream replies that did not answer the question asked.",
	}, []string{"server"})

	cacheCollisions = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "cache_collisions_total",
		Help:      "Counter of cache lookups that hit an entry for a different question and were discarded.",
	})

	invalidProfileCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "invalid_profiles_total",
		Help:      "Counter of queries whose nextdns/profile metadata value was rejected as malformed.",
	})

	devicesKnown = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "devices_known",
		Help:      "Number of devices discovered from the configured device sources.",
	}, instanceLabels)
)

// metricLabels is one instance's values for instanceLabels, captured at startup.
//
// Without them the gauges would be a single unlabelled series per process, so
// every server block — and every instance still alive across a reload — would
// write over the others' values.
type metricLabels struct {
	servers []string // one per listen address; each carries the same value
	zone    string
	view    string
}

// set writes v to g under these labels. It is a no-op before startup has
// captured them, which is what happens in unit tests that never wire an
// instance up to a server.
func (l metricLabels) set(g *prometheus.GaugeVec, v float64) {
	for _, s := range l.servers {
		g.WithLabelValues(s, l.zone, l.view).Set(v)
	}
}

// delete removes this instance's series, so a block that goes away in a reload
// does not leave a frozen value behind.
func (l metricLabels) delete(g *prometheus.GaugeVec) {
	for _, s := range l.servers {
		g.DeleteLabelValues(s, l.zone, l.view)
	}
}
