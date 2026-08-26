package nextdns

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

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

	cacheSize = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "cache_entries",
		Help:      "Entries held in the profile-aware cache, including expired ones not yet evicted.",
	})

	discoveryLookups = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "discovery_lookups_total",
		Help:      "Counter of reverse DNS device lookups by result.",
	}, []string{"result"})

	discoveryEntries = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "discovery_entries",
		Help:      "Number of client addresses in the reverse DNS discovery table.",
	})

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

	devicesKnown = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "devices_known",
		Help:      "Number of devices discovered from the configured device sources.",
	})
)
