package nextdns

import (
	"net/netip"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Two blocks in one process each write these gauges from their own state. With
// a single unlabelled series they overwrote each other, so the value reported
// was whichever instance happened to write last.
func TestInstanceGaugesDoNotOverwriteEachOther(t *testing.T) {
	a := metricLabels{servers: []string{"dns://:53"}, zone: "example.org.", view: ""}
	b := metricLabels{servers: []string{"dns://:53"}, zone: "example.net.", view: ""}
	t.Cleanup(func() {
		a.delete(devicesKnown)
		b.delete(devicesKnown)
	})

	da, db := newDeviceDB(), newDeviceDB()
	da.labels, db.labels = a, b
	da.static[mustAddr("10.0.0.1")] = "one"

	da.labels.set(devicesKnown, 7)
	db.labels.set(devicesKnown, 3)

	if got := testutil.ToFloat64(devicesKnown.WithLabelValues("dns://:53", "example.org.", "")); got != 7 {
		t.Errorf("block A reports %v, want 7", got)
	}
	if got := testutil.ToFloat64(devicesKnown.WithLabelValues("dns://:53", "example.net.", "")); got != 3 {
		t.Errorf("block B reports %v, want 3 — the blocks are sharing a series", got)
	}
}

// A reload replaces the instance. The outgoing one drops its series before the
// new one exists, and puts them back if the reload is abandoned.
func TestGaugeLifecycleAcrossReload(t *testing.T) {
	labels := metricLabels{servers: []string{"dns://:1053"}, zone: ".", view: "guests"}
	other := metricLabels{servers: []string{"dns://:1053"}, zone: ".", view: "iot"}
	t.Cleanup(func() {
		labels.delete(devicesKnown)
		other.delete(devicesKnown)
	})

	n := New()
	n.setMetricLabels(labels)
	n.devices.learned = map[netip.Addr]deviceInfo{
		mustAddr("10.0.0.1"): {name: "one"},
		mustAddr("10.0.0.2"): {name: "two"},
	}

	// An unrelated block's series must survive everything below.
	other.set(devicesKnown, 9)

	n.republishGauges()
	if got := testutil.ToFloat64(devicesKnown.WithLabelValues("dns://:1053", ".", "guests")); got != 2 {
		t.Fatalf("gauge = %v, want 2", got)
	}

	n.deleteGauges()
	if n := testutil.CollectAndCount(devicesKnown); n != 1 {
		t.Errorf("%d series after the delete, want only the unrelated block's", n)
	}
	if got := testutil.ToFloat64(devicesKnown.WithLabelValues("dns://:1053", ".", "iot")); got != 9 {
		t.Errorf("unrelated block's series = %v, want 9 — it was disturbed", got)
	}

	// Reload abandoned: the instance keeps serving, so its series comes back.
	n.republishGauges()
	if got := testutil.ToFloat64(devicesKnown.WithLabelValues("dns://:1053", ".", "guests")); got != 2 {
		t.Errorf("gauge = %v after a failed reload, want it restored to 2", got)
	}
}

// setMetricLabels has to reach the discoverer and the cache too, or their
// gauges stay unlabelled and silently write nothing.
func TestSetMetricLabelsReachesEverything(t *testing.T) {
	c, _ := fakeNextDNS(t, "")
	n := New()
	n.devices.discovery = newDiscoverer()
	n.cache = newMsgCache(100, c)

	l := metricLabels{servers: []string{"dns://:53"}, zone: ".", view: "v"}
	n.setMetricLabels(l)

	if n.devices.labels.zone != "." {
		t.Error("deviceDB did not get the labels")
	}
	if n.devices.discovery.labels.zone != "." {
		t.Error("discoverer did not get the labels")
	}
	if n.cache.labels.zone != "." {
		t.Error("msgCache did not get the labels")
	}
}
