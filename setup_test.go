package nextdns

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"
)

func TestSetupProfile(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
		profile string
	}{
		{`nextdns abc123`, false, "abc123"},
		{`nextdns {
			profile abc123
		}`, false, "abc123"},
		{`nextdns abc123 {
			profile def456
		}`, false, "def456"},
		{`nextdns`, true, ""},
		{`nextdns ab`, true, ""},
		{`nextdns abc/123`, true, ""},
		{`nextdns abc123 def456`, true, ""},
		{`nextdns abc123 {
			bogus
		}`, true, ""},
		{`nextdns abc123
		 nextdns def456`, true, ""},
	}

	for i, tc := range tests {
		n, err := parseNextDNS(caddy.NewTestController("dns", tc.input))
		if tc.wantErr {
			if err == nil {
				t.Errorf("test %d: expected error for %q", i, tc.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("test %d: unexpected error: %v", i, err)
			continue
		}
		if n.profile != tc.profile {
			t.Errorf("test %d: profile = %q, want %q", i, n.profile, tc.profile)
		}
	}
}

func TestSetupOverrides(t *testing.T) {
	n, err := parseNextDNS(caddy.NewTestController("dns", `nextdns abc123 {
		view_profile guests def456
		view_profile iot -
		client_profile 10.0.0.0/8 aaa111
		client_profile 10.1.2.3 bbb222
	}`))
	if err != nil {
		t.Fatal(err)
	}

	if got := n.viewProfiles["guests"]; got != "def456" {
		t.Errorf("view guests = %q, want def456", got)
	}
	if got := n.viewProfiles["iot"]; got != passthrough {
		t.Errorf("view iot = %q, want %q", got, passthrough)
	}

	// The /32 must sort ahead of the /8 it lives inside.
	if len(n.clientProfiles) != 2 {
		t.Fatalf("got %d client profiles, want 2", len(n.clientProfiles))
	}
	if n.clientProfiles[0].profile != "bbb222" {
		t.Errorf("longest prefix should win, got %q first", n.clientProfiles[0].profile)
	}
	if !n.clientProfiles[0].prefix.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Error("host route does not contain its own address")
	}
}

func TestSetupOptions(t *testing.T) {
	n, err := parseNextDNS(caddy.NewTestController("dns", `nextdns abc123 {
		endpoint https://dns.nextdns.io https://dns2.nextdns.io
		bootstrap 45.90.28.0 2a07:a8c0::
		timeout 3s
		max_concurrent 500
		cache 2048
		cache_ttl 10s 30m
		device_id ip
		device_ip false
		device_name 192.168.1.5 Bobs-iPhone
		arp
		reload 1m
	}`))
	if err != nil {
		t.Fatal(err)
	}

	if len(n.client.endpoints) != 2 {
		t.Fatalf("got %d endpoints, want 2", len(n.client.endpoints))
	}
	for _, ep := range n.client.endpoints {
		if len(ep.bootstrap) != 2 {
			t.Errorf("endpoint %s: got %d bootstrap addresses, want 2", ep.host, len(ep.bootstrap))
		}
	}
	if n.client.timeout != 3*time.Second {
		t.Errorf("timeout = %v, want 3s", n.client.timeout)
	}
	if n.maxConcurrent != 500 {
		t.Errorf("maxConcurrent = %d, want 500", n.maxConcurrent)
	}
	if n.cache == nil || n.cache.minTTL != 10*time.Second || n.cache.maxTTL != 30*time.Minute {
		t.Errorf("cache not configured as expected: %+v", n.cache)
	}
	if n.devices.mode != idIP {
		t.Errorf("device_id mode = %v, want idIP", n.devices.mode)
	}
	if n.devices.sendIP {
		t.Error("device_ip false should disable sending the device IP")
	}
	if got := n.devices.static[netip.MustParseAddr("192.168.1.5")]; got != "Bobs-iPhone" {
		t.Errorf("static device name = %q, want Bobs-iPhone", got)
	}
	if n.devices.reload != time.Minute {
		t.Errorf("reload = %v, want 1m", n.devices.reload)
	}
}

func TestSetupDiscovery(t *testing.T) {
	n, err := parseNextDNS(caddy.NewTestController("dns", `nextdns abc123 {
		discovery internal
		discovery_ttl 30m
		discovery_retry 1m
		discovery_timeout 500ms
		discovery_max 512
	}`))
	if err != nil {
		t.Fatal(err)
	}
	d := n.devices.discovery
	if d == nil || d.resolve == nil {
		t.Fatal("discovery not enabled")
	}
	if d.ttl != 30*time.Minute || d.retry != time.Minute {
		t.Errorf("ttl = %v, retry = %v", d.ttl, d.retry)
	}
	if d.timeout != 500*time.Millisecond || d.max != 512 {
		t.Errorf("timeout = %v, max = %d", d.timeout, d.max)
	}

	// Tuning may be written before the option it tunes.
	if _, err := parseNextDNS(caddy.NewTestController("dns", `nextdns abc123 {
		discovery_ttl 30m
		discovery internal
	}`)); err != nil {
		t.Errorf("option order should not matter: %v", err)
	}

	// Explicit resolvers, with the default port filled in.
	n, err = parseNextDNS(caddy.NewTestController("dns", `nextdns abc123 {
		discovery 192.168.1.1 192.168.1.2:5353
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if n.devices.discovery == nil || n.devices.discovery.resolve == nil {
		t.Error("discovery not enabled for explicit resolvers")
	}

	// Defaults when only the mode is given.
	n, err = parseNextDNS(caddy.NewTestController("dns", corefile("discovery internal")))
	if err != nil {
		t.Fatal(err)
	}
	if n.devices.discovery.ttl != defaultDiscoveryTTL || n.devices.discovery.max != defaultDiscoveryMax {
		t.Errorf("ttl = %v, max = %d, want the defaults", n.devices.discovery.ttl, n.devices.discovery.max)
	}

	// Off unless asked for.
	n, err = parseNextDNS(caddy.NewTestController("dns", `nextdns abc123`))
	if err != nil {
		t.Fatal(err)
	}
	if n.devices.discovery != nil {
		t.Error("discovery should be off by default")
	}
}

// corefile wraps block options in a directive. Options must be on their own
// lines: caddy's RemainingArgs reads to the end of the line, so a closing brace
// sharing a line with an option is handed to the option as an argument.
func corefile(options ...string) string {
	s := "nextdns abc123 {\n"
	for _, o := range options {
		s += "\t" + o + "\n"
	}
	return s + "}"
}

func TestSetupBadOptions(t *testing.T) {
	for _, options := range [][]string{
		{`endpoint http://dns.nextdns.io`},
		{`endpoint "https://dns.nextdns.io#notanip"`},
		{`client_profile notacidr def456`},
		{`client_profile 10.0.0.0/8 x`},
		{`view_profile onlyone`},
		{`device_id bogus`},
		{`device_id mac`},
		{`device_names bogusformat /tmp/x`},
		{`device_name notanip somename`},
		{`cache_ttl 30m 10s`},
		{`cache notanumber`},
		{`timeout notaduration`},
		{`max_concurrent -1`},
		{`device_ip maybe`},
		{`discovery`},
		{`discovery_ttl 1h`}, // tuning without the feature
		{`discovery internal`, `discovery_ttl 0s`},
		{`discovery internal`, `discovery_retry notaduration`},
		{`discovery notahost:notaport`},
	} {
		input := corefile(options...)
		if _, err := parseNextDNS(caddy.NewTestController("dns", input)); err == nil {
			t.Errorf("expected an error for:\n%s", input)
		}
	}
}

func TestSetupDeviceIDMacNeedsSource(t *testing.T) {
	_, err := parseNextDNS(caddy.NewTestController("dns", `nextdns abc123 {
		device_id mac
		arp
	}`))
	if err != nil {
		t.Fatalf("device_id mac with arp should be accepted: %v", err)
	}
}

// The "#addr" suffix only survives the Corefile tokenizer when quoted —
// unquoted, caddy takes it for a comment and the bootstrap silently vanishes.
func TestSetupPerEndpointBootstrap(t *testing.T) {
	n, err := parseNextDNS(caddy.NewTestController("dns",
		corefile(`endpoint "https://dns1.nextdns.io#45.90.28.0" "https://dns2.nextdns.io#45.90.30.0"`)))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"https://dns1.nextdns.io": "45.90.28.0",
		"https://dns2.nextdns.io": "45.90.30.0",
	}
	for _, ep := range n.client.endpoints {
		if len(ep.bootstrap) != 1 || ep.bootstrap[0] != want[ep.base] {
			t.Errorf("%s: bootstrap = %v, want [%s]", ep.base, ep.bootstrap, want[ep.base])
		}
	}

	// Unquoted, the suffix is gone by the time the plugin sees it — but for a
	// NextDNS hostname the well-known table backfills, so the mistake no longer
	// leaves the endpoint depending on another resolver.
	n, err = parseNextDNS(caddy.NewTestController("dns",
		corefile(`endpoint https://dns1.nextdns.io#45.90.28.0`)))
	if err != nil {
		t.Fatal(err)
	}
	ep := n.client.endpoints[0]
	if ep.base != "https://dns1.nextdns.io" {
		t.Errorf("base = %q", ep.base)
	}
	if !slices.Equal(ep.bootstrap, wellKnownBootstrap["dns1.nextdns.io"]) {
		t.Errorf("bootstrap = %v, want the well-known addresses to have been filled in", ep.bootstrap)
	}

	// A host we do not know still ends up with nothing, which the startup
	// warning reports.
	n, err = parseNextDNS(caddy.NewTestController("dns",
		corefile(`endpoint https://doh.example.org#203.0.113.1`)))
	if err != nil {
		t.Fatal(err)
	}
	if got := n.client.endpoints[0].bootstrap; len(got) != 0 {
		t.Errorf("bootstrap = %v, want none for a host we cannot guess", got)
	}
}

func TestApplyBootstrap(t *testing.T) {
	got := applyBootstrap(
		[]string{"https://a.example#1.1.1.1", "https://b.example"},
		[]string{"2.2.2.2", "3.3.3.3"},
	)
	want := []string{"https://a.example#1.1.1.1", "https://b.example#2.2.2.2,3.3.3.3"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("endpoint %d = %q, want %q", i, got[i], want[i])
		}
	}

	// Bootstrap without an explicit endpoint still applies to the default one.
	got = applyBootstrap(nil, []string{"2.2.2.2"})
	if len(got) != 1 || got[0] != "https://dns.nextdns.io#2.2.2.2" {
		t.Errorf("got %v, want the default endpoint with bootstrap", got)
	}
}

func TestSetupDeviceModelValidation(t *testing.T) {
	for _, model := range []string{`"iPhone 12 Pro"`, `mac:3c:22:fb`, `router-lan`} {
		if _, err := parseNextDNS(caddy.NewTestController("dns", corefile("device_model "+model))); err != nil {
			t.Errorf("device_model %s rejected: %v", model, err)
		}
	}
	// Unquoted multi-word values are a config error, reported as one.
	if _, err := parseNextDNS(caddy.NewTestController("dns", corefile("device_model iPhone 12 Pro"))); err == nil {
		t.Error("unquoted multi-word device_model was accepted")
	}
	// A value an HTTP header cannot carry must be caught at config time, not at
	// request time when there is nowhere to report it.
	for _, model := range []string{"bad\nvalue", "bad\rvalue", strings.Repeat("x", 200)} {
		if _, err := parseNextDNS(caddy.NewTestController("dns", corefile(`device_model "`+model+`"`))); err == nil {
			t.Errorf("device_model %q was accepted", model)
		}
	}
}

// Options that only tune a feature must be rejected without it, so a typo does
// not hide behind a server that starts and quietly ignores the line.
func TestSetupTuningNeedsItsFeature(t *testing.T) {
	for _, options := range [][]string{
		{`cache_ttl 30s 10m`},                   // no cache
		{`reload 10s`},                          // no device_names, no arp
		{`device_name 10.0.0.1 x`, `reload 1m`}, // device_name is static, nothing to re-read
	} {
		if _, err := parseNextDNS(caddy.NewTestController("dns", corefile(options...))); err == nil {
			t.Errorf("expected an error for %v", options)
		}
	}

	// ...and accepted with it.
	for _, options := range [][]string{
		{`cache 1024`, `cache_ttl 30s 10m`},
		{`arp`, `reload 10s`},
		{`device_names hosts /tmp/x`, `reload 10s`},
	} {
		if _, err := parseNextDNS(caddy.NewTestController("dns", corefile(options...))); err != nil {
			t.Errorf("%v rejected: %v", options, err)
		}
	}
}

// The warning that pairs the cache plugin with multi-profile routing has to
// count the routes this block can actually take, not the ones configured — a
// shared snippet imported into several view blocks configures many and reaches
// one.
func TestReachableRoutes(t *testing.T) {
	shared := func() *NextDNS {
		n := New()
		n.profile = "homeprof"
		n.viewProfiles = map[string]string{"guests": "guestprof", "iot": "iotprof"}
		return n
	}

	tests := []struct {
		name  string
		build func() *NextDNS
		view  string
		want  int
	}{
		{"single profile, no view", func() *NextDNS { n := New(); n.profile = "abc123"; return n }, "", 1},

		// A view that names a profile pins the block to it; the sibling
		// view_profile entries are dead config here.
		{"shared snippet in the guests view", shared, "guests", 1},
		{"shared snippet in the iot view", shared, "iot", 1},
		{"shared snippet with no view", shared, "", 1},

		// A view with no profile of its own falls back to the general rules.
		{"unmapped view", func() *NextDNS {
			n := shared()
			n.clientProfiles = []clientProfile{{prefix: mustPrefix("10.0.0.0/8"), profile: "subnet01"}}
			return n
		}, "other", 2},

		// Client subnets are reachable in the same block, so they count.
		{"client subnets", func() *NextDNS {
			n := New()
			n.profile = "abc123"
			n.clientProfiles = []clientProfile{{prefix: mustPrefix("10.0.0.0/8"), profile: "def456"}}
			return n
		}, "", 2},

		// Passthrough is a route: those clients get an unfiltered answer, which
		// is exactly the difference the cache would erase.
		{"passthrough counts", func() *NextDNS {
			n := New()
			n.profile = "abc123"
			n.clientProfiles = []clientProfile{{prefix: mustPrefix("10.0.99.0/24"), profile: passthrough}}
			return n
		}, "", 2},

		// The same profile named twice is one route.
		{"duplicate profiles collapse", func() *NextDNS {
			n := New()
			n.profile = "abc123"
			n.clientProfiles = []clientProfile{{prefix: mustPrefix("10.0.0.0/8"), profile: "abc123"}}
			return n
		}, "", 1},

		// A view routed to passthrough is still one route.
		{"view passthrough", func() *NextDNS {
			n := New()
			n.profile = "abc123"
			n.viewProfiles = map[string]string{"internal": passthrough}
			return n
		}, "internal", 1},
	}

	for _, tc := range tests {
		got := tc.build().reachableRoutes(tc.view)
		if len(got) != tc.want {
			t.Errorf("%s: reachableRoutes(%q) = %v (%d), want %d", tc.name, tc.view, got, len(got), tc.want)
		}
	}
}

func TestSetupDiscoveryWait(t *testing.T) {
	n, err := parseNextDNS(caddy.NewTestController("dns", corefile(
		"discovery internal", "discovery_wait 500ms")))
	if err != nil {
		t.Fatal(err)
	}
	if n.devices.discovery.wait != 500*time.Millisecond {
		t.Errorf("wait = %v, want 500ms", n.devices.discovery.wait)
	}

	// Zero is the documented way to turn the hold off.
	n, err = parseNextDNS(caddy.NewTestController("dns", corefile(
		"discovery internal", "discovery_wait 0")))
	if err != nil {
		t.Fatal(err)
	}
	if n.devices.discovery.wait != 0 {
		t.Errorf("wait = %v, want it disabled", n.devices.discovery.wait)
	}

	// On by default.
	n, _ = parseNextDNS(caddy.NewTestController("dns", corefile("discovery internal")))
	if n.devices.discovery.wait != defaultDiscoveryWait {
		t.Errorf("wait = %v, want the default", n.devices.discovery.wait)
	}

	for _, options := range [][]string{
		{"discovery internal", "discovery_wait -1s"},
		{"discovery internal", "discovery_wait notaduration"},
		{"discovery_wait 100ms"}, // no discovery
	} {
		if _, err := parseNextDNS(caddy.NewTestController("dns", corefile(options...))); err == nil {
			t.Errorf("expected an error for %v", options)
		}
	}
}
