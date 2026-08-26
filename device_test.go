package nextdns

import (
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShortID(t *testing.T) {
	ip := net.ParseIP("192.168.1.5").To4()

	id := shortID("abc123", ip)
	if len(id) != 5 {
		t.Fatalf("shortID = %q, want 5 characters", id)
	}
	if id != strings.ToUpper(id) {
		t.Errorf("shortID = %q, want upper case", id)
	}

	// Stable for the same inputs.
	if again := shortID("abc123", ip); again != id {
		t.Errorf("shortID is not stable: %q then %q", id, again)
	}

	// Mixing the profile in is what stops a device being correlated across
	// profiles, so the same device must hash differently under another profile.
	if other := shortID("def456", ip); other == id {
		t.Errorf("shortID collides across profiles: %q", id)
	}

	if shortID("abc123", nil) != "" {
		t.Error("shortID with no key should be empty")
	}
}

func TestNormalizeName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"laptop", "laptop"},
		{"laptop.lan", "laptop"},
		{"Bob's iPhone", "Bob-s-iPhone"},
		{"  spaced  out  ", "spaced-out"},
		{"weird\r\nheader: injection", "weird-header-injection"},
		{"...", ""},
		{"", ""},
		{"*", ""},
		{strings.Repeat("a", 100), strings.Repeat("a", maxNameLen)},
	}
	for _, tc := range tests {
		if got := normalizeName(tc.in); got != tc.want {
			t.Errorf("normalizeName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeNameIsHeaderSafe(t *testing.T) {
	// Whatever a hostile DHCP client puts in its hostname must survive being
	// put into an HTTP header without smuggling anything.
	h := http.Header{}
	ci := ClientInfo{Name: normalizeName("evil\r\nX-Device-Id: PWNED")}
	ci.setHeaders(h)
	if got := h.Get("X-Device-Name"); strings.ContainsAny(got, "\r\n:") {
		t.Errorf("X-Device-Name = %q, want no control characters", got)
	}
	if h.Get("X-Device-Id") != "" {
		t.Error("header injection succeeded")
	}
}

func TestDeviceLookup(t *testing.T) {
	d := newDeviceDB()
	d.static[netip.MustParseAddr("10.0.0.1")] = "Static Name"
	d.learned = map[netip.Addr]deviceInfo{
		netip.MustParseAddr("10.0.0.1"): {name: "lease-name", mac: mustMAC("3c:22:fb:11:22:33")},
		netip.MustParseAddr("10.0.0.2"): {name: "printer.lan"},
	}

	ci := lookupIP(d, "10.0.0.1", "abc123")
	if ci.Name != "Static-Name" {
		t.Errorf("Name = %q, want the Corefile name to win", ci.Name)
	}
	if ci.IP != "10.0.0.1" {
		t.Errorf("IP = %q, want 10.0.0.1", ci.IP)
	}
	if ci.Model != "mac:3c:22:fb" {
		t.Errorf("Model = %q, want only the OUI", ci.Model)
	}
	// In auto mode a known MAC is preferred over the IP, so the identity
	// survives a DHCP lease change.
	if ci.ID != shortID("abc123", mustMAC("3c:22:fb:11:22:33")) {
		t.Errorf("ID = %q, want the MAC derived ID", ci.ID)
	}

	ci = lookupIP(d, "10.0.0.2", "abc123")
	if ci.Name != "printer" {
		t.Errorf("Name = %q, want printer", ci.Name)
	}
	if ci.ID != shortID("abc123", netip.MustParseAddr("10.0.0.2").AsSlice()) {
		t.Errorf("ID = %q, want the IP derived ID", ci.ID)
	}

	// Unknown client: still identified by IP, just unnamed.
	ci = lookupIP(d, "10.0.0.99", "abc123")
	if ci.Name != "" || ci.ID == "" {
		t.Errorf("unknown client: got name %q id %q", ci.Name, ci.ID)
	}

	if got := lookupIP(d, "not-an-ip", "abc123"); got != (ClientInfo{}) {
		t.Errorf("unparsable client address should yield nothing, got %+v", got)
	}
}

func TestDeviceIDModes(t *testing.T) {
	addr := netip.MustParseAddr("10.0.0.1")
	mac := mustMAC("3c:22:fb:11:22:33")

	d := newDeviceDB()

	d.mode = idNone
	if got := d.deviceID("abc123", addr, mac); got != "" {
		t.Errorf("idNone = %q, want empty", got)
	}

	d.mode = idIP
	if got := d.deviceID("abc123", addr, mac); got != shortID("abc123", addr.AsSlice()) {
		t.Errorf("idIP did not use the IP")
	}

	d.mode = idMAC
	if got := d.deviceID("abc123", addr, nil); got != "" {
		t.Errorf("idMAC without a MAC = %q, want empty", got)
	}
}

func TestSendDeviceIPDisabled(t *testing.T) {
	d := newDeviceDB()
	d.sendIP = false
	if ci := lookupIP(d, "10.0.0.1", "abc123"); ci.IP != "" {
		t.Errorf("IP = %q, want empty when device_ip is off", ci.IP)
	}
}

func TestSetHeaders(t *testing.T) {
	h := http.Header{}
	ClientInfo{}.setHeaders(h)
	if len(h) != 0 {
		t.Errorf("empty ClientInfo set %d headers", len(h))
	}

	ClientInfo{ID: "ABCDE", IP: "10.0.0.1", Name: "laptop", Model: "mac:3c:22:fb"}.setHeaders(h)
	for k, want := range map[string]string{
		"X-Device-Id":    "ABCDE",
		"X-Device-Ip":    "10.0.0.1",
		"X-Device-Name":  "laptop",
		"X-Device-Model": "mac:3c:22:fb",
	} {
		if got := h.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func mustMAC(s string) net.HardwareAddr {
	mac, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return mac
}

// The refresh ticker must actually stop; goleak in TestMain turns a failure
// here into a package-wide failure.
func TestDeviceDBStartStop(t *testing.T) {
	d := newDeviceDB()
	d.useARP = true
	d.arpPath = filepath.Join(t.TempDir(), "no-such-arp")
	d.reload = 5 * time.Millisecond

	d.start()
	time.Sleep(10 * time.Millisecond)
	d.stop()
	d.stop() // idempotent: OnShutdown can run without OnStartup
}
