package nextdns

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDnsmasqLeases(t *testing.T) {
	in := `1699999999 3c:22:fb:11:22:33 192.168.1.5 Bobs-iPhone 01:3c:22:fb:11:22:33
1699999999 aa:bb:cc:dd:ee:ff 192.168.1.6 * *
garbage
1699999999 aa:bb:cc:dd:ee:00 not-an-ip host *
`
	got, err := parseDnsmasqLeases(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d leases, want 2", len(got))
	}

	e := got[netip.MustParseAddr("192.168.1.5")]
	if e.name != "Bobs-iPhone" || e.mac.String() != "3c:22:fb:11:22:33" {
		t.Errorf("got %+v", e)
	}

	// "*" means dnsmasq has no hostname for the lease, not a device called "*".
	e = got[netip.MustParseAddr("192.168.1.6")]
	if e.name != "" || e.mac == nil {
		t.Errorf("got %+v, want no name but a MAC", e)
	}
}

func TestParseHosts(t *testing.T) {
	in := `# comment
192.168.1.5   laptop laptop.lan
10.0.0.1 router # trailing comment
fe80::1 v6host
not-an-ip nope
badline
`
	got, err := parseHosts(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(got), got)
	}
	if got[netip.MustParseAddr("192.168.1.5")].name != "laptop" {
		t.Error("first name should win over aliases")
	}
	if got[netip.MustParseAddr("10.0.0.1")].name != "router" {
		t.Error("trailing comment not stripped")
	}
	if got[netip.MustParseAddr("fe80::1")].name != "v6host" {
		t.Error("IPv6 entry missing")
	}
}

func TestParseDHCPDLeases(t *testing.T) {
	in := `# ISC dhcpd lease file
lease 192.168.1.5 {
  starts 4 2024/01/01 00:00:00;
  hardware ethernet 3c:22:fb:11:22:33;
  client-hostname "Bobs-iPhone";
}
lease 192.168.1.6 {
  hardware ethernet aa:bb:cc:dd:ee:ff;
}
lease 192.168.1.5 {
  hardware ethernet 3c:22:fb:11:22:33;
  client-hostname "Bobs-New-iPhone";
}
lease 192.168.1.7 {
}
`
	got, err := parseDHCPDLeases(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	// dhcpd appends, so the last block for an address is the current one.
	if n := got[netip.MustParseAddr("192.168.1.5")].name; n != "Bobs-New-iPhone" {
		t.Errorf("name = %q, want the latest lease", n)
	}
	if got[netip.MustParseAddr("192.168.1.6")].mac == nil {
		t.Error("lease with only a MAC should be kept")
	}
	if _, ok := got[netip.MustParseAddr("192.168.1.7")]; ok {
		t.Error("empty lease block should be skipped")
	}
}

func TestReadARP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "arp")
	content := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.5      0x1         0x2         3c:22:fb:11:22:33     *        br0
192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        br0
192.168.1.10     0x1         0x2         00:00:00:00:00:00     *        br0
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := readARP(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(got), got)
	}
	if got[netip.MustParseAddr("192.168.1.5")].mac.String() != "3c:22:fb:11:22:33" {
		t.Error("valid ARP entry missing")
	}
}

func TestDeviceRefreshMerges(t *testing.T) {
	dir := t.TempDir()

	leases := filepath.Join(dir, "leases")
	os.WriteFile(leases, []byte("1 3c:22:fb:11:22:33 192.168.1.5 laptop *\n"), 0o644)

	hosts := filepath.Join(dir, "hosts")
	os.WriteFile(hosts, []byte("192.168.1.6 printer\n"), 0o644)

	d := newDeviceDB()
	lf, err := newDeviceFile("dnsmasq", leases)
	if err != nil {
		t.Fatal(err)
	}
	hf, err := newDeviceFile("hosts", hosts)
	if err != nil {
		t.Fatal(err)
	}
	d.files = []*deviceFile{lf, hf}
	d.refresh()

	if got := lookupIP(d, "192.168.1.5", "abc123"); got.Name != "laptop" || got.Model == "" {
		t.Errorf("got %+v, want name and model from the lease file", got)
	}
	if got := lookupIP(d, "192.168.1.6", "abc123"); got.Name != "printer" {
		t.Errorf("got %+v, want printer from the hosts file", got)
	}

	// A missing source must not wipe out the sources that do work.
	d.files = append(d.files, &deviceFile{path: filepath.Join(dir, "gone"), format: "hosts"})
	d.refresh()
	if got := lookupIP(d, "192.168.1.5", "abc123"); got.Name != "laptop" {
		t.Errorf("got %+v after a failing source, want the entry to survive", got)
	}
}

// The ARP table is a cache, not a record: Linux drops entries for devices that
// have been quiet. A device's identity must not change just because its ARP
// entry aged out, or it splits into two devices in the NextDNS logs.
func TestDeviceIDSurvivesARPExpiry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "arp")
	header := "IP address       HW type     Flags       HW address            Mask     Device\n"

	os.WriteFile(path, []byte(header+
		"192.168.1.5      0x1         0x2         3c:22:fb:11:22:33     *        br0\n"), 0o644)

	d := newDeviceDB()
	d.useARP, d.arpPath = true, path
	d.refresh()

	warm := lookupIP(d, "192.168.1.5", "abc123")
	if warm.ID != shortID("abc123", mustMAC("3c:22:fb:11:22:33")) {
		t.Fatalf("ID = %q, want the MAC derived ID", warm.ID)
	}

	// The device goes quiet and the kernel drops its ARP entry.
	os.WriteFile(path, []byte(header), 0o644)
	d.refresh()

	cold := lookupIP(d, "192.168.1.5", "abc123")
	if cold.ID != warm.ID {
		t.Errorf("ID changed from %q to %q when the ARP entry expired", warm.ID, cold.ID)
	}
	if cold.Model != warm.Model {
		t.Errorf("Model changed from %q to %q when the ARP entry expired", warm.Model, cold.Model)
	}

	// A genuinely different device on that address does take it over.
	os.WriteFile(path, []byte(header+
		"192.168.1.5      0x1         0x2         aa:bb:cc:dd:ee:ff     *        br0\n"), 0o644)
	d.refresh()

	if got := lookupIP(d, "192.168.1.5", "abc123"); got.ID == warm.ID {
		t.Error("a new MAC on the same address did not take over the binding")
	}
}

func TestMergeKeepsFilledFields(t *testing.T) {
	m := map[netip.Addr]deviceInfo{}
	addr := netip.MustParseAddr("10.0.0.1")

	merge(m, addr, deviceInfo{name: "laptop", mac: mustMAC("3c:22:fb:11:22:33")})
	merge(m, addr, deviceInfo{}) // an empty later entry must not blank it out

	if m[addr].name != "laptop" || m[addr].mac == nil {
		t.Errorf("got %+v, want the earlier fields preserved", m[addr])
	}
}

// refresh runs for the life of the process, so a source that stays unreadable
// must be reported once, not once per interval.
func TestUnreadableSourceLogsOnce(t *testing.T) {
	f := &deviceFile{path: "/nonexistent", format: "hosts"}
	_, err := f.read()
	if err == nil {
		t.Fatal("expected a read error")
	}

	if !logChanged(&f.lastErr, err, "x") {
		t.Error("logChanged should report an error as an error")
	}
	first := f.lastErr
	if first == "" {
		t.Fatal("error not recorded")
	}
	// Same error again: state unchanged, so nothing new to say.
	if !logChanged(&f.lastErr, err, "x") || f.lastErr != first {
		t.Error("a repeated identical error should not change the recorded state")
	}
	// Recovery clears it, so a later failure is reported afresh.
	if logChanged(&f.lastErr, nil, "x") {
		t.Error("logChanged should report success as success")
	}
	if f.lastErr != "" {
		t.Errorf("lastErr = %q, want cleared after recovery", f.lastErr)
	}
}

// A lease block whose address does not parse must not leave the previous block
// open, or its fields get attributed to the previous lease's address.
func TestParseDHCPDLeasesMalformedAddress(t *testing.T) {
	in := `lease 192.168.1.5 {
  hardware ethernet 3c:22:fb:11:22:33;
  client-hostname "real-device";
lease NOT-AN-IP {
  client-hostname "attacker-supplied";
}
`
	got, err := parseDHCPDLeases(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if n := got[netip.MustParseAddr("192.168.1.5")].name; n == "attacker-supplied" {
		t.Errorf("name = %q, want the malformed block not to be attributed to the previous lease", n)
	}
}

// A row whose flags field does not parse is not a row to trust.
func TestReadARPRejectsMalformedFlags(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "arp")
	os.WriteFile(path, []byte(
		"IP address       HW type     Flags       HW address            Mask     Device\n"+
			"192.168.1.5      0x1         garbage     3c:22:fb:11:22:33     *        br0\n"+
			"192.168.1.6      0x1         0x2         3c:22:fb:11:22:44     *        br0\n"), 0o644)

	got, err := readARP(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[netip.MustParseAddr("192.168.1.5")]; ok {
		t.Error("row with an unparsable flags field was accepted")
	}
	if _, ok := got[netip.MustParseAddr("192.168.1.6")]; !ok {
		t.Error("valid row was dropped")
	}
}

// bindings is fed from the ARP table and never rebuilt, so it needs its own cap.
// An on-link host can churn the kernel neighbour table by cycling addresses.
func TestBindingsAreBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "arp")
	header := "IP address       HW type     Flags       HW address            Mask     Device\n"

	d := newDeviceDB()
	d.useARP, d.arpPath = true, path
	d.maxBindings = 10

	// Each round presents a fresh set of addresses, as an attacker cycling
	// source addresses through the neighbour table would.
	for round := 0; round < 20; round++ {
		var b strings.Builder
		b.WriteString(header)
		for i := 0; i < 8; i++ {
			fmt.Fprintf(&b, "10.0.%d.%d      0x1  0x2  3c:22:fb:11:%02x:%02x  *  br0\n",
				round, i, round, i)
		}
		os.WriteFile(path, []byte(b.String()), 0o644)
		d.refresh()
	}

	d.mu.RLock()
	n := len(d.bindings)
	d.mu.RUnlock()
	if n > d.maxBindings {
		t.Errorf("bindings holds %d entries after 160 distinct addresses, want at most %d", n, d.maxBindings)
	}
	if n == 0 {
		t.Error("bindings emptied entirely; eviction should drop one entry, not all of them")
	}
}
