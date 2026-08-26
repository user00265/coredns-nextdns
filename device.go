package nextdns

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/request"

	"github.com/cespare/xxhash/v2"
)

// ClientInfo is the device identity NextDNS attaches to a query. It is sent as
// the X-Device-* request headers documented at
// https://help.nextdns.io/t/x2h76ay/device-information-log-enrichment
type ClientInfo struct {
	ID    string // stable, per-profile, non-reversible device identifier
	IP    string // device LAN IP
	Name  string // device name, e.g. Bobs-iPhone
	Model string // device model, e.g. mac:3c:22:fb
}

// setHeaders adds the non-empty fields to h.
func (ci ClientInfo) setHeaders(h http.Header) {
	if ci.ID != "" {
		h.Set("X-Device-Id", ci.ID)
	}
	if ci.IP != "" {
		h.Set("X-Device-Ip", ci.IP)
	}
	if ci.Model != "" {
		h.Set("X-Device-Model", ci.Model)
	}
	if ci.Name != "" {
		h.Set("X-Device-Name", ci.Name)
	}
}

// idMode selects what a device ID is derived from.
type idMode int

const (
	// idAuto uses the MAC address when one is known for the client, and falls
	// back to the client IP. MAC is preferred because it survives a DHCP lease
	// change, which would otherwise split one device into two in the logs.
	idAuto idMode = iota
	idIP
	idMAC
	idNone
)

func parseIDMode(s string) (idMode, error) {
	switch s {
	case "auto":
		return idAuto, nil
	case "ip":
		return idIP, nil
	case "mac":
		return idMAC, nil
	case "none":
		return idNone, nil
	}
	return idAuto, fmt.Errorf("unknown device_id mode %q, expected auto, ip, mac or none", s)
}

// deviceInfo is what has been learned about one device.
type deviceInfo struct {
	name string
	mac  net.HardwareAddr
}

// deviceDB resolves a client IP to a device identity. Static entries come from
// the Corefile; learned entries come from DHCP lease files, hosts files and the
// kernel ARP table, all refreshed in the background.
type deviceDB struct {
	mode    idMode
	model   string
	sendIP  bool
	reload  time.Duration
	arpPath string
	useARP  bool

	// arpLastErr mirrors deviceFile.lastErr for the ARP table.
	arpLastErr string

	// maxBindings caps the remembered address-to-MAC map; a field rather than a
	// constant so tests can drive the eviction path.
	maxBindings int

	static    map[netip.Addr]string
	files     []*deviceFile
	discovery *discoverer

	mu      sync.RWMutex
	learned map[netip.Addr]deviceInfo
	// bindings remembers the MAC last seen for an address, and unlike learned it
	// survives a refresh. The ARP table is a cache: Linux drops entries for a
	// device that has been quiet for a minute or so. Without this, a device's ID
	// would flip between MAC derived and IP derived as its ARP entry came and
	// went, splitting it into two devices in the NextDNS logs.
	bindings map[netip.Addr]net.HardwareAddr

	done chan struct{}
	once sync.Once
}

func newDeviceDB() *deviceDB {
	return &deviceDB{
		mode:        idAuto,
		sendIP:      true,
		reload:      defaultReload,
		arpPath:     defaultARPPath,
		static:      map[netip.Addr]string{},
		learned:     map[netip.Addr]deviceInfo{},
		bindings:    map[netip.Addr]net.HardwareAddr{},
		maxBindings: maxBindings,
		done:        make(chan struct{}),
	}
}

const (
	defaultReload  = 30 * time.Second
	defaultARPPath = "/proc/net/arp"

	// shutdownGrace bounds how long stop waits for detached device lookups.
	shutdownGrace = 5 * time.Second

	// maxBindings caps the remembered address-to-MAC map. It is fed from the
	// ARP table, whose contents an on-link host can churn by cycling source
	// addresses, and unlike the tables it is derived from it is never rebuilt.
	maxBindings = 8192
)

// lookup builds the ClientInfo for the client that sent state, under a given
// profile.
func (d *deviceDB) lookup(ctx context.Context, state *request.Request, profile string) ClientInfo {
	var ci ClientInfo

	addr, err := netip.ParseAddr(state.IP())
	if err != nil {
		return ci
	}
	addr = addr.Unmap()

	if d.sendIP {
		ci.IP = addr.String()
	}

	var info deviceInfo
	d.mu.RLock()
	info = d.learned[addr]
	if len(info.mac) == 0 {
		info.mac = d.bindings[addr]
	}
	d.mu.RUnlock()

	// A name configured in the Corefile always wins over a discovered one.
	if name, ok := d.static[addr]; ok {
		info.name = name
	}
	// Reverse DNS is the last resort: it costs a query, so it is only asked when
	// nothing on disk knew this address.
	if info.name == "" {
		info.name = d.discovery.name(ctx, addr, state.W.LocalAddr())
	}
	ci.Name = normalizeName(info.name)

	if len(info.mac) >= 6 {
		// Only the OUI is sent: enough for NextDNS to show a vendor, not enough
		// to identify the device globally.
		ci.Model = "mac:" + info.mac.String()[:8]
	}
	if d.model != "" {
		ci.Model = d.model
	}

	ci.ID = d.deviceID(profile, addr, info.mac)
	return ci
}

// deviceID derives the value sent as X-Device-Id.
func (d *deviceDB) deviceID(profile string, addr netip.Addr, mac net.HardwareAddr) string {
	switch d.mode {
	case idNone:
		return ""
	case idIP:
		return shortID(profile, addr.AsSlice())
	case idMAC:
		if len(mac) == 0 {
			return ""
		}
		return shortID(profile, mac)
	default: // idAuto
		if len(mac) > 0 {
			return shortID(profile, mac)
		}
		return shortID(profile, addr.AsSlice())
	}
}

// shortID derives a 5 character, non-reversible, per-profile device identifier
// from a stable device key (MAC or IP). Mixing the profile ID into the hash is
// what NextDNS recommends: it means the same device cannot be correlated across
// profiles from its ID alone. This matches the derivation used by the official
// nextdns client, so a device keeps the same ID if you switch between them.
func shortID(profile string, key []byte) string {
	if len(key) == 0 {
		return ""
	}
	buf := make([]byte, 0, max(len(profile)+len(key), 13))
	buf = append(buf, profile...)
	buf = append(buf, key...)

	sum := xxhash.Sum64(buf)
	buf = strconv.AppendUint(buf[:0], sum, 32)

	if len(buf) < 5 {
		pad := make([]byte, 5)
		copy(pad[5-len(buf):], buf)
		for i := range pad[:5-len(buf)] {
			pad[i] = '0'
		}
		buf = pad
	} else {
		buf = buf[:5]
	}
	for i := range buf {
		if buf[i] >= 'a' {
			buf[i] ^= 1 << 5 // to upper case
		}
	}
	return string(buf)
}

// maxNameLen bounds the device name; NextDNS truncates long names anyway and an
// unbounded header from a hostile DHCP client is not worth forwarding.
const maxNameLen = 63

// normalizeName reduces a discovered hostname to the character set NextDNS
// accepts (a-z, A-Z, 0-9 and -). This doubles as sanitising: the name ends up
// in an HTTP header, so it must not carry control characters or newlines.
func normalizeName(name string) string {
	if name == "" {
		return ""
	}
	// Drop any domain part: "laptop.lan" is reported as "laptop".
	if i := strings.IndexByte(name, '.'); i > 0 {
		name = name[:i]
	}

	var b strings.Builder
	b.Grow(len(name))
	dash := false
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		default:
			// Collapse runs of unsupported characters into a single dash.
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
		if b.Len() >= maxNameLen {
			break
		}
	}
	return strings.TrimRight(b.String(), "-")
}

// start begins refreshing the learned devices in the background.
func (d *deviceDB) start() {
	if len(d.files) == 0 && !d.useARP {
		return
	}
	d.refresh()
	go func() {
		t := time.NewTicker(d.reload)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				d.refresh()
			case <-d.done:
				return
			}
		}
	}()
}

func (d *deviceDB) stop() {
	d.once.Do(func() { close(d.done) })
	// Detached reverse lookups are the one thing here that outlives the ticker,
	// so join them rather than leaving them running against a server that is
	// going away.
	d.discovery.wait(shutdownGrace)
}

// refresh re-reads every configured source and swaps in the new table.
func (d *deviceDB) refresh() {
	learned := map[netip.Addr]deviceInfo{}

	for _, f := range d.files {
		entries, err := f.read()
		if logChanged(&f.lastErr, err, "device source "+f.path) {
			continue
		}
		for addr, info := range entries {
			merge(learned, addr, info)
		}
	}

	if d.useARP {
		entries, err := readARP(d.arpPath)
		logChanged(&d.arpLastErr, err, "ARP table "+d.arpPath)
		for addr, info := range entries {
			merge(learned, addr, info)
		}
	}

	d.mu.Lock()
	d.learned = learned
	// Remember every MAC seen this round. An address only ever gives up its
	// binding to a *different* MAC — the device on that address actually
	// changed — never to the entry merely ageing out of the ARP table.
	for addr, info := range learned {
		if len(info.mac) == 0 {
			continue
		}
		if _, known := d.bindings[addr]; !known && len(d.bindings) >= d.maxBindings {
			// Drop an arbitrary binding rather than growing without bound. The
			// cost is that one device may fall back to an IP derived ID.
			for k := range d.bindings {
				delete(d.bindings, k)
				break
			}
		}
		d.bindings[addr] = info.mac
	}
	d.mu.Unlock()

	devicesKnown.Set(float64(len(learned)))
}

// logChanged reports err for source, but only when it differs from the previous
// outcome, and reports the recovery too. refresh runs every reload interval for
// the life of the process, so logging unconditionally would turn one unreadable
// path into a warning every 30 seconds forever. It returns true if err != nil.
func logChanged(last *string, err error, source string) bool {
	cur := ""
	if err != nil {
		cur = err.Error()
	}
	if cur == *last {
		return err != nil
	}
	switch {
	case err != nil:
		log.Warningf("Cannot read %s: %v", source, err)
	default:
		log.Infof("Reading %s again", source)
	}
	*last = cur
	return err != nil
}

// merge folds an entry into the table without letting a later source blank out
// a field an earlier source already filled in.
func merge(m map[netip.Addr]deviceInfo, addr netip.Addr, info deviceInfo) {
	cur := m[addr]
	if info.name != "" {
		cur.name = info.name
	}
	if len(info.mac) > 0 {
		cur.mac = info.mac
	}
	m[addr] = cur
}
