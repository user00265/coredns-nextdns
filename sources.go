package nextdns

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// deviceFile is one on-disk source of device names.
type deviceFile struct {
	path   string
	format string

	// lastErr is the previous read error, so a source that stays unreadable is
	// reported once rather than on every refresh. Only touched from refresh,
	// which is serial: start calls it before spawning the ticker that owns
	// every later call.
	lastErr string
}

// supportedFormats lists the accepted device_names formats.
var supportedFormats = map[string]bool{
	"hosts":   true,
	"dnsmasq": true,
	"dhcpd":   true,
}

func newDeviceFile(format, path string) (*deviceFile, error) {
	if !supportedFormats[format] {
		return nil, fmt.Errorf("unknown device_names format %q, expected hosts, dnsmasq or dhcpd", format)
	}
	return &deviceFile{path: path, format: format}, nil
}

func (f *deviceFile) read() (map[netip.Addr]deviceInfo, error) {
	fh, err := os.Open(f.path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	switch f.format {
	case "hosts":
		return parseHosts(fh)
	case "dnsmasq":
		return parseDnsmasqLeases(fh)
	default:
		return parseDHCPDLeases(fh)
	}
}

// parseHosts reads an /etc/hosts style file: "IP name [alias...]".
func parseHosts(r io.Reader) (map[netip.Addr]deviceInfo, error) {
	out := map[netip.Addr]deviceInfo{}
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := s.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		addr, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}
		out[addr.Unmap()] = deviceInfo{name: fields[1]}
	}
	return out, s.Err()
}

// parseDnsmasqLeases reads a dnsmasq lease file. Each line is
// "<expiry> <mac> <ip> <hostname> <client-id>", with "*" for an unknown field.
func parseDnsmasqLeases(r io.Reader) (map[netip.Addr]deviceInfo, error) {
	out := map[netip.Addr]deviceInfo{}
	s := bufio.NewScanner(r)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 4 {
			continue
		}
		addr, err := netip.ParseAddr(fields[2])
		if err != nil {
			continue
		}
		info := deviceInfo{}
		if fields[3] != "*" {
			info.name = fields[3]
		}
		if mac, err := net.ParseMAC(fields[1]); err == nil {
			info.mac = mac
		}
		out[addr.Unmap()] = info
	}
	return out, s.Err()
}

// parseDHCPDLeases reads an ISC dhcpd leases file. Only the last lease block for
// an address matters, and dhcpd appends, so later blocks overwrite earlier ones.
func parseDHCPDLeases(r io.Reader) (map[netip.Addr]deviceInfo, error) {
	out := map[netip.Addr]deviceInfo{}

	var (
		cur   netip.Addr
		info  deviceInfo
		inTag bool
	)
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		switch {
		case strings.HasPrefix(line, "lease ") && strings.HasSuffix(line, "{"):
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			addr, err := netip.ParseAddr(fields[1])
			if err != nil {
				// Do not leave the previous lease open, or the fields that
				// follow get attributed to the previous lease's address.
				inTag = false
				continue
			}
			cur, info, inTag = addr.Unmap(), deviceInfo{}, true

		case !inTag:
			continue

		case line == "}":
			if info.name != "" || len(info.mac) > 0 {
				out[cur] = info
			}
			inTag = false

		case strings.HasPrefix(line, "client-hostname "):
			info.name = unquote(strings.TrimSuffix(strings.TrimPrefix(line, "client-hostname "), ";"))

		case strings.HasPrefix(line, "hostname "):
			if info.name == "" {
				info.name = unquote(strings.TrimSuffix(strings.TrimPrefix(line, "hostname "), ";"))
			}

		case strings.HasPrefix(line, "hardware ethernet "):
			v := strings.TrimSuffix(strings.TrimPrefix(line, "hardware ethernet "), ";")
			if mac, err := net.ParseMAC(strings.TrimSpace(v)); err == nil {
				info.mac = mac
			}
		}
	}
	return out, s.Err()
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// readARP reads the kernel ARP table so that a device keeps a stable identity
// across DHCP lease changes. Linux only; on other platforms the file is simply
// absent and MAC based identity degrades to IP based identity.
func readARP(path string) (map[netip.Addr]deviceInfo, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	out := map[netip.Addr]deviceInfo{}
	s := bufio.NewScanner(fh)
	if s.Scan() { // header: "IP address HW type Flags HW address Mask Device"
		_ = s.Text()
	}
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 4 {
			continue
		}
		// Flags 0x0 means the entry is incomplete and its MAC is not valid. An
		// unparsable flags field is not a reason to trust the row either.
		flags, err := strconv.ParseUint(strings.TrimPrefix(fields[2], "0x"), 16, 32)
		if err != nil || flags == 0 {
			continue
		}
		addr, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}
		mac, err := net.ParseMAC(fields[3])
		if err != nil || isZeroMAC(mac) {
			continue
		}
		out[addr.Unmap()] = deviceInfo{mac: mac}
	}
	return out, s.Err()
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}
