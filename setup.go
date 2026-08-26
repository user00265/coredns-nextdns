package nextdns

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/parse"
)

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	n, err := parseNextDNS(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		n.Next = next
		return n
	})

	c.OnStartup(func() error {
		// The cache plugin keys on the question only, and it runs ahead of this
		// one, so with more than one profile reachable from this block it serves
		// one profile's answers to another profile's clients. Enabling the cache
		// option here does not help: a query answered by the cache plugin never
		// reaches this plugin at all.
		if len(n.profiles()) > 1 {
			if h := dnsserver.GetConfig(c).Handler("cache"); h != nil {
				log.Warning("This block routes to multiple NextDNS profiles and also loads the cache plugin, which is " +
					"not profile aware and runs first; answers will leak between profiles. Remove the cache plugin from " +
					"this block and use the nextdns cache option, or split the profiles across server blocks.")
			}
		}
		return n.OnStartup()
	})
	c.OnShutdown(n.OnShutdown)

	return nil
}

// profileRe is deliberately permissive: NextDNS profile IDs are short
// alphanumeric strings, and the value is interpolated into a URL path.
var profileRe = regexp.MustCompile(`^[A-Za-z0-9]{4,64}$`)

// validDeviceModel keeps an operator-supplied model from being something an
// HTTP header cannot carry. It is deliberately looser than a device name —
// NextDNS documents models like "iPhone 12 Pro", and the MAC-derived form
// contains colons — but it still has to be printable ASCII.
func validDeviceModel(m string) error {
	if m == "" || len(m) > maxNameLen {
		return fmt.Errorf("device_model %q must be 1 to %d characters", m, maxNameLen)
	}
	for i := 0; i < len(m); i++ {
		if m[i] < 0x20 || m[i] > 0x7e {
			return fmt.Errorf("device_model %q must be printable ASCII", m)
		}
	}
	return nil
}

func validProfile(p string) error {
	if !profileRe.MatchString(p) {
		return fmt.Errorf("invalid profile ID %q, expected 4 to 64 alphanumeric characters", p)
	}
	return nil
}

// validRoute validates a profile used as an override, where "-" means "send
// this query to the next plugin instead of to NextDNS".
func validRoute(p string) error {
	if p == passthrough {
		return nil
	}
	return validProfile(p)
}

func parseNextDNS(c *caddy.Controller) (*NextDNS, error) {
	var (
		n         = New()
		seen      bool
		endpoints []string
		bootstrap []string

		doh = dohOptions{timeout: defaultTimeout}

		cacheOn  bool
		cacheCap int
		cacheMin = defaultCacheMinTTL
		cacheMax = defaultCacheMaxTTL

		// Tuning is collected as pointers so that it can be applied after the
		// whole block is read, and the options may appear in any order.
		discoveryTTL, discoveryRetry, discoveryTimeout *time.Duration
		discoveryMax                                   *int
	)

	for c.Next() {
		if seen {
			return nil, errors.New("this plugin can only be used once per server block")
		}
		seen = true

		args := c.RemainingArgs()
		if len(args) > 1 {
			return nil, c.ArgErr()
		}
		if len(args) == 1 {
			if err := validProfile(args[0]); err != nil {
				return nil, err
			}
			n.profile = args[0]
		}

		for c.NextBlock() {
			switch c.Val() {
			case "profile":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				if err := validProfile(c.Val()); err != nil {
					return nil, err
				}
				n.profile = c.Val()

			case "view_profile":
				args := c.RemainingArgs()
				if len(args) != 2 {
					return nil, c.Errf("view_profile needs a view name and a profile ID")
				}
				if err := validRoute(args[1]); err != nil {
					return nil, err
				}
				n.viewProfiles[args[0]] = args[1]

			case "client_profile":
				args := c.RemainingArgs()
				if len(args) != 2 {
					return nil, c.Errf("client_profile needs a CIDR and a profile ID")
				}
				prefix, err := parsePrefix(args[0])
				if err != nil {
					return nil, err
				}
				if err := validRoute(args[1]); err != nil {
					return nil, err
				}
				n.clientProfiles = append(n.clientProfiles, clientProfile{prefix: prefix, profile: args[1]})

			case "endpoint":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return nil, c.ArgErr()
				}
				endpoints = append(endpoints, args...)

			case "bootstrap":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return nil, c.ArgErr()
				}
				bootstrap = append(bootstrap, args...)

			case "tls_servername":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				doh.tlsServerName = c.Val()

			case "timeout":
				d, err := parseDuration(c)
				if err != nil {
					return nil, err
				}
				doh.timeout = d

			case "max_idle_conns":
				v, err := parsePositiveInt(c)
				if err != nil {
					return nil, err
				}
				doh.maxIdleConns = v

			case "max_concurrent":
				v, err := parsePositiveInt(c)
				if err != nil {
					return nil, err
				}
				n.maxConcurrent = int64(v)

			case "cache":
				cacheOn = true
				if args := c.RemainingArgs(); len(args) == 1 {
					v, err := strconv.Atoi(args[0])
					if err != nil || v <= 0 {
						return nil, c.Errf("cache capacity must be a positive number, got %q", args[0])
					}
					cacheCap = v
				} else if len(args) > 1 {
					return nil, c.ArgErr()
				}

			case "cache_ttl":
				args := c.RemainingArgs()
				if len(args) != 2 {
					return nil, c.Errf("cache_ttl needs a minimum and a maximum duration")
				}
				lo, err := time.ParseDuration(args[0])
				if err != nil {
					return nil, c.Errf("invalid cache_ttl minimum %q: %v", args[0], err)
				}
				hi, err := time.ParseDuration(args[1])
				if err != nil {
					return nil, c.Errf("invalid cache_ttl maximum %q: %v", args[1], err)
				}
				if lo < 0 || hi < lo {
					return nil, c.Errf("cache_ttl needs 0 <= minimum <= maximum")
				}
				cacheMin, cacheMax = lo, hi

			case "device_id":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				mode, err := parseIDMode(c.Val())
				if err != nil {
					return nil, err
				}
				n.devices.mode = mode

			case "device_model":
				// Read the whole line rather than one argument: a model like
				// "iPhone 12 Pro" needs quoting, and taking just the first word
				// would leave the rest to be reported as unknown properties.
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.Errf("device_model takes one value; quote it if it contains spaces")
				}
				if err := validDeviceModel(args[0]); err != nil {
					return nil, err
				}
				n.devices.model = args[0]

			case "device_ip":
				args := c.RemainingArgs()
				switch len(args) {
				case 0:
					n.devices.sendIP = true
				case 1:
					v, err := strconv.ParseBool(args[0])
					if err != nil {
						return nil, c.Errf("device_ip takes true or false, got %q", args[0])
					}
					n.devices.sendIP = v
				default:
					return nil, c.ArgErr()
				}

			case "device_name":
				args := c.RemainingArgs()
				if len(args) != 2 {
					return nil, c.Errf("device_name needs an IP address and a name")
				}
				addr, err := netip.ParseAddr(args[0])
				if err != nil {
					return nil, c.Errf("invalid device_name address %q: %v", args[0], err)
				}
				n.devices.static[addr.Unmap()] = args[1]

			case "device_names":
				args := c.RemainingArgs()
				if len(args) != 2 {
					return nil, c.Errf("device_names needs a format (hosts, dnsmasq or dhcpd) and a path")
				}
				f, err := newDeviceFile(args[0], args[1])
				if err != nil {
					return nil, err
				}
				n.devices.files = append(n.devices.files, f)

			case "discovery":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return nil, c.Errf("discovery needs %q or one or more resolver addresses", "internal")
				}
				d := newDiscoverer()
				if len(args) == 1 && args[0] == "internal" {
					d.resolve = internalResolver()
				} else {
					addrs := make([]string, 0, len(args))
					for _, a := range args {
						hp, err := parse.HostPort(a, "53")
						if err != nil {
							return nil, c.Errf("invalid discovery resolver %q: %v", a, err)
						}
						addrs = append(addrs, hp)
					}
					d.resolve = externalResolver(addrs)
				}
				n.devices.discovery = d

			case "discovery_ttl":
				d, err := parseDuration(c)
				if err != nil {
					return nil, err
				}
				if d <= 0 {
					return nil, c.Errf("discovery_ttl must be a positive duration")
				}
				discoveryTTL = &d

			case "discovery_retry":
				d, err := parseDuration(c)
				if err != nil {
					return nil, err
				}
				if d <= 0 {
					return nil, c.Errf("discovery_retry must be a positive duration")
				}
				discoveryRetry = &d

			case "discovery_timeout":
				d, err := parseDuration(c)
				if err != nil {
					return nil, err
				}
				if d <= 0 {
					return nil, c.Errf("discovery_timeout must be a positive duration")
				}
				discoveryTimeout = &d

			case "discovery_max":
				v, err := parsePositiveInt(c)
				if err != nil {
					return nil, err
				}
				discoveryMax = &v

			case "arp":
				n.devices.useARP = true
				if args := c.RemainingArgs(); len(args) == 1 {
					n.devices.arpPath = args[0]
				} else if len(args) > 1 {
					return nil, c.ArgErr()
				}

			case "reload":
				d, err := parseDuration(c)
				if err != nil {
					return nil, err
				}
				if d <= 0 {
					return nil, c.Errf("reload must be a positive duration")
				}
				n.devices.reload = d

			default:
				return nil, c.Errf("unknown property %q", c.Val())
			}
		}
	}

	if n.profile == "" {
		return nil, errors.New("a profile ID is required")
	}

	if d := n.devices.discovery; d != nil {
		if discoveryTTL != nil {
			d.ttl = *discoveryTTL
		}
		if discoveryRetry != nil {
			d.retry = *discoveryRetry
		}
		if discoveryTimeout != nil {
			d.timeout = *discoveryTimeout
		}
		if discoveryMax != nil {
			d.max = *discoveryMax
		}
	} else if discoveryTTL != nil || discoveryRetry != nil || discoveryTimeout != nil || discoveryMax != nil {
		return nil, errors.New("discovery_ttl, discovery_retry, discovery_timeout and discovery_max need discovery to be enabled")
	}

	// A bare "bootstrap" applies to every endpoint that did not bring its own.
	doh.endpoints = applyBootstrap(endpoints, bootstrap)

	client, err := newDOHClient(doh)
	if err != nil {
		return nil, err
	}
	n.client = client

	// One tls.Config is shared by the whole transport, so a server name pinned
	// here is the name every endpoint's certificate is checked against.
	if doh.tlsServerName != "" && len(client.endpoints) > 1 {
		log.Warningf("tls_servername %q applies to all %d endpoints, so every endpoint certificate is verified "+
			"against that one name.", doh.tlsServerName, len(client.endpoints))
	}

	// An endpoint named by hostname with nothing to bootstrap from has to be
	// resolved by whatever resolver the host has — which may be this server,
	// which cannot answer until it has resolved the endpoint. Worth saying out
	// loud, not least because the Corefile makes it easy to do by accident: the
	// "#addr" suffix is eaten as a comment unless the endpoint is quoted.
	for _, ep := range client.endpoints {
		if len(ep.bootstrap) == 0 && net.ParseIP(ep.host) == nil {
			log.Warningf("Endpoint %s has no bootstrap address, so reaching it depends on another resolver. "+
				"Add a bootstrap option, or quote the endpoint if you meant to write %q.", ep.base, ep.base+"#IP")
		}
	}

	if cacheOn {
		n.cache = newMsgCache(cacheCap, client)
		n.cache.minTTL, n.cache.maxTTL = cacheMin, cacheMax
	}

	// Longest prefix wins, so that a /32 override beats the /24 it sits in.
	sort.SliceStable(n.clientProfiles, func(i, j int) bool {
		return n.clientProfiles[i].prefix.Bits() > n.clientProfiles[j].prefix.Bits()
	})

	// idMAC and idAuto are only useful when something can supply a MAC address.
	if n.devices.mode == idMAC && len(n.devices.files) == 0 && !n.devices.useARP {
		return nil, errors.New("device_id mac needs a MAC source: add arp, or device_names with a lease file")
	}

	return n, nil
}

// applyBootstrap appends the shared bootstrap addresses to endpoints that do
// not already specify their own.
func applyBootstrap(endpoints, bootstrap []string) []string {
	if len(endpoints) == 0 {
		if len(bootstrap) == 0 {
			return nil
		}
		endpoints = []string{"https://dns.nextdns.io"}
	}
	if len(bootstrap) == 0 {
		return endpoints
	}
	out := make([]string, 0, len(endpoints))
	for _, e := range endpoints {
		if !strings.Contains(e, "#") {
			e += "#" + strings.Join(bootstrap, ",")
		}
		out = append(out, e)
	}
	return out
}

// parsePrefix accepts either a CIDR or a bare address, which is treated as a
// host route.
func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid subnet or address %q", s)
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func parseDuration(c *caddy.Controller) (time.Duration, error) {
	if !c.NextArg() {
		return 0, c.ArgErr()
	}
	d, err := time.ParseDuration(c.Val())
	if err != nil {
		return 0, c.Errf("invalid duration %q: %v", c.Val(), err)
	}
	return d, nil
}

func parsePositiveInt(c *caddy.Controller) (int, error) {
	if !c.NextArg() {
		return 0, c.ArgErr()
	}
	v, err := strconv.Atoi(c.Val())
	if err != nil || v <= 0 {
		return 0, c.Errf("expected a positive number, got %q", c.Val())
	}
	return v, nil
}
