# nextdns

A CoreDNS plugin that resolves queries through the [NextDNS](https://nextdns.io) DNS-over-HTTPS
endpoint, attributed to the device that asked.

A network-wide resolver shows up in the NextDNS dashboard as one anonymous device: itself. This
plugin attaches the client's identity to each query — device name, a stable per-profile device ID,
device model, and LAN IP — so the logs and analytics break down per device.

It also does the things a resolver has to do: route queries to different profiles per view or per
client subnet, bootstrap its own connection from literal anycast addresses so it doesn't need a
resolver to become one, and optionally cache in a way that keeps profiles apart.

## Building

CoreDNS has no runtime plugin loading, so the plugin is compiled into the binary.

```sh
git clone https://github.com/coredns/coredns
cd coredns

# Register it. Position in plugin.cfg is position in the request chain — anything
# that should answer ahead of NextDNS must be listed above it.
sed -i 's|^forward:forward$|forward:forward\nnextdns:github.com/user00265/coredns-nextdns|' plugin.cfg

go get github.com/user00265/coredns-nextdns
go generate
go build -o coredns .

./coredns -plugins | grep nextdns
```

Use `go generate`, not `go generate ./...` — the latter runs unrelated generators that fail in a
shallow clone.

To build against a local working copy instead of the published module, swap the `go get` for:

```sh
go mod edit -replace=github.com/user00265/coredns-nextdns=/path/to/coredns-nextdns
go generate && go mod tidy && go build -o coredns .
```

After that, `go build -o coredns .` picks up your edits directly. Re-run `go generate` only if
`plugin.cfg` changes.

Port 53 needs root or `CAP_NET_BIND_SERVICE`. For testing use `.:1053` and
`dig -p 1053 @127.0.0.1 example.org`.

## Configuration

```
nextdns [PROFILE]
```

**PROFILE** is your NextDNS configuration ID, from the Setup tab of the dashboard. That one line is a
working configuration.

```
nextdns [PROFILE] {
    profile PROFILE
    view_profile VIEW PROFILE
    client_profile CIDR PROFILE

    endpoint URL...
    bootstrap IP...
    tls_servername NAME
    timeout DURATION
    max_idle_conns N
    max_concurrent N

    cache [CAPACITY]
    cache_ttl MIN MAX

    discovery internal|ADDR...
    discovery_ttl DURATION
    discovery_retry DURATION
    discovery_timeout DURATION
    discovery_max N

    device_id auto|ip|mac|none
    device_ip BOOL
    device_model MODEL
    device_name IP NAME
    device_names FORMAT PATH
    arp [PATH]
    reload DURATION
}
```

Each option goes on its own line. A Corefile reads arguments to end-of-line, so a closing brace
sharing a line with an option becomes an argument to it.

### Profile routing

| Option | Default | |
| --- | --- | --- |
| `profile PROFILE` | required | Default profile; same as the directive argument. |
| `view_profile VIEW PROFILE` | — | Profile for a named view. Repeatable. |
| `client_profile CIDR PROFILE` | — | Profile for a subnet; a bare address is a host route. Repeatable, longest prefix wins. |

Either override accepts `-`, meaning don't use NextDNS for this query — pass it to the next plugin.

Precedence: the `nextdns/profile` metadata label, then `view_profile`, then `client_profile`, then
the default.

That metadata label is the only profile value not written in the Corefile, so it's checked per query:
4–64 alphanumeric characters, or `-`. Anything else is ignored and counted in
`coredns_nextdns_invalid_profiles_total`. The profile ID isn't a secret and isn't treated as one — it
identifies profiles in logs and metrics, so it's logged as-is and used as a Prometheus label. Just
keep the set of profiles bounded; each distinct one is a time series.

### Upstream

| Option | Default | |
| --- | --- | --- |
| `endpoint URL...` | NextDNS anycast | Tried in order. |
| `bootstrap IP...` | see below | Applied to endpoints that do not carry their own. |
| `tls_servername NAME` | from URL | Name verified in the certificate. |
| `timeout DURATION` | `5s` | Whole query, failover included. |
| `max_idle_conns N` | `16` | Connection pool size. |
| `max_concurrent N` | off | REFUSED past N in-flight queries. |

A NextDNS hostname that ends up with no bootstrap addresses is filled in from the ones the official
`nextdns` client uses — all four anycast addresses for `dns.nextdns.io`, and the matching half of the
set for `dns1.nextdns.io` and `dns2.nextdns.io`. The ordinary configuration therefore never depends
on another resolver, and `bootstrap` is only needed for an endpoint that is not NextDNS.

An endpoint can also carry its own addresses after a `#`. **Quote it** — a Corefile treats an
unquoted `#` as a comment, so the suffix is gone before the plugin sees it:

```corefile
endpoint "https://dns1.nextdns.io#45.90.28.0" "https://dns2.nextdns.io#45.90.30.0"
```

When every bootstrap address for a host is failing, queries to it fail. The plugin deliberately does
*not* fall back to resolving the endpoint's hostname: on a machine that resolves through this server,
that fallback asks this server for the endpoint's own name, and every client query then holds a
goroutine and a socket for the whole timeout — precisely when the upstream is already down. The
transition is logged once, and `coredns_nextdns_bootstrap_failures_total` counts the failed dials.

If you point a NextDNS hostname somewhere else in `/etc/hosts` on purpose, give the address directly
instead and keep certificate verification:

```corefile
endpoint https://45.90.28.0
tls_servername dns.nextdns.io
```

Redirects are never followed: Go copies custom headers across a redirect to a different host, which
would leak the device identity.

### Caching

| Option | Default | |
| --- | --- | --- |
| `cache [CAPACITY]` | off; `10000` when on | Profile-aware response cache. Capacity is spread over 256 shards and rounded up, so it never holds fewer than 256 entries. |
| `cache_ttl MIN MAX` | `5s 1h` | Clamp on entry lifetime. |

The stock *cache* plugin keys on the question alone, which is fine when a block resolves to one
profile — including one block per view, since each gets its own cache:

```corefile
. {
    cache 3600
    nextdns abc123
}
```

When one block routes to several profiles via `client_profile`, drop the *cache* plugin from that
block and use `cache` inside `nextdns` instead. Adding the built-in cache is not enough on its own —
the *cache* plugin runs first, so a query it answers never reaches this plugin, and its answer is
whatever the first client to ask got, on whatever profile. CoreDNS warns at startup if it sees both.

The built-in cache also drops a profile's entries when NextDNS reports its configuration changed, so
blocklist edits apply without waiting out TTLs.

Either way, a cached answer means NextDNS never sees the query — no log entry, no analytics, no
device attribution. Caching trades away some of the visibility this plugin exists to provide, so pick
the TTL knowing that.

Neither cache is keyed on the device either, so per-device NextDNS settings within one profile won't
work with caching on: the first device to ask answers for all of them. Turn caching off for a profile
whose policy varies by device.

`cache_ttl` without `cache` is a configuration error rather than a line that parses and does nothing.

### Device discovery by reverse DNS

| Option | Default | |
| --- | --- | --- |
| `discovery internal\|ADDR...` | off | `internal` resolves through CoreDNS itself; addresses are queried directly, port 53 by default. |
| `discovery_ttl DURATION` | `1h` | Lifetime of a discovered name. |
| `discovery_retry DURATION` | `5m` | Delay before retrying an address that produced no name — no PTR record, a resolver error, or a failed lookup. |
| `discovery_timeout DURATION` | `2s` | One lookup. |
| `discovery_max N` | `4096` | Table cap. |

The name source that doesn't care where CoreDNS runs — most DHCP servers already publish leases as
PTR records. Only consulted for clients nothing else could name.

Lookups run asynchronously, so a device's first query goes out unnamed and the name is there by its
second. They also can't recurse: a lookup is marked on its context, and a marked query is never
enriched or sent to NextDNS.

With `internal`, something else in the chain has to answer the reverse zone — either ahead of
`nextdns` or behind it, since the lookup is offered onward before this plugin gives up. If nothing
answers it gets NXDOMAIN from here, cached for `discovery_retry`. A plugin placed *behind* `nextdns`
will see these reverse queries for your LAN addresses, so don't put a public forwarder there unless
you mean to:

```corefile
. {
    forward 1.168.192.in-addr.arpa 192.168.1.1
    nextdns abc123 {
        discovery internal
    }
}
```

Pointing at the reverse zone's resolver directly is the same result with one less moving part:

```corefile
nextdns abc123 {
    discovery 192.168.1.1
}
```

### Device identity

| Option | Default | |
| --- | --- | --- |
| `device_id auto\|ip\|mac\|none` | `auto` | What the ID derives from. |
| `device_ip BOOL` | `true` | Send the client's LAN IP. |
| `device_model MODEL` | MAC vendor prefix | Fixed model for every device. Quote it if it has spaces. |
| `device_name IP NAME` | — | Pin a name. Repeatable; always wins. |
| `device_names FORMAT PATH` | — | `dnsmasq`, `dhcpd` or `hosts` file. Repeatable. |
| `arp [PATH]` | `/proc/net/arp` | Kernel ARP table. Linux, same segment, IPv4 only. |
| `reload DURATION` | `30s` | Re-read interval for files and ARP. An error without a source to re-read. |

A DNS query carries no device identity; all a plugin gets is the client address. Everything here is
an out-of-band lookup on that address. Names resolve in the order `device_name`, `device_names`,
`discovery`.

The `dnsmasq` and `dhcpd` formats read IPv4 leases, and `arp` reads the IPv4 neighbour table, so an
IPv6-only client takes its name from `device_name` or `discovery` and gets an IP-derived device ID.

`device_names` and `arp` read local state, so they only apply where CoreDNS has it — the lease file
on the same filesystem, or the client's own L2 segment. They're worth using where you have them,
since they're the only sources of a MAC, which is what keeps a device ID stable across a DHCP lease
change. Once an address has been seen with a MAC that binding sticks, so an expiring ARP entry
doesn't silently flip the device to an IP-derived ID.

The ID is a 5-character hash of the profile and the device key, as NextDNS recommends, and matches
the official `nextdns` client. Names are reduced to `a-z A-Z 0-9 -`, domain part dropped, capped at
63 characters — which also sanitises them, since a LAN hostname ends up in an HTTP header.

These are attribution, not authentication. Everything they derive from is asserted by the client.

### Views

Views are separate server blocks, so the plain approach is one `nextdns` per block. `view_profile`
exists for when you'd rather write the config once:

```corefile
(nextdns-shared) {
    metadata
    cache 3600
    nextdns homeprofile {
        view_profile guests guestprofile
        view_profile iot    iotprofile
        discovery 192.168.1.1
    }
    errors
}

. {
    view guests {
        expr incidr(client_ip(), '10.0.20.0/24')
    }
    import nextdns-shared
}

. {
    view iot {
        expr incidr(client_ip(), '10.0.30.0/24')
    }
    import nextdns-shared
}

. {
    import nextdns-shared
}
```

Each block gets its own instance and its own cache, so the stock *cache* plugin is fine here — a
block bound to a view can only reach that view's profile, and the startup warning knows it.

That warning counts the routes a block can actually take, and a `-` passthrough counts as one: those
clients get an unfiltered answer, which a question-keyed cache will hand to everyone else. It cannot
see a profile supplied at request time through `nextdns/profile`, so if you route that way, keep the
*cache* plugin out of the block yourself.

### Metadata

With the *metadata* plugin loaded, this plugin publishes `nextdns/profile-used`,
`nextdns/device-id`, `nextdns/device-name`, `nextdns/device-model` and `nextdns/device-ip`, and reads
`nextdns/profile` as an override.

```corefile
log . "{remote} {name} {type} -> {/nextdns/profile-used} {/nextdns/device-name} ({/nextdns/device-id})"
```

### Metrics

| Metric | Labels |
| --- | --- |
| `coredns_nextdns_request_duration_seconds` | `server`, `profile` — the upstream exchange only, so cache hits are not in it |
| `coredns_nextdns_responses_total` | `server`, `profile`, `rcode` |
| `coredns_nextdns_errors_total` | `endpoint` |
| `coredns_nextdns_bootstrap_failures_total` | `endpoint`, `address` |
| `coredns_nextdns_max_concurrent_rejects_total` | `server` |
| `coredns_nextdns_cache_hits_total`, `coredns_nextdns_cache_misses_total` | `server` |
| `coredns_nextdns_cache_entries` | `server`, `zone`, `view` |
| `coredns_nextdns_cache_collisions_total` | should stay zero |
| `coredns_nextdns_invalid_profiles_total` | |
| `coredns_nextdns_mismatches_total` | `server` — upstream replies that did not answer the question |
| `coredns_nextdns_discovery_lookups_total` | `result`: `found`, `notfound`, `error`, `panic` |
| `coredns_nextdns_discovery_entries` | `server`, `zone`, `view` |
| `coredns_nextdns_devices_known` | `server`, `zone`, `view` |

### Example

```corefile
.:53 {
    metadata

    # No cache plugin here: this block reaches two profiles, and the cache
    # plugin runs ahead of nextdns without knowing about profiles. The
    # profile-aware cache below does that job instead.
    nextdns a1b2c3 {
        client_profile 10.20.30.0/24 1f2e3d
        client_profile 10.20.99.0/24 -

        discovery 10.20.0.1
        discovery_ttl 6h
        device_name 10.20.30.31 Living-Room-TV

        cache 8192
        timeout 4s
    }

    log . "{remote} {name} {type} -> {/nextdns/profile-used} {/nextdns/device-name}"
    errors
}
```

## Note on LLM assistance

This code was generated with the assistance of LLM tools. LLMs were also used to verify its
functionality and to automate the creation of its tests. The code was audited and tested by me before
I agreed with the output.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Elisamuel Resto Donate <sam@samresto.dev>.

This plugin is **not part of the CoreDNS codebase**. It's a separate project with its own author, and
the CoreDNS project isn't responsible for it. Please send any issues, questions or pull requests
about this plugin to <https://github.com/user00265/coredns-nextdns>, not to CoreDNS.

## Acknowledgements

Thanks to the [CoreDNS](https://github.com/coredns/coredns) project and its contributors — this is
built on their plugin architecture, and their work is what makes it possible.
