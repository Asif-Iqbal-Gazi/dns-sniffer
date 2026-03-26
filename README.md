# DNS Sniffer

A DNS spoofing tool written in C that captures live DNS queries on a network interface and injects crafted responses to redirect specified domains lookups to attacker-specified IP addresses.

Intended for educational use, penetration testing, and security research in authorized environments.

---

## How It Works

1. Listens on a network interface using **libpcap** with a BPF filter on UDP port 53
2. Parses full DNS query packets (Ethernet -> IP -> UDP -> DNS)
3. Matches the queried domain against a user-supplied CSV mapping
4. Immediately injects a forged DNS `A` record response with the spoofed IP
5. If the spoof packet arrives at the client before the real DNS server's reply, the client caches the fake IP

## Winning the Race

DNS spoofing is a race: the forged reply must reach the client before legitimate server's response. Two optimisations are in place to minimise the time between "query captured" and "spoof injected":

| Technique                   | Detail                                                                                                                                                                          |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Precomputes payloads**    | Full DNS response payloads are built once at startup for every domain in the map. Per-packer work is reduced to a `memcpy` + patching two fields (transaction ID and RD flags). |
| **Stack-allocated buffers** | The response packet buffer is allocated on the stack inside the pcap callback, avoiding per-packet `malloc/free` overhead.                                                      |

---

## Project Structure

```
dns-sniffer/
├── include/
│   └── dns_protocol.h          # DNS structs, flags, constants
├── src/
│   ├── dns_spoofer.c           # Optimised build (precomputed responses)
│   └── dns_spoofer_static.c    # Reference build (responses built on the fly)
├── bin/
│   └── domains.txt             # Example domain → IP mapping
├── doc/
│   └── dns_udp_packet_layout.md  # Packet layout reference
├── Makefile
└── LICENSE
```

---

## Requirements

- GCC with C11 support
- `libpcap` (`libpcap-dev` on Debian/Ubuntu, `libpacp-devel` on Fedora/RHEL)
- Root privileges (required for raw packet capture and injection)

## Build

```bash
# Build both versions
make all

# Build only the optimized version
make bin/dns_spoofer

# Build only the static (legacy) version
make bin/dns_spoofer_static

# Clean build artifacts
make clean
```

## Usage

```bash
sudo ./bin/dns_spoofer [-i <interface>] -f <domain_map_file>
sudo ./bin/dns_spoofer_static [-i <interface>] -f <domain_map_file>
```

| Flag             | Required | Description                                                  |
| ---------------- | -------- | ------------------------------------------------------------ |
| `-f <file>`      | Yes      | Path to the domain-IP mapping CSV file                       |
| `-i <interface>` | No       | Network interface to listen on (defaults to first available) |
| `-h`             | No       | Show help message                                            |

**Example:**

```bash
sudo ./bin/dns_spoofer -i eth0 -f /bin/domains.txt
```

> `sudo` (or `CAP_NET_RAW`) is required for raw packet capture and injection.

---

## Domain Map File

A plain CSV file - One `domain, ip` pair per line:

```
example.com,1.2.3.4
www.google.com,192.0.2.2
```

- Maximum **256** entries
- Only IPv4 (`A` record) spoofing is supported
- Lines without a comma are skipped with a warning

---

## Known Limitations

| Limitation                   | Notes                                                                    |
| ---------------------------- | ------------------------------------------------------------------------ |
| DNS compression pointers     | Not handled in query parser; packets using label compression are skipped |
| UDP checksum                 | Set to 0 (disabled)                                                      |
| Multiple questions per query | Only the first question is processed                                     |
| Record types                 | Only `A` (IPv4) queries are spoofed                                      |
| TTL                          | Hardcoded to 60 seconds                                                  |

---

## License

MIT — see [LICENSE](LICENSE).
