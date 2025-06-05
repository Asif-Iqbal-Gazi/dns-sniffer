# DNS Query Packet Structure (Captured via libpcap)

This document outlines the structure of a raw DNS query packet over Ethernet as seen in a typical `libpcap` capture. This follows the OSI model from Layer 2 to Layer 7.

---

## 📦 Packet Layout

```
+------------------------+
| Ethernet Header        | ← Layer 2
| (14 bytes)             |
+------------------------+
| IP Header              | ← Layer 3
| (20 bytes typical)     |
+------------------------+
| UDP Header             | ← Layer 4
| (8 bytes)              |
+------------------------+
| DNS Message            | ← Layer 7 (Application)
| (variable size)        |
+------------------------+
```

---

## ✉️ Example DNS Query Packet (Hex Dump)

Captured using `tcpdump -X -s 0 udp port 53`:

```
00 0c 29 b7 2c 92 00 50 56 c0 00 08 08 00 45 00
00 3c 1c 46 40 00 40 11 b8 61 c0 a8 38 66 c0 a8
38 01 d3 63 00 35 00 28 77 57 a1 22 01 00 00 01
00 00 00 00 00 00 07 65 78 61 6d 70 6c 65 03 63
6f 6d 00 00 01 00 01
```

---

## 🧪 Dissected

### 🧱 1. Ethernet Header (14 bytes)

| Field           | Bytes             | Description               |
|----------------|-------------------|---------------------------|
| Dest MAC       | `00 0c 29 b7 2c 92`| Destination MAC address   |
| Src MAC        | `00 50 56 c0 00 08`| Source MAC address        |
| EtherType      | `08 00`           | IPv4                      |

---

### 🌐 2. IPv4 Header (20 bytes)

| Field           | Bytes             | Description                        |
|----------------|-------------------|------------------------------------|
| Version/IHL     | `45`             | IPv4, header length = 5×4 = 20B    |
| Total Length     | `00 3c`         | 60 bytes total                     |
| Protocol        | `11`             | UDP (17)                           |
| Src IP          | `c0 a8 38 66`    | 192.168.56.102                     |
| Dst IP          | `c0 a8 38 01`    | 192.168.56.1                       |

---

### 📬 3. UDP Header (8 bytes)

| Field           | Bytes             | Description                        |
|----------------|-------------------|------------------------------------|
| Src Port       | `d3 63`           | Random ephemeral port (54115)     |
| Dst Port       | `00 35`           | Port 53 (DNS)                      |
| Length         | `00 28`           | 40 bytes total                     |

---

### 🌍 4. DNS Message (Starts Here)

| Field               | Bytes             | Description                   |
|--------------------|-------------------|-------------------------------|
| Transaction ID     | `a1 22`           | Client-chosen ID              |
| Flags              | `01 00`           | Standard query                |
| Questions          | `00 01`           | 1 question                    |
| Answer RRs         | `00 00`           | None                          |
| Authority RRs      | `00 00`           | None                          |
| Additional RRs     | `00 00`           | None                          |
| Query Name         | `07 65 ... 03 63` | `example.com` in label format |
| Query Type         | `00 01`           | A record                      |
| Query Class        | `00 01`           | IN (Internet)                 |

---

## 🧠 Summary

This breakdown helps you understand how libpcap captures packets, and how we parse through headers in code using pointer arithmetic:

```c
struct ether_header *eth = (struct ether_header *)packet;
struct ip *ip = (struct ip *)(packet + sizeof(struct ether_header));
struct udphdr *udp = (struct udphdr *)((u_char *)ip + ip_header_len);
u_char *dns_payload = (u_char *)udp + sizeof(struct udphdr);
```

You can build robust DNS sniffers by understanding and navigating this structure.

---
