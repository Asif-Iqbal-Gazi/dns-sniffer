#include "dns_protocol.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_DOMAINS 256
#define MAX_LINE_LEN 256

#define BYTES_PER_LINE 16

// ANSI color macros
#define COLOR_HEADER "\033[1;34m" // Bold Blue
#define COLOR_RESET "\033[0m"
#define COLOR_LABEL "\033[1;33m" // Bold Yellow
#define COLOR_DATA "\033[0;37m"  // Light gray

typedef struct {
  char domain[128];
  char ip[INET_ADDRSTRLEN];
} DomainMapEntry;

int domain_count = 0;
DomainMapEntry domain_map[MAX_DOMAINS];

void print_usage(const char *progname) {
  // clang-format off
  printf("Usage: %s [-i interface] [-f domain_map_file]\n", progname);
  printf("Options:\n");
  printf("  -i <interface>        Specify network interface to listen on (optional)\n");
  printf("  -f <file>             Path to domain_IP mapping file (CSV format) (mandatory)\n");
  printf("  -h                    Show this help message\n");
  // clang-format on
}

int load_domain_map(const char *filename) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    perror("Error: Could not open domain map file");
    return -1;
  }

  char line[MAX_LINE_LEN];
  while (fgets(line, sizeof(line), fp)) {
    // Remove trailing newline
    line[strcspn(line, "\n")] = '\0';
    // Split on comma
    char *comma = strchr(line, ',');
    if (!comma) {
      fprintf(stderr, "Warning: Skipping invalid line (missing comma): %s\n",
              line);
      continue;
    }

    *comma = '\0';
    char *domain = line;
    char *ip = comma + 1;

    if (domain_count >= MAX_DOMAINS) {
      fprintf(stderr, "Error: Too many domain mappings (limit %d)\n",
              MAX_DOMAINS);
      break;
    }
    strncpy(domain_map[domain_count].domain, domain,
            sizeof(domain_map[domain_count].domain) - 1);
    domain_map[domain_count]
        .domain[sizeof(domain_map[domain_count].domain) - 1] = '\0';
    strncpy(domain_map[domain_count].ip, ip,
            sizeof(domain_map[domain_count].ip) - 1);
    domain_map[domain_count].ip[sizeof(domain_map[domain_count].ip) - 1] = '\0';
    domain_count++;
  }

  fclose(fp);
  printf("Loaded %d domain mapping(s).\n", domain_count);
  return 0;
}

const char *choose_interface(const char *requested_if) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs, *dev;
  const char *selected_if = NULL;

  // Find all network devices
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Error finding devices: %s\n", errbuf);
    return NULL;
  }

  if (alldevs == NULL) {
    fprintf(stderr, "No network interfaces found.\n");
    return NULL;
  }

  if (requested_if) {
    // Try to find matching inteface name
    for (dev = alldevs; dev; dev = dev->next) {
      if (strcmp(dev->name, requested_if) == 0) {
        selected_if = dev->name;
        break;
      }
    }

    if (!selected_if) {
      fprintf(stderr, "Error: Interface %s not found.\n", requested_if);
      pcap_freealldevs(alldevs);
      return NULL;
    }
  } else {
    // No interface provided: list all and select first
    printf("\n+----------------------------------------+\n");
    printf("| No interface provided.                 |\n");
    printf("| Available interfaces:                  |\n");
    printf("+----------------------------------------+\n");
    for (dev = alldevs; dev != NULL; dev = dev->next) {
      printf("- %s\n", dev->name);
    }
    selected_if = alldevs->name;
    printf("+----------------------------------------+\n");
    printf("Defaulting to first: %s\n\n", selected_if);
  }

  // After hours of debugging:
  // pcap_freealldevs frees the memory assocaited with dev->name
  char *selected_if_copy = NULL;
  if (selected_if)
    selected_if_copy = strdup(selected_if);

  pcap_freealldevs(alldevs);
  return selected_if_copy;
}

// Convert DNS name format to dotted domain (e.g: 3www6google3com0 ->
// www.google.com)
int parse_dns_query_name(const uint8_t *payload, int payload_len, int offset,
                         char *output, int max_len) {
  int curr_pos = offset; // Current reading position in DNS paylaod
  int output_idx = 0;    // Curretn wrting position in the output buffer

  while (curr_pos < payload_len) {
    uint8_t len_byte = payload[curr_pos++];
    if (len_byte == 0)
      break; // End of domain name

    if (len_byte + curr_pos > payload_len ||
        output_idx + len_byte + 1 >= max_len)
      return -1;

    if (output_idx > 0)
      output[output_idx++] = '.';
    memcpy(output + output_idx, payload + curr_pos, len_byte);
    output_idx += len_byte;
    curr_pos += len_byte;
  }
  output[output_idx] = '\0';
  return curr_pos;
}

void print_dns_packet_info(const struct ip *ip_hdr,
                           const struct udphdr *udp_hdr,
                           const uint8_t *dns_payload, int dns_length,
                           const struct pcap_pkthdr *p_pkt_hdr) {
  char time_str[64];
  time_t pkt_time = p_pkt_hdr->ts.tv_sec;
  struct tm *ltime = localtime(&pkt_time);
  strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", ltime);

  // Extract IPs and Ports
  char src_ip[INET_ADDRSTRLEN];
  char dst_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);
  uint16_t src_port = ntohs(udp_hdr->uh_sport);
  uint16_t dst_port = ntohs(udp_hdr->uh_dport);

  // Start output
  // clang-format off
  printf(COLOR_HEADER "\n=============================================\n" COLOR_RESET);
  printf(COLOR_LABEL "📦 DNS Packet Captured  " COLOR_RESET "(%d bytes)\n", dns_length);
  printf(COLOR_LABEL "⏰ Timestamp:           " COLOR_RESET "%s.%06ld\n", time_str, p_pkt_hdr->ts.tv_usec);
  printf(COLOR_LABEL "🔹 From:                " COLOR_RESET "%s:%d\n", src_ip, src_port);
  printf(COLOR_LABEL "🔸 To:                  " COLOR_RESET "%s:%d\n", dst_ip, dst_port);
  printf(COLOR_HEADER "=============================================\n" COLOR_RESET);

  printf(COLOR_LABEL "Offset   Hex Bytes                                      | ASCII\n" COLOR_RESET);
  printf(COLOR_HEADER "--------------------------------------------------------|----------------\n" COLOR_RESET);
  // clang-format on

  for (int i = 0; i < dns_length; i += BYTES_PER_LINE) {
    printf("%04x:  ", i);

    // Print hex bytes
    for (int j = 0; j < BYTES_PER_LINE; j++) {
      if (i + j < dns_length)
        printf("%02x ", dns_payload[i + j]);
      else
        printf("   ");
    }

    printf(" | ");

    // Print ASCII
    for (int j = 0; j < BYTES_PER_LINE && i + j < dns_length; j++) {
      unsigned char c = dns_payload[i + j];
      printf("%c", (c >= 32 && c <= 126) ? c : '.');
    }

    printf("\n");
  }
  printf(COLOR_HEADER
         "=============================================\n" COLOR_RESET);
}

void dns_packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header,
                        const u_char *raw_packet) {
  (void)user;

  const struct ether_header *eth_hdr;
  const struct ip *ip_hdr;
  const struct udphdr *udp_hdr;
  const uint8_t *dns_payload;

  // Parse Ethernet header
  eth_hdr = (const struct ether_header *)raw_packet;
  if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP)
    return;

  // Parse IP header
  ip_hdr = (const struct ip *)(raw_packet + sizeof(struct ether_header));
  uint32_t ip_header_len = ip_hdr->ip_hl * 4;
  // Basic IP length validation
  if (ip_header_len < 20 || ip_header_len > ip_hdr->ip_len * 4)
    return;

  // Only process UDP packets
  if (ip_hdr->ip_p != IPPROTO_UDP)
    return;

  // Parse UDP header
  udp_hdr = (const struct udphdr *)((const uint8_t *)ip_hdr + ip_header_len);

  // Filter for DNS packets (UDP src or dst port = 53)
  if (ntohs(udp_hdr->uh_dport) != DNS_PORT &&
      ntohs(udp_hdr->uh_sport) != DNS_PORT)
    return;

  // Get DNS payload pointer and length
  dns_payload = (const uint8_t *)udp_hdr + sizeof(struct udphdr);
  uint32_t dns_length = ntohs(udp_hdr->uh_ulen) - sizeof(struct udphdr);

  // Only process DNS packet
  if (dns_length < sizeof(dns_header_t))
    return;
  const dns_header_t *dns_header = (const dns_header_t *)dns_payload;

  // Get the flags
  uint16_t flags_host = ntohs(dns_header->flags);

  // Fliter for DNS Queries (QR bit = 0)
  if (flags_host & 0x8000)
    return;

  // Get number of questions
  uint16_t qdcount = ntohs(dns_header->qdcount);
  if (qdcount == 0)
    return;
  if (qdcount > 1) {
    fprintf(stderr,
            "Warning: DNS query with multiple questions (%hu) "
            "received.\nProcessing only "
            "the first for now.\n",
            qdcount);
  }

  char queried_domain[DNS_MAX_NAME_LENGTH + 1];
  uint32_t current_dns_offset =
      sizeof(dns_header_t); // Start of Question section is after the DNS header

  // Parse the doamin name
  int name_len_in_packet =
      parse_dns_query_name(dns_payload, dns_length, current_dns_offset,
                           queried_domain, sizeof(queried_domain));
  if (name_len_in_packet < 0) {
    fprintf(stderr, "Error: Failed to parse domain name. Skipping packet.\n");
    return;
  }

  // Advance past the QNAME to get to QTYPE and QCLASS
  current_dns_offset += name_len_in_packet;

  // Check bounds for QTYPE and QCLASS (2 bytes each)
  if (current_dns_offset + sizeof(u_int16_t) * 2 > dns_length) {
    fprintf(stderr,
            "Error: DNS packet too short for QTYPTE/QCLASS. Skipping packet\n");
    return;
  }

  // Extract QTYPE and QCLASS
  const uint8_t *qtype_ptr = dns_payload + current_dns_offset;
  uint16_t qtype = ntohs(*(const uint16_t *)qtype_ptr);
  uint16_t qclass =
      ntohs(*(uint16_t *)(dns_payload + current_dns_offset + sizeof(uint16_t)));

  printf(COLOR_LABEL "Queried domain:         " COLOR_RESET "%s\n",
         queried_domain);

  printf("QTYPE: %hu, QCLASS: %hu\n", qtype, qclass);

  // Check for A record and match with doamin map
  if (qtype == DNS_TYPE_A && qclass == DNS_CLASS_IN) {
    for (int i = 0; i < domain_count; i++) {
      if (strcasecmp(queried_domain, domain_map[i].domain) == 0) {
        printf("TODO: Inject Response: %s --> %s\n", domain_map[i].domain,
               domain_map[i].ip);
        print_dns_packet_info(ip_hdr, udp_hdr, dns_payload, dns_length,
                              pkt_header);
        break;
      }
    }
  }
}

int main(int argc, char **argv) {
  char *iface = NULL;
  char *file_path = NULL;
  int opt;

  opterr = 0;

  while ((opt = getopt(argc, argv, "i:f:h")) != -1) {
    switch (opt) {
    case 'i':
      iface = optarg;
      break;
    case 'f':
      file_path = optarg;
      break;
    case 'h':
      print_usage(argv[0]);
      return 0;
    case '?':
      if (optopt == 'i' || optopt == 'f')
        fprintf(stderr, "Error: Option '-%c' requires an arguments.\n", optopt);
      else
        fprintf(stderr, "Error: Unknown option -%c\n", optopt);
      print_usage(argv[0]);
      return 1;
    }
  }

  // After the while loop, optind is the index of the first non-option argument.
  // We handle this case here.
  if (optind < argc) {
    fprintf(stderr, "Error: Unexpected non-option arguments provided.\n");
    for (int index = optind; index < argc; index++) {
      fprintf(stderr, "Non-option argument: %s\n", argv[index]);
    }
    print_usage(argv[0]);
    return 1;
  }

  if (!file_path) {
    fprintf(stderr, "Error: Domain map file not specified. Use -f option.\n");
    print_usage(argv[0]);
    return 1;
  }

  if (load_domain_map(file_path) != 0)
    return 1;

  const char *selected_if = choose_interface(iface);
  if (!selected_if)
    return 1;

  printf("Using interface: %s\n", selected_if);
  printf("+----------------------------------------+\n");

  char errbuf[PCAP_ERRBUF_SIZE];
  // Open the selected interface for packet capture
  pcap_t *handle = pcap_open_live(selected_if, 65535, 1, 1000, errbuf);
  if (!handle) {
    fprintf(stderr, "Error: Failed to open interface '%s':\n%s\n", selected_if,
            errbuf);
    free((char *)selected_if);
    return 1;
  }

  free((char *)selected_if);

  printf("Successfully opened interface '%s' for packet capture.\n",
         iface ? iface : "(default iface)");

  // Set up BPF filter for DNS (UDP port 53)
  struct bpf_program dns_filter;
  const char filter_exp[] = "port 53";
  bpf_u_int32 net_mask = PCAP_NETMASK_UNKNOWN;

  // Compile the BPF filter
  if (pcap_compile(handle, &dns_filter, filter_exp, 0, net_mask) == -1) {
    fprintf(stderr, "Error: Failed to compile filter %s:\n%s\n", filter_exp,
            pcap_geterr(handle));
    pcap_close(handle);
    return 1;
  }

  // Install the BPF
  if (pcap_setfilter(handle, &dns_filter) == -1) {
    fprintf(stderr, "Error: Failed to set filter %s:\n%s\n", filter_exp,
            pcap_geterr(handle));
    pcap_freecode(&dns_filter);
    pcap_close(handle);
    return 1;
  }

  printf("Starting packet capture on %s...\nPress Ctrl+C to stop.\n",
         iface ? iface : "(default interface)");

  // Start packet capture loop, call packet_handler for each packet
  pcap_loop(handle, -1, dns_packet_handler, NULL);

  pcap_freecode(&dns_filter);
  pcap_close(handle);
  return 0;
}
