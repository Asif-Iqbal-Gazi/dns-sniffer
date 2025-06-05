#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

void dns_packet_handler(u_char *user, const struct pcap_pkthdr *header,
                        const u_char *packet) {
  (void)user;
  (void)header;

  const struct ether_header *eth_hdr;
  const struct ip *ip_hdr;
  const struct udphdr *udp_hdr;
  const u_char *dns_payload;

  eth_hdr = (struct ether_header *)packet;

  // Check if IP Packet
  if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
    return;
  }

  ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));

  // Check if the protocol is UDP
  if (ip_hdr->ip_p != IPPROTO_UDP) {
    return;
  }

  int ip_header_len = ip_hdr->ip_hl * 4;
  udp_hdr = (struct udphdr *)((const u_char *)ip_hdr + ip_header_len);

  // Not a DNS packet
  if (ntohs(udp_hdr->uh_dport) != 53 && ntohs(udp_hdr->uh_sport) != 53) {
    return;
  }

  dns_payload = (u_char *)udp_hdr + sizeof(struct udphdr);
  int dns_length = ntohs(udp_hdr->uh_ulen) - sizeof(struct udphdr);
  printf("\nDNS packet capture (%d bytes)\n", dns_length);
  printf("DNS Payload (hex view):\n");

  for (int i = 0; i < dns_length; i += 8) {
    printf("%04x:  ", i);

    // Print hex bytes
    for (int j = 0; j < 8; j++) {
      if (i + j < dns_length)
        printf("%02x ", dns_payload[i + j]);
      else
        printf("   ");
    }

    printf(" | ");

    // Print ASCII
    for (int j = 0; j < 8 && i + j < dns_length; j++) {
      unsigned char c = dns_payload[i + j];
      printf("%c", (c >= 32 && c <= 126) ? c : '.');
    }

    printf("\n");
  }

  // char time_str[64];
  // time_t pkt_time = header->ts.tv_sec;
  // struct tm *ltime = localtime(&pkt_time);
  // strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", ltime);
  // printf("[%s.%06ld] Packet length: %d bytes\n", time_str, header->ts.tv_sec,
  //        header->len);
  // printf("\nPacket\n: %s", packet);
}

int main(int argc, char **argv) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs, *device;
  const char *selected_if = NULL;

  // Find all network devices
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Error finding devices: %s\n", errbuf);
    return 1;
  }

  if (alldevs == NULL) {
    fprintf(stderr, "No network interfaces found.\n");
    return 1;
  }

  // Check for user-supplied interface
  if (argc > 1) {
    for (device = alldevs; device != NULL; device = device->next) {
      if (strcmp(device->name, argv[1]) == 0) {
        selected_if = device->name;
        break;
      }
    }
    if (!selected_if) {
      fprintf(stderr, "Provided interface '%s' not found. Exiting.\n", argv[1]);
      pcap_freealldevs(alldevs);
      return 1;
    }
  } else {
    // No interface provided: list all and select first
    selected_if = alldevs->name;

    printf("\n+----------------------------------------+\n");
    printf("| No interface provided.                 |\n");
    printf("| Available interfaces:                  |\n");
    printf("+----------------------------------------+\n");
    for (device = alldevs; device != NULL; device = device->next) {
      printf("- %s\n", device->name);
    }
    printf("+----------------------------------------+\n");
    printf("Defaulting to: %s\n\n", selected_if);
  }

  printf("Using interface: %s\n", selected_if);
  printf("+----------------------------------------+\n");

  // Open the selected interface for packet capture
  pcap_t *handle = pcap_open_live(selected_if, 65535, 1, 1000, errbuf);
  if (!handle) {
    fprintf(stderr, "Failed to open interface '%s':\n%s\n", selected_if,
            errbuf);
    pcap_freealldevs(alldevs);
    return 1;
  }

  printf("Successfully opened interface '%s' for packet capture.\n",
         selected_if);

  // Set up BPF filter for DNS (UDP port 53)
  struct bpf_program dns_filter;
  const char filter_exp[] = "port 53";
  bpf_u_int32 net_mask = PCAP_NETMASK_UNKNOWN;

  // Compile the BPF filter
  if (pcap_compile(handle, &dns_filter, filter_exp, 0, net_mask) == -1) {
    fprintf(stderr, "Failed to compile filter %s:\n%s\n", filter_exp,
            pcap_geterr(handle));
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 1;
  }

  // Install the BPF
  if (pcap_setfilter(handle, &dns_filter) == -1) {
    fprintf(stderr, "Failed to set filter %s:\n%s\n", filter_exp,
            pcap_geterr(handle));
    pcap_freecode(&dns_filter);
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 1;
  }

  printf("Starting packet capture on %s...\nPress Ctrl+C to stop.\n",
         selected_if);

  // Start packet capture loop, call packet_handler for each packet
  pcap_loop(handle, -1, dns_packet_handler, NULL);

  pcap_freecode(&dns_filter);
  pcap_close(handle);
  pcap_freealldevs(alldevs);
  return 0;
}
