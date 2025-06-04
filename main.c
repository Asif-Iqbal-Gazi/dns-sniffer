#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

void packet_handler(u_char *user, const struct pcap_pkthdr *header,
                    const u_char *packet) {
  (void)user;
  char time_str[64];
  time_t pkt_time = header->ts.tv_sec;
  struct tm *ltime = localtime(&pkt_time);
  strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", ltime);
  printf("[%s.%06ld] Packet length: %d bytes\n", time_str, header->ts.tv_sec,
         header->len);
  printf("\nPacket\n: %s", packet);
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
  pcap_loop(handle, -1, packet_handler, NULL);

  pcap_freecode(&dns_filter);
  pcap_close(handle);
  pcap_freealldevs(alldevs);
  return 0;
}
