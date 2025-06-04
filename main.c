#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

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

  pcap_close(handle);
  pcap_freealldevs(alldevs);
  return 0;
}
