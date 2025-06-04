#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

int main(int argc, char **argv) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs, *device;
  char *selected_if = NULL;

  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Error finding devices: %s\n", errbuf);
    return 1;
  }

  if (alldevs == NULL) {
    fprintf(stderr, "No network interfaces found.\n");
    return 1;
  }

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
    selected_if = alldevs->name;

    printf("\n+----------------------------------------+\n");
    printf("| No interface provided.                 |\n");
    printf("| Available interfaces:                  |\n");
    printf("+----------------------------------------+\n");
    for (device = alldevs; device != NULL; device = device->next) {
      printf("- %s\n", device->name);
    }
    printf("+----------------------------------------+\n");
    printf("Defaulting to: %s\n", selected_if);
  }

  printf("\nUsing interface: %s\n", selected_if);
  printf("+----------------------------------------+\n");

  pcap_freealldevs(alldevs);
  return 0;
}
