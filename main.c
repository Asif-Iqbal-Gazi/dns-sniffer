#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

int main(void) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs, *d;

  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Error finding devices: %s\n", errbuf);
    return 1;
  }

  printf("Available devices:\n");
  printf("+----------------------------------------+\n");

  for (d = alldevs; d != NULL; d = d->next) {
    printf("%s\n", d->name);
  }

  printf("+----------------------------------------+\n");

  pcap_freealldevs(alldevs);
  return 0;
}
