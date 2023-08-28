
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap/pcap.h>

#include "depktcap.h"


int main(int argc, char **argv)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *hdl = NULL;

  struct bpf_program prog;
  if (depkt_compile(argv[1], &prog)) {
    return -1;
  }

  if (argc > 2) {
    hdl = pcap_open_live(argv[2], 100, 0, 1000, errbuf);
    if (hdl == NULL) {
      fprintf(stderr, "Couldn't open device %s: %s\n", argv[2], errbuf);
      return -1;
    }
  }
  bpf_dump(&prog, 2);
  // we did not need pcap_compile, bpf_prog will be translated from our self defined DSL
  if (pcap_setfilter(hdl, &prog) == -1) {
    fprintf(stderr, "Couldn't install filter %s\n",
            pcap_geterr(hdl));
    goto end;
  }

  struct pcap_pkthdr hdr;
  const u_char *packet = pcap_next(hdl, &hdr);
  printf("Capture a packet length %d, type 0x%x\n", hdr.len, packet[12] << 8 | packet[13]);

end:
  pcap_close(hdl);
  pcap_freecode(&prog);
  free(prog.bf_insns);

  return 0;
}