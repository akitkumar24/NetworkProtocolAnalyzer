#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <time.h>

#include "packet_headers.h"


int main(int argc, char *argv[]) {
  // check args
  if (argc < 2) {
    printf("Usage: ./dump filename.pcap\n");
    exit(0);
  }

  // open pcap file
  pcap_t *pc = checkPcapFile(argv[1]);

  // read the packets
  const u_char *pdata;
  struct pcap_pkthdr h;
  int count = 0;
  while ((pdata = pcap_next(pc, &h)) != NULL) { // call pcap_next, and malloc/bcopy, return; or nto...
    char *c_time_string = ctime(&(h.ts.tv_sec));

    // print off info from h about the packet
    printf("packet #%d: caplen %d, len %d, time %s", count, h.caplen, h.len, c_time_string);

    // print off packet bytes
    setUpPacket(pdata,h.caplen);

    printf("\n%s %d \n\n\n","end of packet",count);


    count++;
    if (count == 6){
      //break;
    }
  }

  // close
  pcap_close(pc);

  return 0;
}
