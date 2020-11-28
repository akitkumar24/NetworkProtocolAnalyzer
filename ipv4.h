// IPv4 header
typedef struct IPV4_T {
  u_char vers_IHL;
  u_char DSCP_ECN; // DSCP_ECN << 4 >> 4
  u_short length;
  u_short ident;
  u_short flags_offset;
  u_char TTL;
  u_char protocol;
  u_short checksum;
  u_int src;
  u_int dest;
} ipv4_t;


u_short printIPv4(ipv4_t *ipData);
u_short print_Version_IHL(u_char input);
void printIPv4IP(void *data,int leng);
ipv4_t *getIPv4(const u_char *pdata);
char *getProtocolName(int protocol);

u_short printIPv4(ipv4_t *ipData){
  printf("%s\n","IPv4 Packer details are : " );
  u_short ipPacketLen= print_Version_IHL(ipData->vers_IHL);
  printf("DSCP_ECN : "); print_bytes_hex(&(ipData->DSCP_ECN), sizeof(ipData->DSCP_ECN),"\0");
  printf("Total length : %d\n",ntohs(ipData->length));
  printf("Identification : 0x" ); print_bytes_hex(&(ipData->ident),sizeof(ipData->ident),"\0");
  printf("flags_offset : 0x"); print_bytes_hex(&(ipData->flags_offset),sizeof(ipData->flags_offset),"\0");
  printf("Time to Live : %d\n",(int)(ipData->TTL) );
  printf("protocol : %s (%d)\n",getProtocolName((int)(ipData->protocol)),(int)(ipData->protocol) );
  printf("Header Checksum : "); print_bytes_hex(&(ipData->checksum),sizeof(ipData->checksum),"\0");
  printf("Source IP address : "); printIPv4IP(&(ipData->src),sizeof(ipData->src));
  printf("Destination IP address : "); printIPv4IP(&(ipData->dest),sizeof(ipData->dest));
  printf("\n");
  return ipPacketLen;
  
}

ipv4_t *getIPv4(const u_char *pdata){
  ipv4_t *ipv4 = (ipv4_t *)malloc(sizeof(ipv4_t));
  int pointer = 0;
  ipv4->vers_IHL = pdata[pointer++];
  ipv4->DSCP_ECN = pdata[pointer++];
  copyUShort(pdata,&(ipv4->length),pointer);
  pointer+=2;
  copyUShort(pdata,&(ipv4->ident),pointer);
  pointer+=2;
  copyUShort(pdata,&(ipv4->flags_offset),pointer);
  pointer+=2;
  ipv4->TTL = pdata[pointer++];
  ipv4->protocol = pdata[pointer++];
  copyUShort(pdata,&(ipv4->checksum),pointer);
  pointer+=2;
  copyInt(pdata,&(ipv4->src),pointer);
  pointer+=4;
  copyInt(pdata,&(ipv4->dest),pointer);
  return ipv4;
}

u_short print_Version_IHL(u_char input){
  u_short te = input - 24;
  u_short first = te%10;
  u_short sec = te/10;
  first = first*4;
  printf("Version: %d\n",sec );
  printf("Internet Header length is : %d Bytes\n",first );
  return (first/4);
}

void printIPv4IP(void *data,int leng){
  for(int i=0; i < leng-1; i++) {
    printf("%d%s", ((u_char *)data)[i],".");
  }
  printf("%d\n", ((u_char *)data)[leng-1]);
}

char *getProtocolName(int protocol){
  switch(protocol){
    case ICMP: return "ICMP";
    case UDP: return "UDP";
    case TCP: return "TCP";
    default: return "Unknown protocol";
  }
}

