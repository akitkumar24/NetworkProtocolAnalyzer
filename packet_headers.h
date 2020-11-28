#include "checkAnything.h"
#define ETHERTYPE_IPv4 0x0800
#define ETHERTYPE_ARP 0x0806
#define IPv4Type 1
#define ARPType 6
#define ICMP 1
#define UDP 17
#define TCP 6

#include <netinet/in.h>
#include "ipv4.h"
#include "protocol.h"
#include "arp.h"
/*Notes:
  1. htons: converts short to hex value
  2. If u_char is displayed then we directly print
  3. ntohl
*/
//Packet Header
typedef struct completePacket{
  void *etherLayer;
  void *IPLayer;
  void *protocolLayer;
  void *Data;
} packet;

// ethernet header
typedef struct ETHERNET_t {
  u_char dst[6];
  u_char src[6];
  u_short ethertype;
} ethernet_t;




packet setUpPacket(const u_char *pdata,int packetLen);
void print_ethernet_t(ethernet_t *p);

ethernet_t *getEtherLayer(const u_char *pdata,int start,int end);
int checkIPType(ethernet_t *p);
void *getIPLayer(int ipType,const u_char *pdata);
u_short print_ip_packet(int ipType,void *ipData);
int checkProtocol(u_char protocol);
void *getProtocolLayerData(int protocolType,const u_char *pdata);
void printProtocolData(int protocolType,void *protocolLayer);
int getIPSize(int ipType);
int getEtherLayerSize();
int getProtocolSize(int protocolType,void *p);
void printData(const u_char *pdata,int start,int end);
// helper functions and definitions


//get complete packet data
packet setUpPacket(const u_char *pdata,int packetLen){
    packet p;
    const u_char *starting = pdata;
    int etherSize = getEtherLayerSize();
    p.etherLayer = getEtherLayer(pdata,0,etherSize);
    print_ethernet_t(p.etherLayer);
    int ipType = checkIPType(p.etherLayer);
    int protocolType = 0;
    if(ipType > 0){
      pdata = pdata+etherSize;
      p.IPLayer = getIPLayer(ipType,pdata);
      u_short ipPackLen = print_ip_packet(ipType,p.IPLayer);
      protocolType = checkProtocolType(p.IPLayer,ipType);
      int ipSize = getIPSize(ipType);
      pdata = pdata+ipSize;
      if(protocolType>0){
        p.protocolLayer = getProtocolLayerData(protocolType,pdata);
        printProtocolData(protocolType,p.protocolLayer);
        int protSize = getProtocolSize(protocolType,p.protocolLayer);
        pdata = pdata+protSize;
        int start = protSize+ipSize+etherSize;
        printData(starting,start,packetLen);
      }
      else{
        printf("%s\n", "Unknown protocol type");
      }
    //p.Data = getData();
    }
    else{
      printf("%s\n","Unknown IP type" );
    }
    return p;
}

ethernet_t *getEtherLayer(const u_char *pdata,int start,int end){
  ethernet_t *ether = (ethernet_t *)malloc(sizeof(ethernet_t));
  copyData(pdata,ether->dst,start,6);
  copyData(pdata,ether->src,6,12);
  copyUShort(pdata,&(ether->ethertype),12);
  return ether;
}

/*
  1 is for IPv4
*/
int checkIPType(ethernet_t *p){
  switch(htons(p->ethertype)){
    case ETHERTYPE_IPv4: return IPv4Type;
    case ETHERTYPE_ARP: return ARPType;
    default: return -1;
  }

}




void print_ethernet_t(ethernet_t *p) {
  printf("Destination MAC Address: "); 
  print_bytes_hex(p->dst, sizeof(p->dst),": ");
  printf("Source MAC Address: "); 
  print_bytes_hex(p->src, sizeof(p->src),": ");
  printf("Ethertype: "); 
  print_bytes_hex(&(p->ethertype), sizeof(p->ethertype),"\0");
  printf("\n");
}




void *getIPLayer(int ipType,const u_char *pdata){
  switch(ipType){
    case IPv4Type: return getIPv4(pdata);
    case ARPType: return getARPData(pdata);
  }
}

u_short print_ip_packet(int ipType,void *ipData){
  switch(ipType){
    case IPv4Type: return printIPv4((ipv4_t *)ipData);
    case ARPType: return printARP((arp *)ipData);
  }
}

void printProtocolData(int protocolType,void *protocolData){
  switch(protocolType){
    case ICMP: printICMP((protocol_icmp *)protocolData);
              break;
    case UDP: printUDP((protocol_udp *)protocolData);
              break;
    case TCP: printTCP((protocol_tcp *)protocolData);
              break;
    default: printf("%s\n","not a valid protocol" );
  }
}

int getIPSize(int ipType){
  switch(ipType){
    case IPv4Type: return sizeof(ipv4_t);
  }
}

int getEtherLayerSize(){
  return sizeof(ethernet_t);
}

int getProtocolSize(int protocolType,void *data){
  switch(protocolType){
    case ICMP: return sizeof(protocol_icmp);
    case UDP: return sizeof(protocol_udp);
    case TCP: if(((protocol_tcp *)data)->optional == NULL)
                  return sizeof(protocol_tcpNull);
              else
                  return sizeof(protocol_tcp);

  }
}

void printData(const u_char *pdata,int start,int end){
  printf("\nData is :\n");
  for(int i = start ;i<end;i++){
      printf("%c ",checkChar(pdata[i]));
  }
}

