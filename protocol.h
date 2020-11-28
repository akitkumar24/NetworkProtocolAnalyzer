//All define String

#define SYN 2
#define SYNACN 12
#define ACK 16
#define PSHACK 24
#define FINACK 17


typedef struct ICMPProtocol
{
	u_char type;
	u_char code;
	u_short checksum;
	u_int restOfHeader;
	u_long date;
}protocol_icmp;

typedef struct UDPProtocol{
	u_short src;
	u_short dst;
	u_short length;
	u_short checksum;
}protocol_udp;

typedef struct TCPProtocol{
	u_short srcPort;
	u_short dstPort;
	u_int seqNum;
	u_int achNum;
	u_char headerLen;
	u_char flag;
	u_short windowSize;
	u_short checksum;
	u_short urgentPtr;
	u_char *optional;
}protocol_tcp;

typedef struct TCPProtoco{
	u_short srcPort;
	u_short dstPort;
	u_int seqNum;
	u_int achNum;
	u_char headerLen;
	u_char flag;
	u_short windowSize;
	u_short checksum;
	u_short urgentPtr;
	//u_char *optional;
}protocol_tcpNull;


protocol_icmp *ICMPProtocolData(const u_char *pdata);
int checkProtocol(u_char protocol);
protocol_udp *UDPProtocolData(const u_char *pdata);
void printUDP(protocol_udp *protocolData);
protocol_tcp *TCPProtocolData(const u_char *pdata);
u_char *getOptionalData(const u_char *pdata,u_char headerLen,int pointer);
char *getFlagType(u_char flag);


int checkProtocolType(void *ipData,int ipType){
  switch(ipType){
    case IPv4Type:	return checkProtocol(((ipv4_t *)ipData)->protocol);
    default: return -1;
  }
}

int checkProtocol(u_char protocol){
  switch((int)protocol){
  	case ICMP: return ICMP;
  	case UDP: return UDP;
  	case TCP: return TCP;
  	default: return -1;
  }
}

void *getProtocolLayerData(int protocolType,const u_char *pdata){
	switch(protocolType){
		case ICMP:return ICMPProtocolData(pdata);
		case UDP: return UDPProtocolData(pdata);
		case TCP: return TCPProtocolData((pdata));
		default: return NULL;
	}
}


protocol_tcp *TCPProtocolData(const u_char *pdata){
	protocol_tcp *data = (protocol_tcp *)malloc(sizeof(protocol_tcp));
	int pointer  = 0;
	copyUShort(pdata,&(data->srcPort),pointer);
	pointer+=2;
	copyUShort(pdata,&(data->dstPort),pointer);
	pointer+=2;
	copyInt(pdata,&(data->seqNum),pointer);
	pointer+=sizeof(data->seqNum);
	copyInt(pdata,&(data->achNum),pointer);
	pointer+=sizeof(data->seqNum);
	data->headerLen = pdata[pointer++];
	data->flag = pdata[pointer++];
	copyUShort(pdata,&(data->windowSize),pointer);
	pointer+=2;
	copyUShort(pdata,&(data->checksum),pointer);
	pointer+=2;
	copyUShort(pdata,&(data->urgentPtr),pointer);
	pointer+=2;
	data->optional = getOptionalData(pdata,data->headerLen,pointer);
	return data;
}
protocol_udp *UDPProtocolData(const u_char *pdata){
	protocol_udp *data = (protocol_udp *)malloc(sizeof(protocol_udp));
	int pointer = 0;
	copyUShort(pdata,&(data->src),pointer);
	pointer+=2;
	copyUShort(pdata,&(data->dst),pointer);
	pointer+=2;
	copyUShort(pdata,&(data->length),pointer);
	pointer+=2;
	copyUShort(pdata,&(data->checksum),pointer);
	pointer+=2;
	return data;
}

void printUDP(protocol_udp *protocolData){
	printf("UDP header Data :\n");
	printf("Source port : %d\n",ntohs(protocolData->src));
	printf("Destination port : %d\n",ntohs(protocolData->dst));
	printf("length : 0x"); print_bytes_hex(&(protocolData->length),sizeof(protocolData->length),"\0");
	printf("Checksum : 0x"); print_bytes_hex(&(protocolData->checksum),sizeof(protocolData->checksum),"\0");
}

void printTCP(protocol_tcp *protocolData){
	printf("TCP header Data :\n");
	printf("Source port : %d\n",ntohs(protocolData->srcPort));
	printf("Destination port :%d\n",ntohs(protocolData->dstPort));
	printf("Sequence Number : ");print_bytes_hex(&(protocolData->seqNum),sizeof(protocolData->seqNum)," ");
	printf("Acknowledgment number : ");print_bytes_hex(&(protocolData->achNum),sizeof(protocolData->achNum)," ");
	u_int temp = getTCPHeader(protocolData->headerLen);
	printf("Header length : %d bytes (%d)\n",temp*4,temp);
	printf("Flag : 0x"); print_bytes_hex(&(protocolData->flag),sizeof(protocolData->flag),"\0");
	printf("Flag Type : %s\n",getFlagType(protocolData->flag) );
	printf("int flag %d\n",(int) protocolData->flag );
	printf("Window size : %d\n",ntohs(protocolData->windowSize));
	printf("Checksum : 0x"); print_bytes_hex(&(protocolData->checksum),sizeof(protocolData->checksum),"\0");
	printf("Urgent Pointer : %d\n",(int) protocolData->urgentPtr);
	if(protocolData->optional!=NULL){
		printf("Optional Data : %s\n",protocolData->optional );
	}
}
	


protocol_icmp *ICMPProtocolData(const u_char *pdata){
	protocol_icmp *data = (protocol_icmp *)malloc(sizeof(protocol_icmp));
	int pointer = 0;
	data->type = pdata[pointer++];
	data->code = pdata[pointer++];
	copyUShort(pdata,&(data->checksum),pointer);
	pointer+=2;
	copyInt(pdata,&(data->restOfHeader),pointer);
	pointer+=sizeof(data->restOfHeader);
	copyLong(pdata,&(data->date),pointer);
	return data;
}

void printICMP(protocol_icmp *protocolData){
	printf("ICMP header Data :\n");
	printf("Type : "); print_bytes_hex(&(protocolData->type), sizeof(protocolData->type),"\0");
	printf("Code : "); print_bytes_hex(&(protocolData->code), sizeof(protocolData->code),"\0");
	printf("checksum : "); print_bytes_hex(&(protocolData->checksum), sizeof(protocolData->checksum),"\0");
	printf("Rest of Header : "); 
	print_bytes_hex(&(protocolData->restOfHeader), sizeof(protocolData->restOfHeader),"\0");
	printf("%s","Time : " );
	print_bytes_hex(&(protocolData->date), sizeof(protocolData->date),"\0");
	printf("\n");
}

u_char *getOptionalData(const u_char *pdata,u_char headerLen,int pointer){
	u_int temp= getTCPHeader(headerLen)-5;
	char *returnData = NULL;
	if(temp>0){
		returnData = (u_char *)malloc(temp*4*sizeof(u_char));
		for (int i=0;i<(4*temp);i++){
			returnData[i] = checkChar(pdata[pointer++]);
		}
	}
	return returnData;
}

char *getFlagType(u_char flag){
	switch ((int)flag){
		case SYN: return "SYN";
		case SYNACN: return "SYN/ACN";
		case ACK: return "ACK";
		case PSHACK: return "PSH/ACK";
		case FINACK: return "FIN/ACK";
		default: return "Unknown Flag";
	}
}