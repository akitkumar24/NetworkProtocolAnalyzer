#define Ethernet 1

typedef struct arpHeader{
	u_short hardware;
	u_short protocol;
	u_char hardwareSize;
	u_char protocolSize;
	u_short opcode;
	u_char senderMAC[6];
	u_int senderIP;
	u_char targetMAC[6];
	u_int targetIP;
} arp;


arp* getARPData(const u_char *pdata);
char *getHardwareName(u_short hardware);
char *getIp(u_short ipType);
char *getOpcode(u_short opcode);
void printIp(u_short ipType,void *data);


arp* getARPData(const u_char *pdata){
	arp* arpData = (arp *) malloc(sizeof(arp));
	int pointer = 0;
	copyUShort(pdata,&(arpData->hardware),pointer);
	pointer+=sizeof(arpData->hardware);
	copyUShort(pdata,&(arpData->protocol),pointer);
	pointer+=sizeof(arpData->protocol);
	arpData->hardwareSize = pdata[pointer++];
	arpData->protocolSize= pdata[pointer++];
	copyUShort(pdata,&(arpData->opcode),pointer);
	pointer+=sizeof(arpData->opcode);
	copyData(pdata,arpData->senderMAC,pointer,pointer+sizeof(arpData->senderMAC));
	pointer+=sizeof(arpData->senderMAC);
	copyInt(pdata,&(arpData->senderIP),pointer);
	pointer+=sizeof(arpData->senderIP);
	copyData(pdata,arpData->targetMAC,pointer,pointer+sizeof(arpData->targetMAC));
	pointer+=sizeof(arpData->targetMAC);
	copyInt(pdata,&(arpData->targetIP),pointer);
	return arpData;
}

u_short printARP(arp *arpData){
	printf("hardware type : %s (%d)\n",getHardwareName(arpData->hardware),htons(arpData->hardware));
	printf("protocol Type : %s 0x",getIp(arpData->protocol));
	print_bytes_hex(&(arpData->protocol),sizeof(arpData->protocol),"\0");
	printf("Hardware Size : "); print_bytes_hex(&(arpData->hardwareSize),sizeof(arpData->hardwareSize),"\0");
	printf("protocol Size : "); print_bytes_hex(&(arpData->protocolSize),sizeof(arpData->protocolSize),"\0");
	printf("Opcode : %s (%d)\n",getOpcode(arpData->opcode),htons(arpData->opcode));
	printf("Sender MAC address : ");
	print_bytes_hex(&(arpData->senderMAC),sizeof(arpData->senderMAC),":");
	printf("Sender IP address: ");
	printIp(arpData->protocol,&(arpData->senderIP));
	printf("Target MAC address : ");
	print_bytes_hex(&(arpData->targetMAC),sizeof(arpData->targetMAC),":");
	printf("Target IP address: ");
	printIp(arpData->protocol,&(arpData->targetIP));
	printf("\n\n");
}

char *getHardwareName(u_short hardware){
	switch (htons(hardware)){
		case Ethernet: return "Ethernet";
		default: return "Unkown hardware Type";
	}
}

char *getIp(u_short ipType){
	switch(htons(ipType)){
    case ETHERTYPE_IPv4: return "IPv4";
    default: return "Unkown IP Type";
	}
}

void printIp(u_short ipType,void *data){
	switch(htons(ipType)){
    case ETHERTYPE_IPv4: printIPv4IP(data,4);
    						break;
    default: printf("%s\n","Unkown IP Type" );
    			break;
	}
}

char *getOpcode(u_short opcode){
	switch(htons(opcode)){
    case 1: return "request";
    case 2: return "reply";
    default: return "Not valid opcode";
	}
}



