#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

char errbuff[PCAP_ERRBUF_SIZE+1];
pcap_t *checkPcapFile(char *fileName){
  pcap_t * pc = pcap_open_offline(fileName, errbuff);
  if (pc == NULL) {
    printf("pcap_open_offline error: %s\n", errbuff);
    exit(0);
  }
}

char *subString(const u_char *s,int start, int end) {
   int c = 0;
   int till = end-start;
   u_char *rs = (u_char*)malloc(till * sizeof(u_char));
   while (c<till && (s[start]!='\0')) {
      rs[c] = s[start];
      c++;
      start++;
   }
   rs[c] = '\0';
   return rs;
}

void copyData(const u_char *mainString,u_char *copyString,int start,int end){
	for (int i=start,j=0;i<end,j<(end-start);i++,j++){
		copyString[j] = mainString[i];
	}
}


void copyUShort(const u_char *mainString,u_short *copyShort,int start){
	unsigned char temp[2];
	temp[0] = mainString[start];
	temp[1] = mainString[start+1];
	memcpy(copyShort,temp,2);
}

void copyInt(const u_char *mainString,u_int *copyInt, int start){
	char temp[sizeof(u_int)];
	for(int i=0;i<sizeof(u_int);i++){
		temp[i] = mainString[start+i]; 
	}
	memcpy(copyInt,temp,sizeof(u_int));
}

void copyLong(const u_char *mainString,u_long *copyInt, int start){
  char temp[sizeof(u_long)];
  for(int i=0;i<sizeof(u_long);i++){
    temp[i] = mainString[start+i]; 
  }
  memcpy(copyInt,temp,sizeof(u_long));
}

// helper functions and definitions
void print_bytes_hex(void *p,int leng,char *delimiter) {  
  for(int i=0; i < leng-1; i++) {
    printf("%02x%s", ((u_char *)p)[i],delimiter);
  }
  printf("%02x",((u_char *)p)[leng-1] );
  printf("\n");
}

u_int getTCPHeader(u_char inputV){
 u_int temp = inputV>>4;
  return temp;
}

char checkChar(u_char data){
  if(isprint(data))                /* Check if the packet data is printable */
    return (char) data;          /* Print it */
  else
    return '.';
}




