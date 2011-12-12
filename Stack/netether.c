/*
 * Code for management of network interfaces
 */

////
// Include files
////

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <arpa/inet.h>

#include <libarrays.h>
#include <libevents.h>

#include "netether.h"
#include "netip.h"
#include "stack.h"

////
// Constants
////

#define ETHERNET_STRING_MAX		18
#define ETHERNET_PACKET_MAX		1518

////
// Global variables
////

EthernetAddress ETHERNET_ADDRESS_NULL={{0x00,0x00,0x00,0x00,0x00,0x00}};
EthernetAddress ETHERNET_ADDRESS_BROADCAST={{0xFF,0x0FF,0xFF,0xFF,0xFF,0xFF}};

////
// Functions
////

//
// Decode Ethernet packet
//

#ifdef VERBOSE
#define MAX_BYTES_BY_ROW 16
void displayEthernetPacket(FILE *output,Ethernet_fields *ethernet,int data_size){
fprintf(output,"%sTarget: %s%s\n", BLUE, BLACK, ethernetAddress2String(ethernet->target));
fprintf(output,"%sSender: %s%s\n", BLUE, BLACK, ethernetAddress2String(ethernet->sender));
fprintf(output,"%sProtocol: %s%04x\n", BLUE, BLACK, ntohs(ethernet->protocol));
fprintf(output,"%sData:\n  %s", BLUE, BBLACK);
int i;
for(i=0;i<data_size;i++){
  fprintf(output,"%02x ", ethernet->data[i]);
  if(i%MAX_BYTES_BY_ROW == MAX_BYTES_BY_ROW-1){
    fprintf(output,"\n");
    if(i<data_size-1) fprintf(output,"  ");
    }
  }
if(i%MAX_BYTES_BY_ROW != 0) fprintf(output,"%s\n", BLACK);
}
#endif

unsigned char ethernetDecodePacket(EventsEvent *event,EventsSelector *selector){
EthernetInterface *intf=(EthernetInterface *)event->data_init;
unsigned char *packet=(unsigned char *)malloc(ETHERNET_PACKET_MAX);
int size=read(intf->descriptor,packet,ETHERNET_PACKET_MAX);
if(size<=0){ free(packet); return 1; }
packet=(unsigned char *)realloc(packet,size);
if(packet==NULL){ printf("%s",RED);perror("ethernetDecodePacket.realloc");printf("%s",BLACK); return 1; }
int data_size=size-sizeof(Ethernet_fields)+1;
Ethernet_fields *fields=(Ethernet_fields *)packet;
EthernetAddress target=fields->target;
if(!ethernetCompare(target,ETHERNET_ADDRESS_BROADCAST) &&
   !ethernetCompare(target,intf->ether_addr))
  { free(packet); return 0; }
#ifdef VERBOSE
fprintf(stderr,"\n%s<<<<<  Incoming Ethernet packet (intf=%s)  <<<<<\n%s", BGREEN, intf->name_int, BLACK);
displayEthernetPacket(stderr,fields,data_size);
#endif
int proto=ntohs(fields->protocol);
StackLayers *layer=stackFindProtoById(LEVEL_NETWORK,proto);
if(layer!=NULL && layer->event_in>=0){
  unsigned char *data=packet;
  memmove(packet,fields->data,data_size);
  data=(unsigned char *)realloc(data,data_size);
  AssocArray *infos=NULL;
  arraysSetValue(&infos,"data",data,data_size,AARRAY_DONT_DUPLICATE);
  arraysSetValue(&infos,"size",&data_size,sizeof(int),0);
  eventsTrigger(layer->event_in,infos);
  }
else free(packet);
return 0;
}

//
// Send Ethernet packet
//

unsigned char ethernetSendPacket(EventsEvent *event,EventsSelector *selector){
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"data",0)<0 || arraysTestIndex(infos,"size",0)<0 ||
   arraysTestIndex(infos,"dst",0)<0 || arraysTestIndex(infos,"src",0)<0 ||
   arraysTestIndex(infos,"proto",0)<0){ arraysFreeArray(infos); return 1; }
unsigned char *data=(unsigned char *)arraysGetValue(infos,"data",NULL,0);
int data_size=*((int *)arraysGetValue(infos,"size",NULL,0));
EthernetAddress dst=*((EthernetAddress *)arraysGetValue(infos,"dst",NULL,0));
EthernetAddress src=*((EthernetAddress *)arraysGetValue(infos,"src",NULL,0));
short int proto=*((short int *)arraysGetValue(infos,"proto",NULL,0));
arraysFreeArray(infos);
EthernetInterface *intf=stackFindDeviceByAddr(src);
if(intf==NULL){ free(data); return 0; }
int offset=sizeof(Ethernet_fields)-1;
int size=offset+data_size;
data=(unsigned char *)realloc(data,size);
if(data==NULL){ printf("%s",RED);perror("ethernetSendPacket.realloc"); printf("%s",BLACK); return 1; }
memmove(data+offset,data,data_size);
Ethernet_fields *fields=(Ethernet_fields *)data;
fields->target=dst;
fields->sender=src;
fields->protocol=htons(proto);
#ifdef VERBOSE
fprintf(stderr,"\n%s >>>>>  Outgoing Ethernet packet (intf=%s) >>>>>%s\n", BMAGENTA, intf->name_int, BLACK);
displayEthernetPacket(stderr,fields,data_size);
#endif
int sent=write(intf->descriptor,data,size);
free(data);
if(sent==size) return 0; else return 1;
}

//
// Generic checksum computation
//

unsigned short int genericChecksum(unsigned char *bytes,int size){
long int checksum=0;
int i;
for(i=0;i<size;i += 2){
  unsigned char b1=bytes[i];
  unsigned char b2=(i+1<size)?bytes[i+1]:0;
  checksum += b1<<8 | b2;
  }
while(checksum>>16) checksum=(checksum&0xffff)+(checksum>>16);
return ~(unsigned short int)checksum;
}

//
// Convert string to Ethernet address
//

EthernetAddress ethernetString2Address(char *string){
EthernetAddress address;
int i;
for(i=0;i<ETHERNET_ADDRESS_SIZE;i++){
  if(sscanf(string,"%hhx",address.bytes+i)!=1) break;
  string=strchr(string,':');
  if(string==NULL) break;
  string++;
  }
if(i<ETHERNET_ADDRESS_SIZE-1) return ETHERNET_ADDRESS_NULL;
return address;
}

//
// Convert Ethernet address to string
//

char *ethernetAddress2String(EthernetAddress ethernet){
static char string[ETHERNET_STRING_MAX];
string[0]='\0';
int i;
for(i=0;i<ETHERNET_ADDRESS_SIZE;i++){
  char byte[ETHERNET_STRING_MAX];
  sprintf(byte,"%02x",ethernet.bytes[i]);
  strcat(string,byte);
  if(i<ETHERNET_ADDRESS_SIZE-1) strcat(string,":");
  }
return string;
}

//
// Convert array to Ethernet address
//

EthernetAddress ethernetArray2Address(unsigned char *array){
EthernetAddress address;
int i;
for(i=0;i<ETHERNET_ADDRESS_SIZE;i++) address.bytes[i]=array[i];
return address;
}

//
// Convert Ethernet address to array
//

void ethernetAddress2Array(EthernetAddress ethernet,unsigned char *field){
int i;
for(i=0;i<ETHERNET_ADDRESS_SIZE;i++) field[i]=ethernet.bytes[i];
}

//
// Compare two Ethernet addresses
//

unsigned char ethernetCompare(EthernetAddress a1,EthernetAddress a2){
unsigned char result=1;
int i;
for(i=0;i<ETHERNET_ADDRESS_SIZE;i++)
  if(a1.bytes[i]!=a2.bytes[i]){ result=0; break; }
return result;
}

//
// Test Ethernet addresses
//

unsigned char ethernetBroadcast(EthernetAddress address){
unsigned char result=1;
int i;
for(i=0;i<ETHERNET_ADDRESS_SIZE;i++)
  if(address.bytes[i]!=0xff){ result=0; break; }
return result;
}

unsigned char ethernetMulticast(EthernetAddress address){
return address.bytes[0] & 0x01;
}

unsigned char ethernetUnicast(EthernetAddress address){
return !ethernetMulticast(address);
}

