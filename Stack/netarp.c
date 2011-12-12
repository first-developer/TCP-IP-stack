/*
 * Code for ARP/RARP protocol implementation
 */

////
// Include files
////

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

#include <libarrays.h>
#include <libevents.h>

#include "netether.h"
#include "netip.h"
#include "netarp.h"
#include "stack.h"

////
// Global variables
////

static ARP_cache *cache=NULL;

////
// Functions
////

#ifdef VERBOSE
//
// Display ARP packet
//

void displayARPPacket(FILE *output,ARP_fields *arp,int size){
unsigned char *addresses=arp->addresses;
EthernetAddress eth_sender=ethernetArray2Address(addresses);
addresses += ETHERNET_ADDRESS_SIZE;
IPv4Address ipv4_sender=ipArray2Address(addresses);
addresses += IPV4_ADDRESS_SIZE;
EthernetAddress eth_target=ethernetArray2Address(addresses);
addresses += ETHERNET_ADDRESS_SIZE;
IPv4Address ipv4_target=ipArray2Address(addresses);
int opcode=ntohs(arp->opcode);
char *opname="unknown";
switch(opcode){
  case ARP_OPCODE_REQUEST: opname="request"; break;
  case ARP_OPCODE_ANSWER: opname="answer"; break;
  case RARP_OPCODE_REQUEST: opname="reverse request"; break;
  case RARP_OPCODE_ANSWER: opname="reverse answer"; break;
  }
fprintf(stderr,"%sARP Operation: %s%s\n", BLUE, opname, BLACK);
fprintf(stderr,"%sARP Sender Ethernet Address: %s%s\n", BLUE,
                ethernetAddress2String(eth_sender),BLACK );
fprintf(stderr,"%sARP Sender IPv4 Address: %s%s\n", BLUE, ipAddress2String(ipv4_sender), BLACK);
fprintf(stderr,"%sARP Target Ethernet Address: %s%s\n", BLUE,
                ethernetAddress2String(eth_target), BLACK);
fprintf(stderr,"%sARP Target IPv4 Address: %s%s\n",BLUE, ipAddress2String(ipv4_target), BLACK);
}
#endif

//
// Decode ARP packet
//

unsigned char arpDecodePacket(EventsEvent *event,EventsSelector *selector){
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"data",0)<0 || arraysTestIndex(infos, "size",0)<0)
  { arraysFreeArray(infos); return 1; }
unsigned char *data=(unsigned char *)arraysGetValue(infos,"data",NULL,0);
int data_size=*((int *)arraysGetValue(infos,"size",NULL,0));
arraysFreeArray(infos);
StackLayers *parp=stackFindProtoById(LEVEL_NETWORK,ETHERNET_PROTO_ARP);
if(parp==NULL || parp->event_out<0){ free(data); return 0; }
ARP_fields *fields=(ARP_fields *)data;
if(ntohs(fields->hw_type)!=ARP_HW_TYPE_ETHERNET || 
   ntohs(fields->proto_type)!=ARP_PROTO_TYPE_IPV4)
  { free(data); return 0; }
#ifdef VERBOSE
fprintf(stderr,"\n%s<<<<<   Incoming (R)ARP packet: <<<<< %s\n", BGREEN, BLACK);
displayARPPacket(stderr,fields,data_size);
#endif
EthernetAddress eth_sender,eth_target;
IPv4Address ipv4_sender,ipv4_target;
int msize=sizeof(EthernetAddress);
int lsize=sizeof(IPv4Address);
int offset=sizeof(ARP_fields)-1;
eth_sender=ethernetArray2Address(data+offset);
offset += ETHERNET_ADDRESS_SIZE;
ipv4_sender=ipArray2Address(data+offset);
offset += IPV4_ADDRESS_SIZE;
eth_target=ethernetArray2Address(data+offset);
offset += ETHERNET_ADDRESS_SIZE;
ipv4_target=ipArray2Address(data+offset);
int opcode=htons(fields->opcode);
free(data);
if(opcode==ARP_OPCODE_REQUEST){
  EthernetInterface *device=stackFindDeviceByIPv4(ipv4_target);
  if(device!=NULL){
    EthernetAddress msrc=device->ether_addr;
    short int protocol=ETHERNET_PROTO_ARP;
    AssocArray *arp_infos=NULL;
    arraysSetValue(&arp_infos,"mdst",&eth_sender,msize,0);
    arraysSetValue(&arp_infos,"msrc",&msrc,msize,0);
    arraysSetValue(&arp_infos,"ldst",&ipv4_sender,lsize,0);
    arraysSetValue(&arp_infos,"lsrc",&ipv4_target,lsize,0);
    arraysSetValue(&arp_infos,"proto",&protocol,sizeof(short int),0);
    eventsTrigger(parp->event_out,arp_infos);
    }
  }
if(opcode==RARP_OPCODE_REQUEST){
  EthernetInterface *device=stackFindDeviceByAddr(eth_target);
  if(device!=NULL){
    IPv4Address lsrc=device->IPv4[0].address;
    EthernetAddress msrc=device->ether_addr;
    short int protocol=ETHERNET_PROTO_RARP;
    AssocArray *arp_infos=NULL;
    arraysSetValue(&arp_infos,"mdst",&eth_sender,msize,0);
    arraysSetValue(&arp_infos,"msrc",&msrc,msize,0);
    arraysSetValue(&arp_infos,"ldst",&ipv4_target,lsize,0);
    arraysSetValue(&arp_infos,"lsrc",&lsrc,lsize,0);
    arraysSetValue(&arp_infos,"proto",&protocol,sizeof(short int),0);
    eventsTrigger(parp->event_out,arp_infos);
    }
  }
if(opcode==ARP_OPCODE_ANSWER)
  arpAddToCache(ipv4_sender,eth_sender,0);
return 0;
}

//
// Send ARP packet
//

unsigned char arpSendPacket(EventsEvent *event,EventsSelector *selector){
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"mdst",0)<0 || arraysTestIndex(infos,"msrc",0)<0 ||
   arraysTestIndex(infos,"ldst",0)<0 || arraysTestIndex(infos,"lsrc",0)<0 ||
   arraysTestIndex(infos,"proto",0)<0)
  { arraysFreeArray(infos); return 1; }
StackLayers *pether=stackFindProtoById(LEVEL_LINK,0x0000);
if(pether==NULL || pether->event_out<0){ arraysFreeArray(infos); return 0; }
EthernetAddress mdst=*((EthernetAddress *)arraysGetValue(infos,"mdst",NULL,0));
EthernetAddress msrc=*((EthernetAddress *)arraysGetValue(infos,"msrc",NULL,0));
IPv4Address ldst=*((IPv4Address *)arraysGetValue(infos,"ldst",NULL,0));
IPv4Address lsrc=*((IPv4Address *)arraysGetValue(infos,"lsrc",NULL,0));
short int protocol=*((short int *)arraysGetValue(infos,"proto",NULL,0));
arraysFreeArray(infos);
int size=sizeof(ARP_fields)-1+2*ETHERNET_ADDRESS_SIZE+2*IPV4_ADDRESS_SIZE;
unsigned char *packet=(unsigned char *)malloc(size);
ARP_fields *fields=(ARP_fields *)packet;
fields->hw_type=htons(ARP_HW_TYPE_ETHERNET);
fields->proto_type=htons(ARP_PROTO_TYPE_IPV4);
fields->hw_addr_len=ETHERNET_ADDRESS_SIZE;
fields->proto_addr_len=IPV4_ADDRESS_SIZE;
unsigned char arp_request=ethernetCompare(mdst,ETHERNET_ADDRESS_NULL);
unsigned char rarp_request=ipCompare(ldst,IPV4_ADDRESS_NULL);
int opcode;
if(protocol==ETHERNET_PROTO_ARP)
  opcode=arp_request?ARP_OPCODE_REQUEST:ARP_OPCODE_ANSWER;
if(protocol==ETHERNET_PROTO_RARP)
  opcode=rarp_request?RARP_OPCODE_REQUEST:RARP_OPCODE_ANSWER;
fields->opcode=htons(opcode);
int offset=sizeof(ARP_fields)-1;
ethernetAddress2Array(msrc,packet+offset);
offset += ETHERNET_ADDRESS_SIZE;
ipAddress2Array(lsrc,packet+offset);
offset += IPV4_ADDRESS_SIZE;
ethernetAddress2Array(mdst,packet+offset);
offset += ETHERNET_ADDRESS_SIZE;
ipAddress2Array(ldst,packet+offset);
offset += IPV4_ADDRESS_SIZE;
#ifdef VERBOSE
fprintf(stderr,"\n %s>>>>>   Outgoing ARP packet:>>>>>%s\n", BMAGENTA, BLACK);
displayARPPacket(stderr,fields,offset);
#endif
EthernetAddress edst=mdst;
if(ethernetCompare(mdst,ETHERNET_ADDRESS_NULL)){
  edst=ETHERNET_ADDRESS_BROADCAST;
  arpAddToCache(ldst,ETHERNET_ADDRESS_NULL,1);
  }
AssocArray *ether_infos=NULL;
arraysSetValue(&ether_infos,"data",packet,size,AARRAY_DONT_DUPLICATE);
arraysSetValue(&ether_infos,"size",&size,sizeof(int),0);
arraysSetValue(&ether_infos,"dst",&edst,sizeof(EthernetAddress),0);
arraysSetValue(&ether_infos,"src",&msrc,sizeof(EthernetAddress),0);
arraysSetValue(&ether_infos,"proto",&protocol,sizeof(short int),0);
eventsTrigger(pether->event_out,ether_infos);
return 0;
}

//
// Display ARP informations in stack
//

#ifdef VERBOSE
void arpDisplay(FILE *output){
int i;
time_t now=time(NULL);
for(i=0;i<cache->size;i++){
  int delta=now-cache->entries[i].timestamp;
  char *ip=ipAddress2String(cache->entries[i].ipv4);
  char *ether=ethernetAddress2String(cache->entries[i].ethernet);
  fprintf(output,"%s%s at %s (age=%ds)%s\n",BLUE, ip,ether,delta, BLACK);
  }
}
#endif

//
// Purge ARP cache
//

void arpPurgeCache(){
int i,j;
time_t now=time(NULL);
if(cache==NULL) return;
for(i=0;i<cache->size;i++){
  int delta=now-cache->entries[i].timestamp;
  if(delta>ARP_CACHE_TIMEOUT){
    for(j=i+1;j<cache->size;j++) cache->entries[j-1]=cache->entries[j];
    cache->size--; i--;
    }
  }
}

//
// Add entry to ARP cache
//

void arpAddToCache(IPv4Address ip,EthernetAddress ether,unsigned char force){
time_t now=time(NULL);
int i;
arpPurgeCache();
if(cache==NULL){
  cache=(ARP_cache *)malloc(sizeof(ARP_cache));
  cache->allocated=0;
  cache->size=0;
  cache->entries=NULL;
  }
for(i=0;i<cache->size;i++)
  if(ipCompare(ip,cache->entries[i].ipv4)){
    cache->entries[i].ethernet=ether;
    cache->entries[i].timestamp=now;
    return;
    }
if(i>=cache->size){
  if(!force) return;
  cache->size++;
  }
if(i>=cache->allocated){
  cache->allocated++;
  cache->entries=
    (ARP_cache_entry *)realloc(cache->entries,
                               cache->allocated*sizeof(ARP_cache_entry));
  if(cache->entries==NULL){ printf("%s", RED);perror("arpAddToCache.realloc"); printf("%s", BLACK);exit(-1); }
  }
cache->entries[i].ipv4=ip;
cache->entries[i].ethernet=ether;
cache->entries[i].timestamp=now;
#ifdef VERBOSE
arpDisplay(stderr);
#endif
}

//
// Find entry in ARP cache
//

EthernetAddress arpFindInCache(IPv4Address ip){
int i;
arpPurgeCache();
if(cache!=NULL)
  for(i=0;i<cache->size;i++)
    if(ipCompare(ip,cache->entries[i].ipv4))
      return cache->entries[i].ethernet;
return ETHERNET_ADDRESS_NULL;
}

IPv4Address arpReverseFindInCache(EthernetAddress ethernet){
int i;
arpPurgeCache();
if(cache!=NULL)
  for(i=0;i<cache->size;i++)
    if(ethernetCompare(ethernet,cache->entries[i].ethernet))
      return cache->entries[i].ipv4;
return IPV4_ADDRESS_NULL;
}

