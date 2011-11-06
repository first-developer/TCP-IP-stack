/*
 * Code for IP protocol implementation
 */

////
// Include files
////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <libarrays.h>
#include <libevents.h>

#include "netether.h"
#include "netip.h"
#include "neticmp.h"
#include "stack.h"

////
// Global variables
////

IPv4Address IPV4_ADDRESS_NULL={{0x00,0x00,0x00,0x00}};
IPv4Address IPV4_ADDRESS_BROADCAST={{0xFF,0x0FF,0xFF,0xFF}};

////
// Prototypes
////

static int ipFillHeader(
       unsigned char **packet,AssocArray *headers,AssocArray *options);

////
// Functions
////

//
// Display IPv4 packet
//

#ifdef VERBOSE
#define	MAX_BYTES_BY_ROW	16
void displayIPv4Packet(FILE *output,IPv4_fields *ip,int size){
int hlength=4*IPv4_get_hlength(ip);
unsigned char *options=ip->options;
unsigned char *start=(unsigned char *)ip;
unsigned char *data=start+hlength;
fprintf(output,"IPv4 Version: %d\n",IPv4_get_version(ip));
fprintf(output,"IPv4 Header length: %d bytes\n",hlength);
fprintf(output,"IPv4 Services: %02hhx\n",ip->diffserv);
fprintf(output,"IPv4 Packet length: %d bytes\n",ntohs(ip->length));
fprintf(output,"IPv4 Fragmentation: id=%02x, ",ip->id);
fprintf(output,"flags=%01x, ",IPv4_get_flags(ip));
fprintf(output,"offset=%d\n",IPv4_get_offset(ip));
fprintf(output,"IPv4 Time to live: %01x\n",ip->ttl);
fprintf(output,"IPv4 Protocol: %02x\n",ip->protocol);
fprintf(output,"IPv4 Checksum: %04x\n",ntohs(ip->checksum));
fprintf(output,"IPv4 Source: %s\n",ipAddress2String(ip->source));
fprintf(output,"IPv4 Target: %s\n",ipAddress2String(ip->target));
for(start=options;start<data;){
  IPv4_option_fields *option=(IPv4_option_fields *)start;
  if(option->code<2){
    fprintf(output,"IPv4 Option #%d\n",option->code);
    start++;
    }
  else{
    fprintf(output,"IPv4 Option #%d (length=%d)\n",
                    option->code,option->length);
    if(option->length>2) fprintf(output,"  ");
    int i;
    for(i=0;i<option->length-2;i++){
      fprintf(output,"%02x ",option->data[i]);
      if(i%MAX_BYTES_BY_ROW == MAX_BYTES_BY_ROW-1){
        fprintf(output,"\n");
        if(i<option->length-1) fprintf(output,"  ");
        }
      }
    if(i%MAX_BYTES_BY_ROW != 0) fprintf(output,"\n");
    start += option->length;
    }
  }
fprintf(output,"IPv4 Data:\n");
int i;
int size_data=ntohs(ip->length)-hlength;
if(size_data>0) fprintf(output,"  ");
for(i=0;i<size_data;i++){
  fprintf(output,"%02x ",data[i]);
  if(i%MAX_BYTES_BY_ROW == MAX_BYTES_BY_ROW-1){
    fprintf(output,"\n");
    if(i<size_data-1) fprintf(output,"  ");
    }
  }
if(i%MAX_BYTES_BY_ROW != 0) fprintf(output,"\n");
}
#endif

//
// Decode IPv4 packet
//

unsigned char ipDecodePacket(EventsEvent *event,EventsSelector *selector){
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"data",0)<0 || arraysTestIndex(infos,"size",0)<0)
  { arraysFreeArray(infos); return 1; }
unsigned char *data=(unsigned char *)arraysGetValue(infos,"data",NULL,0);
int size=*((int *)arraysGetValue(infos,"size",NULL,0));
arraysFreeArray(infos);
IPv4_fields *ip=(IPv4_fields *)data;
unsigned short int checksum=genericChecksum(data,4*IPv4_get_hlength(ip));
if(checksum!=0){
#ifdef VERBOSE
  fprintf(stderr,"IP packet: bad checksum !\n");
#endif
  free(data); return 0;
  }
if(ip->ttl==0){
#ifdef VERBOSE
  fprintf(stderr,"IP packet: null TTL !\n");
#endif	
	// ------------------------------------------------------------------
	// Sending ICMP Time exceeded packet to the sender if ip->ttl == 0 
	// ------------------------------------------------------------------

	// Get the layer related to the sender
	StackLayers *picmp=stackFindProtoById(LEVEL_TRANSPORT,IPV4_PROTOCOL_ICMP);
		
	// Verify if everything work fine after the 'stackFindProtoById' call
	if(picmp!=NULL && picmp->event_out>=0){
		
		// Set the type of the ICMP message (ICMPV4_TYPE_TIME_EXCEEDED: 11)
  	unsigned char type= ICMPV4_TYPE_TIME_EXCEEDED;
		  
 		// Set the type of the ICMP message (ICMPV4_UNREACHABLE_CODE_NETWORK: 0)
  	unsigned char code= ICMPV4_CODE_NONE;
		
		//  Get src address and data of the datagram sent
		IPv4Address source=ip->source;
		int reply_size=(IPv4_get_hlength(ip)+3)*4;
		data=(unsigned char *)realloc(data,reply_size);
		if(data==NULL){ perror("ipDecodePacket.realloc"); return 1; }
		memmove(data,data,reply_size);
    

		// Initialized and set the icmp packet to replay
		AssocArray *icmp_infos=NULL;
		arraysSetValue(&icmp_infos,"type",&type,sizeof(unsigned char),0);
		arraysSetValue(&icmp_infos,"code",&code,sizeof(unsigned char),0);
		arraysSetValue(&icmp_infos,"data",data,reply_size,AARRAY_DONT_DUPLICATE);
		arraysSetValue(&icmp_infos,"size",&reply_size,sizeof(int),0);
		arraysSetValue(&icmp_infos,"ldst",&source,sizeof(IPv4Address),0);
		eventsTrigger(picmp->event_out,icmp_infos);
  }

  free(data); return 0;
  }
if(ntohs(ip->length)!=size){
#ifdef VERBOSE
  fprintf(stderr,"IP packet: bad size !\n");
#endif
  free(data); return 0;
  }
if(!ipCompare(ip->target,IPV4_ADDRESS_BROADCAST) &&
   stackFindDeviceByIPv4Broadcast(ip->target)!=NULL &&
   stackFindDeviceByIPv4(ip->target)!=NULL){
#ifdef VERBOSE
  fprintf(stderr,"IP packet: not for us !\n");
#endif
  free(data); return 0;
  }
#ifdef VERBOSE
/* TODO: handle fragments */
fprintf(stderr,"Incoming IP packet:\n");
displayIPv4Packet(stderr,ip,size);
#endif
int size_data=size;
StackLayers *layer=stackFindProtoById(LEVEL_TRANSPORT,ip->protocol);
if(layer!=NULL && layer->event_in>=0){
  int size_header=IPv4_get_hlength(ip)*4;
  unsigned char *iph=(unsigned char *)malloc(size_header);
  memcpy(iph,data,size_header);
  size_data=size-size_header;
  memmove(data,data+size_header,size_data);
  data=(unsigned char *)realloc(data,size_data);
  if(data==NULL){ perror("ipDecodePacket.realloc"); return 1; }
  AssocArray *infos=NULL;
  arraysSetValue(&infos,"data",data,size_data,AARRAY_DONT_DUPLICATE);
  arraysSetValue(&infos,"size",&size_data,sizeof(int),0);
  arraysSetValue(&infos,"iph",iph,size_header,AARRAY_DONT_DUPLICATE);
  eventsTrigger(layer->event_in,infos);
  }
else{
  StackLayers *picmp=stackFindProtoById(LEVEL_TRANSPORT,IPV4_PROTOCOL_ICMP);
  if(picmp!=NULL && picmp->event_out>=0){
    unsigned char type=ICMPV4_TYPE_UNREACHABLE;
    unsigned char code=ICMPV4_UNREACHABLE_CODE_PROTOCOL;
    IPv4Address source=ip->source;
    int reply_size=(IPv4_get_hlength(ip)+3)*4;
    data=(unsigned char *)realloc(data,reply_size);
    if(data==NULL){ perror("ipDecodePacket.realloc"); return 1; }
    memmove(data+4,data,reply_size-4);
    bzero(data,4);
    AssocArray *icmp_infos=NULL;
    arraysSetValue(&icmp_infos,"type",&type,sizeof(unsigned char),0);
    arraysSetValue(&icmp_infos,"code",&code,sizeof(unsigned char),0);
    arraysSetValue(&icmp_infos,"data",data,reply_size,AARRAY_DONT_DUPLICATE);
    arraysSetValue(&icmp_infos,"size",&reply_size,sizeof(int),0);
    arraysSetValue(&icmp_infos,"ldst",&source,sizeof(IPv4Address),0);
    eventsTrigger(picmp->event_out,icmp_infos);
    }
  else free(data);
  }
return 0;
}

//
// Send IPv4 packet
//

static int ipFillHeader( unsigned char **packet,AssocArray *headers,AssocArray *options){
if(arraysTestIndex(headers,"ldst",0)<0 ||
   arraysTestIndex(headers,"proto",0)<0 ||
   arraysTestIndex(headers,"size",0)<0)
  { arraysFreeArray(options); arraysFreeArray(headers); return -1; }
IPv4Address target=*((IPv4Address *)arraysGetValue(headers,"ldst",NULL,0));
unsigned char proto=*((unsigned char *)arraysGetValue(headers,"proto",NULL,0));
int size_data=*((int *)arraysGetValue(headers,"size",NULL,0));
arraysFreeArray(headers);
int size_options=0;
/* TODO: compute IPv4 options length    */
int len_hdr=sizeof(IPv4_fields)-1+size_options;
int len_pkt=len_hdr+size_data;
*packet=(unsigned char *)realloc(*packet,len_pkt);
if(*packet==NULL)
  { perror("ipFillHeader.realloc"); arraysFreeArray(options); return 1; }
memmove(*packet+len_hdr,*packet,size_data);
bzero(*packet,len_hdr);
IPv4_fields *ip=(IPv4_fields *)*packet;
if(arraysTestIndex(options,"lsrc",0)>=0)
  ip->source=*((IPv4Address *)arraysGetValue(options,"lsrc",NULL,0));
if(arraysTestIndex(options,"ttl",0)>=0)
  ip->ttl=*((unsigned char *)arraysGetValue(options,"ttl",NULL,0));
/* TODO: handle more IPv4 header tuning */
/* TODO: handle IPv4 options            */
IPv4_set_version(ip,IPV4_VERSION);
int hlength=(sizeof(IPv4_fields)-1+size_options)/4;
IPv4_set_hlength(ip,len_hdr/4);
ip->length=htons(len_pkt);
ip->target=target;
if(arraysTestIndex(options,"lsrc",0)<0){
  EthernetInterface *device=stackFindDeviceByIPv4Network(target);
  if(device==NULL) ip->source=IPV4_ADDRESS_NULL;
  else ip->source=device->IPv4[0].address;
  }
if(arraysTestIndex(options,"ttl",0)<0) ip->ttl=IPV4_DEFAULT_TTL;
arraysFreeArray(options);
ip->protocol=proto;
ip->checksum=htons(genericChecksum((unsigned char *)ip,4*hlength));
return len_pkt;
}

unsigned char ipSendPacket(EventsEvent *event,EventsSelector *selector){
/* Compute addresse sizes */
int msize=sizeof(EthernetAddress);
int lsize=sizeof(IPv4Address);

/* Get values from associative array */
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"ldst",0)<0 || arraysTestIndex(infos,"proto",0)<0 ||
   arraysTestIndex(infos,"data",0)<0 || arraysTestIndex(infos,"size",0)<0 ||
   arraysTestIndex(infos,"opts",0)<0)
  { arraysFreeArray(infos); return 1; }
StackLayers *pether=stackFindProtoById(LEVEL_LINK,0x0000);
if(pether==NULL || pether->event_out<0){ arraysFreeArray(infos); return 0; }
IPv4Address ipv4_target=*((IPv4Address *)arraysGetValue(infos,"ldst",NULL,0));
unsigned char protocol=*((unsigned char *)arraysGetValue(infos,"proto",NULL,0));
unsigned char *data=(unsigned char *)arraysGetValue(infos,"data",NULL,0);
int size_data=*((int *)arraysGetValue(infos,"size",NULL,0));
AssocArray *options=(AssocArray *)arraysGetValue(infos,"opts",NULL,0);

/* Try to resolve target IPv4 address    */
/* Reschedule packet if resolution fails */ 
EthernetInterface *device=stackFindDeviceByIPv4Network(ipv4_target);
if(device==NULL)
  { free(data); arraysFreeArray(options); arraysFreeArray(infos); return 0; }
EthernetAddress ether_target=stackAddressResolution(ipv4_target);
if(ethernetCompare(ether_target,ETHERNET_ADDRESS_NULL)){
  StackLayers *parp=stackFindProtoById(LEVEL_NETWORK,ETHERNET_PROTO_ARP);
  if(parp==NULL || parp->event_out<0)
    { free(data); arraysFreeArray(options); arraysFreeArray(infos); return 0; }
  int retrans=0;
  if(arraysTestIndex(infos,"try",0)>=0) 
    retrans=*((int *)arraysGetValue(infos,"try",NULL,0));
  if(retrans<IPV4_RETRANS_MAX){
    EthernetAddress msrc=device->ether_addr;
    IPv4Address lsrc=device->IPv4[0].address;
    short int protocol=ETHERNET_PROTO_ARP;
    AssocArray *arp_infos=NULL;
    arraysSetValue(&arp_infos,"mdst",&ETHERNET_ADDRESS_NULL,msize,0);
    arraysSetValue(&arp_infos,"msrc",&msrc,msize,0);
    arraysSetValue(&arp_infos,"ldst",&ipv4_target,lsize,0);
    arraysSetValue(&arp_infos,"lsrc",&lsrc,lsize,0);
    arraysSetValue(&arp_infos,"proto",&protocol,sizeof(short int),0);
    eventsTrigger(parp->event_out,arp_infos);
    retrans++;
    arraysSetValue(&infos,"try",&retrans,sizeof(int),0);
    eventsSchedule(event->identity,IPV4_RETRANS_WAIT_TIME,infos);
#ifdef VERBOSE
    fprintf(stderr,"Queued IP packet to %s.\n",ipAddress2String(ipv4_target));
#endif
    }
  else{
#ifdef VERBOSE
    fprintf(stderr,"Destroyed IP packet to %s\n",ipAddress2String(ipv4_target));
    fprintf(stderr,"  -> retransmitted %d times.\n",retrans+1);
#endif
    free(data); arraysFreeArray(options); arraysFreeArray(infos);
    }
  return 0;
  }
arraysFreeArray(infos);

/* Fill IP headers          */
/* TODO: fragment if needed */
AssocArray *headers=NULL;
arraysSetValue(&headers,"ldst",&ipv4_target,msize,0);
arraysSetValue(&headers,"proto",&protocol,sizeof(unsigned char),0);
arraysSetValue(&headers,"size",&size_data,sizeof(int),0);
int size=ipFillHeader(&data,headers,options);
if(size<0) return 1;
#ifdef VERBOSE
fprintf(stderr,"Outgoing IP packet:\n");
displayIPv4Packet(stderr,(IPv4_fields *)data,size);
#endif

/* Call Link layer */
short int ether_proto=ETHERNET_PROTO_IP;
AssocArray *ether_infos=NULL;
arraysSetValue(&ether_infos,"data",data,size,AARRAY_DONT_DUPLICATE);
arraysSetValue(&ether_infos,"size",&size,sizeof(int),0);
arraysSetValue(&ether_infos,"dst",&ether_target,msize,0);
arraysSetValue(&ether_infos,"src",&(device->ether_addr),msize,0);
arraysSetValue(&ether_infos,"proto",&ether_proto,sizeof(short int),0);
eventsTrigger(pether->event_out,ether_infos);

return 0;
}

//
// Compute network mask
//

IPv4Address ipNetmask(int mask){
int i;
IPv4Address addr;
for(i=0;i<IPV4_ADDRESS_SIZE;i++){
  int local=(mask>8)?8:mask; 
  addr.bytes[i]=(1<<local)-1;
  mask=mask-local;
  }
return addr;
}

//
// Compute network address
//

IPv4Address ipNetwork(IPv4Address ip,int mask){
IPv4Address netmask=ipNetmask(mask);
IPv4Address result;
int i;
for(i=0;i<IPV4_ADDRESS_SIZE;i++)
  result.bytes[i]=(ip.bytes[i]&netmask.bytes[i]);
return result;
}

//
// Compute broadcast address
//

IPv4Address ipBroadcast(IPv4Address ip,int mask){
IPv4Address network=ipNetwork(ip,mask);
IPv4Address netmask=ipNetmask(mask);
IPv4Address result;
int i;
for(i=0;i<IPV4_ADDRESS_SIZE;i++)
  result.bytes[i]=(network.bytes[i]|~netmask.bytes[i]);
return result;
}

//
// Compare IP addresses
//

unsigned char ipCompare(IPv4Address ip1,IPv4Address ip2){
unsigned char result=1;
int i;
for(i=0;i<IPV4_ADDRESS_SIZE;i++)
  if(ip1.bytes[i]!=ip2.bytes[i]){ result=0; break; }
return result;
}

//
// Convert string to IPv4 address
//

IPv4Address ipString2Address(char *string){
IPv4Address address;
int i;
for(i=0;i<IPV4_ADDRESS_SIZE;i++){
  if(sscanf(string,"%hhd",address.bytes+i)!=1) break;
  string=strchr(string,'.');
  if(string==NULL) break;
  string++;
  }
if(i<IPV4_ADDRESS_SIZE-1) return IPV4_ADDRESS_NULL;
return address;
}

//
// Convert IPv4 address to string
//

char *ipAddress2String(IPv4Address ip){
static char string[IPV4_STRING_MAX];
string[0]='\0';
int i;
for(i=0;i<IPV4_ADDRESS_SIZE;i++){
  char byte[IPV4_STRING_MAX];
  sprintf(byte,"%d",ip.bytes[i]);
  strcat(string,byte);
  if(i<IPV4_ADDRESS_SIZE-1) strcat(string,".");
  }
return string;
}

//
// Convert array to IPv4 address
//

IPv4Address ipArray2Address(unsigned char *array){
IPv4Address address;
int i;
for(i=0;i<IPV4_ADDRESS_SIZE;i++) address.bytes[i]=array[i];
return address;
}

//
// Convert IPv4 address to packet field
//

void ipAddress2Array(IPv4Address ip,unsigned char *field){
int i;
for(i=0;i<IPV4_ADDRESS_SIZE;i++) field[i]=ip.bytes[i];
}

//
// Compute checksum with pseudo header
//

unsigned short int pseudoHeaderChecksum(
  IPv4Address source,IPv4Address target,
  unsigned char protocol,unsigned char **bytes,int size){
int size_phdr=sizeof(IPv4_pseudo_header);
int size_total=size+size_phdr;
*bytes=(unsigned char *)realloc(*bytes,size_total);
if(*bytes==NULL){ perror("pseudoHeaderChecksum.realloc"); exit(-1); }
memmove(*bytes+size_phdr,*bytes,size);
IPv4_pseudo_header *pheader=(IPv4_pseudo_header *)*bytes;
pheader->source=source;
pheader->target=target;
pheader->zero=0x00;
pheader->protocol=protocol;
pheader->length=htons((short int)size);
unsigned short int checksum=genericChecksum(*bytes,size_total);
memmove(*bytes,*bytes+size_phdr,size);
*bytes=(unsigned char *)realloc(*bytes,size);
if(*bytes==NULL){ perror("pseudoHeaderChecksum.realloc"); exit(-1); }
return checksum;
}
