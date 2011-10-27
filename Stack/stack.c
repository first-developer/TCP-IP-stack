/*
 * Code for virtual machine
 */

////
// Include files
////

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_tun.h>

#include <libarrays.h>
#include <libevents.h>
#include <libtap.h>

#include "netether.h"
#include "netip.h"
#include "netarp.h"
#include "neticmp.h"
#include "netudp.h"
#include "stack.h"

#include "processes.h"

////
// Constants
////

#define EVENTS_PRIORITY_DEVICE	0
#define EVENTS_PRIORITY_LAYER	10
#define EVENTS_PRIORITY_PROCESS	20

////
// Global variables
////

static SocketAddress localAddr;

static NetworkAddressesIPv4 eth0_ipv4[]={
    { {{192,168,100,100}}, 24 },
    { {{0,0,0,0}}, 0 }
  };

static EthernetInterface interfaces[]={
  {-1,"eth0","",-1,{{0x00,0x01,0x02,0x03,0x04,0x05}},eth0_ipv4},
  {-1,""}
  };

static AddressResolutionModule resolvModules[]={{arpFindInCache},{NULL}};

static StackLayers stackLayers[]={
  {LEVEL_LINK,0x0000,NULL,ethernetSendPacket,-1,-1},
  {LEVEL_NETWORK,ETHERNET_PROTO_IP,ipDecodePacket,ipSendPacket,-1,-1},
  {LEVEL_NETWORK,ETHERNET_PROTO_ARP,arpDecodePacket,arpSendPacket,-1,-1},
  {LEVEL_NETWORK,ETHERNET_PROTO_RARP,arpDecodePacket,arpSendPacket,-1,-1},
  {LEVEL_TRANSPORT,IPV4_PROTOCOL_ICMP,NULL,NULL,-1,-1},
  {LEVEL_TRANSPORT,IPV4_PROTOCOL_UDP,udpDecodePacket,udpSendPacket,-1,-1},
  {LEVEL_TRANSPORT,IPV4_PROTOCOL_TCP,NULL,NULL,-1,-1},
  {-1,-1,NULL,NULL,-1,-1}
  };

static StackProcess stackProcess[]={
  {IPV4_PROTOCOL_UDP,{{0,0,0,0}},4000,udp_echo,-1},
  {0,{{0,0,0,0}},0,NULL,-1}
  };

////
// Prototypes
////

static void stackInitializeDevices(void);
static void stackInitializeLayers(void);
static unsigned char stackUDPHandleDatagram(
  EventsEvent *event,EventsSelector *selector);
static void stackInitializeProcesses(void);

////
// Functions on network interface structure
////

//
// Find a network interface structure by address
//
EthernetInterface *stackFindDeviceByAddr(EthernetAddress src){
int i=0;
while(interfaces[i].name_int[0]!='\0'){
  if(ethernetCompare(interfaces[i].ether_addr,src))
    return interfaces+i;
  i++;
  }
return NULL;
}

//
// Find a network interface structure by name
//
EthernetInterface *stackFindDeviceByName(char *name){
int i=0;
while(interfaces[i].name_int[0]!='\0'){
  if(strcmp(interfaces[i].name_int,name)==0)
    return interfaces+i;
  i++;
  }
return NULL;
}

//
// Find a network interface structure by IPv4 address
//
EthernetInterface *stackFindDeviceByIPv4(IPv4Address ip){
int i=0;
while(interfaces[i].name_int[0]!='\0'){
  int j=0;
  while(!ipCompare(interfaces[i].IPv4[j].address,IPV4_ADDRESS_NULL)){
    if(ipCompare(interfaces[i].IPv4[j].address,ip)) return interfaces+i;
    j++;
    }
  i++;
  }
return NULL;
}

//
// Find a network interface structure by IPv4 broadcast
//
EthernetInterface *stackFindDeviceByIPv4Broadcast(IPv4Address ip){
int i=0;
while(interfaces[i].name_int[0]!='\0'){
  int j=0;
  while(!ipCompare(interfaces[i].IPv4[j].address,IPV4_ADDRESS_NULL)){
    IPv4Address bdc=ipBroadcast(interfaces[i].IPv4[j].address,
                                interfaces[i].IPv4[j].netmask);
    if(ipCompare(bdc,ip)) return interfaces+i;
    j++;
    }
  i++;
  }
return NULL;
}

//
// Find a network interface structure by IPv4 network
//
EthernetInterface *stackFindDeviceByIPv4Network(IPv4Address ip){
int i=0;
while(interfaces[i].name_int[0]!='\0'){
  int j=0;
  while(!ipCompare(interfaces[i].IPv4[j].address,IPV4_ADDRESS_NULL)){
    IPv4Address inet=ipNetwork(ip,interfaces[i].IPv4[j].netmask);
    IPv4Address tnet=ipNetwork(interfaces[i].IPv4[j].address,
                               interfaces[i].IPv4[j].netmask);
    if(ipCompare(inet,tnet)) return interfaces+i;
    j++;
    }
  i++;
  }
return NULL;
}

//
// Open network interfaces
//
static void stackInitializeDevices(void){
int i=0;
while(interfaces[i].name_int[0]!='\0'){
  int ether_in=eventsCreate(EVENTS_PRIORITY_DEVICE,&(interfaces[i]));
  eventsAddAction(ether_in,ethernetDecodePacket,0);
  strcpy(interfaces[i].name_tap,"");
  int tap=allocateNetworkDevice(interfaces[i].name_tap,IFF_TAP|IFF_NO_PI);
  if(tap<0){
    fprintf(stderr,"Cannot open %s TAP interface!\n",interfaces[i].name_int);
    exit(-1);
    }
  eventsAssociateDescriptor(ether_in,tap,NULL);
  interfaces[i].descriptor=tap;
  interfaces[i].ether_in=ether_in;
  i++;
  }
}

//
// Display network interfaces structure
//
void stackDisplayDevices(FILE *output){
int i=0;
while(interfaces[i].name_int[0]!='\0'){
  fprintf(output,"Interface %s :\n",interfaces[i].name_int);
  fprintf(output,"  TAP=%s",interfaces[i].name_tap); 
  fprintf(output," MAC=%s\n",ethernetAddress2String(interfaces[i].ether_addr)); 
  fprintf(output,"  IPv4="); 
  int j=0;
  while(!ipCompare(interfaces[i].IPv4[j].address,IPV4_ADDRESS_NULL)){
    if(j>0) fprintf(output,",");
    fprintf(output,"%s",ipAddress2String(interfaces[i].IPv4[j].address));
    fprintf(output,"/%d",interfaces[i].IPv4[j].netmask);
    j++;
    }
  fprintf(output,"\n"); 
  i++;
  }
}

////
// Functions on layer structure
////

//
// Find a protocol by ID
//
StackLayers *stackFindProtoById(int level,int id){
int i=0;
while(stackLayers[i].level>=0){
  if(stackLayers[i].level==level && stackLayers[i].identity==id)
    return stackLayers+i;
  i++;
  }
return NULL;
}

//
// Initialize stack layers
//
static void stackInitializeLayers(void){
int i=0;
while(stackLayers[i].level>=0){
  if(stackLayers[i].action_in!=NULL){
    int e=eventsCreate(EVENTS_PRIORITY_LAYER,NULL);
    eventsAddAction(e,stackLayers[i].action_in,0);
    stackLayers[i].event_in=e;
    }
  if(stackLayers[i].action_out!=NULL){
    int e=eventsCreate(EVENTS_PRIORITY_LAYER,NULL);
    eventsAddAction(e,stackLayers[i].action_out,0);
    stackLayers[i].event_out=e;
    }
  i++;
  }
}

////
// Functions on address resolution 
////

//
// Resolve IPv4 address into Ethernet address
//
EthernetAddress stackAddressResolution(IPv4Address address){
int i=0;
while(resolvModules[i].function!=NULL){
  return resolvModules[i].function(address);
  i++;
  }
return ETHERNET_ADDRESS_BROADCAST;
}

////
// Functions about processes
////

//
// Find a specific process 
//
StackProcess *stackFindProcess(
  unsigned char protocol,IPv4Address address,short int port){
int i=0;
while(stackProcess[i].process!=NULL){
  if(stackProcess[i].protocol==protocol &&
     (ipCompare(stackProcess[i].address,IPV4_ADDRESS_NULL) ||
      ipCompare(stackProcess[i].address,address)) &&
     stackProcess[i].port==port)
    return stackProcess+i;
  i++;
  }
return NULL;
}

//
// Function used by processes to send UDP datagram
//
unsigned char stackUDPSendDatagram(
  IPv4Address to_ip,short int to_port,unsigned char *data,int size){
StackLayers *pudp=stackFindProtoById(LEVEL_TRANSPORT,IPV4_PROTOCOL_UDP);
if(pudp==NULL || pudp->event_out<0) return 1;
if(localAddr.port==0){ perror("stackUDPSendDatagram"); exit(-1); }
AssocArray *udp_infos=NULL;
arraysSetValue(&udp_infos,"ldst",&to_ip,sizeof(IPv4Address),0);
arraysSetValue(&udp_infos,"pdst",&to_port,sizeof(short int),0);
arraysSetValue(&udp_infos,"psrc",&localAddr.port,sizeof(short int),0);
arraysSetValue(&udp_infos,"data",data,size,AARRAY_DONT_DUPLICATE);
arraysSetValue(&udp_infos,"size",&size,sizeof(int),0);
eventsTrigger(pudp->event_out,udp_infos);
return 0;
}

//
// Function triggering process for UDP datagram processing
//
static unsigned char stackUDPHandleDatagram(
  EventsEvent *event,EventsSelector *selector){
StackProcess *process=(StackProcess *)event->data_init;
AssocArray *infos=(AssocArray *)selector->data_this;
if(arraysTestIndex(infos,"ldst",0)<0 || arraysTestIndex(infos,"pdst",0)<0 ||
   arraysTestIndex(infos,"lsrc",0)<0 || arraysTestIndex(infos,"psrc",0)<0 ||
   arraysTestIndex(infos,"data",0)<0 || arraysTestIndex(infos,"size",0)<0 ||
   arraysTestIndex(infos,"type",0)<0)
  { arraysFreeArray(infos); return 0; }
SocketAddress from;
localAddr.address=*((IPv4Address *)arraysGetValue(infos,"ldst",NULL,0));
from.address=*((IPv4Address *)arraysGetValue(infos,"lsrc",NULL,0));
localAddr.port=ntohs(*((short int *)arraysGetValue(infos,"pdst",NULL,0)));
from.port=ntohs(*((short int *)arraysGetValue(infos,"psrc",NULL,0)));
unsigned char type=*((unsigned char *)arraysGetValue(infos,"type",NULL,0));
unsigned char *data=(unsigned char *)arraysGetValue(infos,"data",NULL,0);
int size=*((int *)arraysGetValue(infos,"size",NULL,0));
arraysFreeArray(infos);
int status=process->process(type,localAddr,from,data,size);
localAddr.port=0;
if(status!=0) process->event=-1;
return status;
}

//
// Initialize processes
//
static void stackInitializeProcesses(void){
int i=0;
while(stackProcess[i].process!=NULL){
  int e=eventsCreate(EVENTS_PRIORITY_PROCESS,stackProcess+i);
  eventsAddAction(e,stackUDPHandleDatagram,0);
  stackProcess[i].event=e;
  unsigned char type=PROCESS_INIT;
  IPv4Address address=IPV4_ADDRESS_NULL;
  short int port=0;
  int size=0;
  AssocArray *infos=NULL;
  arraysSetValue(&infos,"type",&type,sizeof(unsigned char),0);
  arraysSetValue(&infos,"ldst",&address,sizeof(IPv4Address),0);
  arraysSetValue(&infos,"lsrc",&address,sizeof(IPv4Address),0);
  arraysSetValue(&infos,"pdst",&port,sizeof(short int),0);
  arraysSetValue(&infos,"psrc",&port,sizeof(short int),0);
  arraysSetValue(&infos,"data",NULL,0,AARRAY_DONT_DUPLICATE);
  arraysSetValue(&infos,"size",&size,sizeof(int),0);
  eventsTrigger(e,infos);
  i++;
  }
}

////
// Main procedure
////

int main(void){
stackInitializeDevices();
stackDisplayDevices(stderr);
stackInitializeLayers();
stackInitializeProcesses();
eventsScan();
exit(0);
}
