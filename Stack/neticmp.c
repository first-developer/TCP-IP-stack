/*
 * Code for ICMP protocol implementation
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

////
// Functions
////

#ifdef VERBOSE
//
// Display ICMPv4 packet
//

void displayICMPv4Packet(FILE *output,ICMPv4_fields *icmp,int size){

}
#endif

//
// Decode ICMPv4 packet
//

unsigned char icmpDecodePacket(EventsEvent *event,EventsSelector *selector){




	return 0;
}
/*
    arraysSetValue(&icmp_infos,"type",&type,sizeof(unsigned char),0);
    arraysSetValue(&icmp_infos,"code",&code,sizeof(unsigned char),0);
    arraysSetValue(&icmp_infos,"data",data,reply_size,AARRAY_DONT_DUPLICATE);
    arraysSetValue(&icmp_infos,"size",&reply_size,sizeof(int),0);
    arraysSetValue(&icmp_infos,"ldst",&source,sizeof(IPv4Address),0);


    unsigned char *data=(unsigned char *)arraysGetValue(infos,"data",NULL,0);
    int size=*((int *)arraysGetValue(infos,"size",NULL,0));
    arraysFreeArray(infos);
    IPv4_fields *ip=(IPv4_fields *)data;
    unsigned short int checksum=genericChecksum(data,4*IPv4_get_hlength(ip));
*/

//
// Send ICMPv4 packet
//

unsigned char icmpSendPacket(EventsEvent *event,EventsSelector *selector){

  // Get icmp data from the selector
  AssocArray *infos=(AssocArray *)selector->data_this;
/*
  // Checking presence of ICMP attributes
  if( arraysTestIndex(infos,"type",0)<0 || 
      arraysTestIndex(infos,"code",0)<0)||
      arraysTestIndex(infos,"size",0)<0)||
      arraysTestIndex(infos,"data",0)<0) )
  { arraysFreeArray(infos); return 1; } 
	
  // Get ICMP attributes: type, code, data
  unsigned char *type=(unsigned char *)arraysGetValue(infos,"type",NULL,0); //type
  unsigned char *code=(unsigned char *)arraysGetValue(infos,"code",NULL,0); //code
  unsigned char *size=(unsigned char *)arraysGetValue(infos,"size",NULL,0); //size
  unsigned char *data=(unsigned char *)arraysGetValue(infos,"data",NULL,0); //data

  // Compute checksum
  unsigned short int checksum=genericChecksum(data,size);

  // et icmp header size
  int icmp_header_size = 4;

  // Init and set icmp header 
  data=(unsigned char *)realloc(data, size+icmp_header_size);
  memmove(data+4, data, size);
  bzero(data,4);

  arraysSetValue(&icmp_infos,"type",&type,sizeof(unsigned char),0);
  arraysSetValue(&icmp_infos,"code",&code,sizeof(unsigned char),0);
  arraysSetValue(&icmp_infos,"checksum",data,reply_size,AARRAY_DONT_DUPLICATE);
  arraysSetValue(&icmp_infos,"size",&reply_size,sizeof(int),0);
  arraysSetValue(&icmp_infos,"ldst",&source,sizeof(IPv4Address),0);
  eventsTrigger(picmp->event_out,icmp_infos);  
*/

	return 0;
}
