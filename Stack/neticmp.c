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
#include "netudp.h"
#include "neticmp.h"
#include "stack.h"

////
// Global variables
////

#define	MAX_BYTES_BY_ROW	16

////
// Functions
////

#ifdef VERBOSE

//
// Display ICMPv4 packet
//

void displayICMPv4Packet(FILE *output,ICMPv4_fields *icmp,int size){
	fprintf(output,"%sICMP type: %s%04x\n", BLUE, BLACK, ntohs(icmp->type));
	fprintf(output,"%sICMP code: %s%04x\n", BLUE, BLACK, ntohs(icmp->code));
	fprintf(output,"%sICMP Checksum: %s%04x\n", BLUE, BLACK, ntohs(icmp->checksum));
	fprintf(output,"%sICMP Data:%s\n  ", BLUE,BBLACK );
	int i;
	int data_size=size-sizeof(ICMPv4_fields)+1;
	for(i=0;i<data_size;i++){
	  fprintf(output,"%02hhx ",icmp->data[i]);
	  if(i%MAX_BYTES_BY_ROW == MAX_BYTES_BY_ROW-1){
	    fprintf(output,"\n");
	    if(i<data_size-1) fprintf(output,"  ");
	    }
	  }
	if(i%MAX_BYTES_BY_ROW != 0) fprintf(output,"%s\n", BLACK);
}
#endif

//
// Decode ICMPv4 packet
//

unsigned char icmpDecodePacket(EventsEvent *event,EventsSelector *selector){

	// Get icmp data from the selector
	AssocArray *infos=(AssocArray *)selector->data_this;

	// Checking presence of ip attributes and get them if it's well done
	if(arraysTestIndex(infos,"data",0)<0 || arraysTestIndex(infos,"size",0)<0 ||
			arraysTestIndex(infos,"iph",0)<0)
	{ arraysFreeArray(infos); return 1; }

	unsigned char *data=(unsigned char *)arraysGetValue(infos,"data",NULL,0);
	int size=*((int *)arraysGetValue(infos,"size",NULL,0));
	IPv4_fields *iph=(IPv4_fields *)arraysGetValue(infos,"iph",NULL,0);

	// free infos received
	arraysFreeArray(infos);

	//* Check ICMP headers 
	ICMPv4_fields *icmp=(ICMPv4_fields *)data;

	// Get value of icmp fields
	unsigned char type = (unsigned char) icmp->type;
#ifdef VERBOSE
	// display the packet received
	fprintf(stderr,"\n%s<<<<<  Incoming ICMP packet:  <<<<<%s\n", BGREEN, BLACK);
	displayICMPv4Packet(stderr,icmp,size);
#endif

	unsigned short int checksum=genericChecksum(data,size);

	if(checksum!=0){
#ifdef VERBOSE
		fprintf(stderr,"%sICMP packet: bad checksum%s\n", RED, BLACK);
#endif
		free(data); free(iph); return 0;
	}
	
	// Get the layer related to the sender
	StackLayers *picmp=stackFindProtoById(LEVEL_TRANSPORT,IPV4_PROTOCOL_ICMP);

	// Process data depends on Type of packet
	switch(type) {
	case ICMPV4_TYPE_ECHO_REQUEST:   // echo request message -> echo reply

		// ----------------------------------------------
		// Sending the reply message
		// ----------------------------------------------

		// Verify if everything work fine after the 'stackFindProtoById' call
		if(picmp!=NULL && picmp->event_out>=0){
			// reverse source and destination adresses
			IPv4Address rev_source = iph->source;

			// Set type and code  of the reply message
			unsigned char type = ICMPV4_TYPE_ECHO_REPLY;
			unsigned char code= ICMPV4_CODE_NONE;

			//  Compute the reply size of packet
			int size_iph=sizeof(ICMPv4_fields) -1;  // ip header size
			int reply_size=size - size_iph;
			
			// Make packet fit the right size
			memmove(data,data + size_iph,reply_size); 
			data=(unsigned char *)realloc(data,reply_size);
			if(data==NULL){ perror("ipDecodePacket.realloc"); return 1; }
			
			// Initialized and set the icmp packet to replay
			AssocArray *icmp_infos=NULL;
			arraysSetValue(&icmp_infos,"type",&type,sizeof(unsigned char),0);
			arraysSetValue(&icmp_infos,"code",&code,sizeof(unsigned char),0);
			arraysSetValue(&icmp_infos,"data",data,reply_size,AARRAY_DONT_DUPLICATE);
			arraysSetValue(&icmp_infos,"size",&reply_size,sizeof(int),0);
			arraysSetValue(&icmp_infos,"ldst",&rev_source,sizeof(IPv4Address),0);
			eventsTrigger(picmp->event_out,icmp_infos);
		}
		else free(data);
		break;
	case ICMPV4_TYPE_UNREACHABLE:
		if ( icmp->code == 	ICMPV4_UNREACHABLE_CODE_PORT ) {  // port introuvable
			unsigned char type=PROCESS_ERROR;

			// Get the upd source port 
			// -------------------------
			/// Get the ip header(icmp_iph) and udp fields (icmp_udp) inside icmp data
			IPv4_fields *icmp_iph = (IPv4_fields *)(data + 4);
			int icmp_iph_size = IPv4_get_hlength(icmp_iph)*4;  // Size of icmp_iph
			UDP_fields *icmp_udp = (UDP_fields *)(data + 4 + icmp_iph_size);

			// Get Source port from icmp_udp fields
			unsigned short int psource = ntohs(icmp_udp->source);

			int psource_net= icmp_udp->source;

			// Get he process linked to the psource getting previously
			StackProcess *process=stackFindProcess(IPV4_PROTOCOL_UDP,iph->source,psource);

			// Compute size_data and set data infos to send
		   	int size_hdr=sizeof(UDP_fields)-1;
 			int size_data=size-size_hdr;
 			memmove(data,data+size_hdr,size_data);
 			data=(unsigned char *)realloc(data,size_data);
 	
			AssocArray *infos=NULL;
 			arraysSetValue(&infos,"type",&type,sizeof(unsigned char),0);
 			arraysSetValue(&infos,"ldst",&iph->target,sizeof(IPv4Address),0); // unused normally ?
 			arraysSetValue(&infos,"lsrc",&iph->source,sizeof(IPv4Address),0); // unused normally ?
 			arraysSetValue(&infos,"pdst",&psource_net,sizeof(short int),0);
 			arraysSetValue(&infos,"psrc",&psource_net,sizeof(short int),0);   // unused normally ?
 			arraysSetValue(&infos,"data",data,size_data,AARRAY_DONT_DUPLICATE);
 			arraysSetValue(&infos,"size",&size_data,sizeof(int),0);
 			eventsTrigger(process->event,infos);
		}
		else free(data);
		break;
	default: break;
	}
	free(iph);
	return 0;
}



//
// Send ICMPv4 packet
//

unsigned char icmpSendPacket(EventsEvent *event,EventsSelector *selector){
	// Get icmp data from the selector
	AssocArray *infos=(AssocArray *)selector->data_this;

	// Checking presence of ICMP attributes
	if( arraysTestIndex(infos,"type",0)<0 || arraysTestIndex(infos,"code",0)<0 ||
			arraysTestIndex(infos,"size",0)<0 || arraysTestIndex(infos,"data",0)<0 ||
			arraysTestIndex(infos,"ldst",0)<0 )
	{ arraysFreeArray(infos); return 1; }

	// Get the icmp layer
	StackLayers *pip=stackFindProtoById(LEVEL_NETWORK,ETHERNET_PROTO_IP);
	if(pip==NULL || pip->event_out<0){ arraysFreeArray(infos); return 0; }

	// Get ICMP attributes: type, code, data, ldst
	unsigned char type	=	*(unsigned char *)arraysGetValue(infos,"type",NULL,0); //type
	unsigned char code	=	*(unsigned char *)arraysGetValue(infos,"code",NULL,0); //code
	int 	data_size	=	*(int *)arraysGetValue(infos,"size",NULL,0); //size
	unsigned char *data	=	(unsigned char *)arraysGetValue(infos,"data",NULL,0); //data
 	IPv4Address target	=	*((IPv4Address *)arraysGetValue(infos,"ldst", NULL, 0)); 	//ldst
	
	// free infos datas
	arraysFreeArray(infos);

	IPv4Address	 source = 	IPV4_ADDRESS_NULL;  // set target adresse to NULL address
	EthernetInterface *device=stackFindDeviceByIPv4Network(target);
	if(device!=NULL) source=device->IPv4[0].address;

	// Fill ICMP Header 
	// -----------------------------------------------------------------------
	// Compute size_hicmp and size_icmp
	int size_hicmp = sizeof(ICMPv4_fields)-1;
	int size_icmp  = data_size + size_hicmp;

	// Reallocate data space memory and check if it's done well
	data=(unsigned char *) realloc(data, size_icmp);
	if (data == NULL) { perror("icmpSendPacket.realloc"); return 1; }

	// put icmp_header before icmp data
	memmove(data+size_hicmp,data,data_size);
	bzero(data,size_hicmp);  // fill icmp header with zero

	// Apply the ICMP structure to the data by casting data
	ICMPv4_fields *icmp = (ICMPv4_fields *)data;

	// Set attributes of icmp structure
	icmp->type 	= type;
	icmp->code	= code;

	// Compute and set checksum attribute
	// icmp->checksum = 0;
	unsigned short int checksum=genericChecksum(data,size_icmp);
	icmp = (ICMPv4_fields *)data; 
	icmp->checksum = htons(checksum);

#ifdef VERBOSE
	fprintf(stderr,"\n%s>>>>>  Outgoing ICMP packet:  >>>>>%s\n", BMAGENTA, BLACK);
	displayICMPv4Packet(stderr,icmp,size_icmp);
#endif


	// Call IP layer
	unsigned char protocol = IPV4_PROTOCOL_ICMP;
	AssocArray *ip_options = NULL;
	arraysSetValue(&ip_options,"lsrc",&source,sizeof(IPv4Address),0);
	//Set ip infos
	AssocArray *ip_infos=NULL;
	arraysSetValue(&ip_infos,"ldst",&target,sizeof(IPv4Address),0);
	arraysSetValue(&ip_infos,"proto",&protocol,sizeof(unsigned char),0);
	arraysSetValue(&ip_infos,"data",data,size_icmp,AARRAY_DONT_DUPLICATE);
	arraysSetValue(&ip_infos,"size",&size_icmp,sizeof(int),0);
	arraysSetValue(&ip_infos,"opts",ip_options,sizeof(AssocArray *), AARRAY_DONT_DUPLICATE);
	eventsTrigger(pip->event_out,ip_infos);

	return 0;
}
