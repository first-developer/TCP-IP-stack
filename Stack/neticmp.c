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
//  unsigned char type;
//  unsigned char code;
//  unsigned short int checksum;
//  unsigned char data[1];
//  } ICMPv4_fields;
#ifdef VERBOSE
//
// Display ICMPv4 packet
//

void displayICMPv4Packet(FILE *output,ICMPv4_fields *icmp,int size){
	fprintf(output,"ICMP type: %04x\n",ntohs(icmp->type));
	fprintf(output,"ICMP code: %04x\n",ntohs(icmp->code));
	fprintf(output,"ICMP Checksum: %04x\n",ntohs(icmp->checksum));
	fprintf(output,"ICMP Data:\n  ");
	int i;
	int data_size=size-sizeof(ICMPv4_fields)+1;
	for(i=0;i<data_size;i++){
	  fprintf(output,"%02hhx ",icmp->data[i]);
	  if(i%MAX_BYTES_BY_ROW == MAX_BYTES_BY_ROW-1){
	    fprintf(output,"\n");
	    if(i<data_size-1) fprintf(output,"  ");
	    }
	  }
	if(i%MAX_BYTES_BY_ROW != 0) fprintf(output,"\n");
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
	fprintf(stderr,":D Incoming ICMP packet:\n");
	displayICMPv4Packet(stderr,icmp,size);
#endif


	// Verify the cheksum
	if(icmp->checksum!=0){
		unsigned short int checksum=pseudoHeaderChecksum(
				iph->source, iph->target, IPV4_PROTOCOL_ICMP, &data, size);
		icmp=(ICMPv4_fields *)data;
		if(checksum!=0){
#ifdef VERBOSE
			fprintf(stderr,"ICMP packet: bad checksum\n");
#endif
			free(data); free(iph); return 0;
		}
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
			IPv4Address rev_source = iph->target;

			// Set type and code  of the reply message
			unsigned char type = ICMPV4_TYPE_ECHO_REPLY;
			unsigned char code= ICMPV4_CODE_NONE;

			//  Compute the reply size of packet
			int reply_size=(IPv4_get_hlength(iph)+3)*4;

			// Make packet fit the right size
			data=(unsigned char *)realloc(data,reply_size);
			if(data==NULL){ perror("ipDecodePacket.realloc"); return 1; }
			memmove(data,data,reply_size);


			// Initialized and set the icmp packet to replay
			AssocArray *icmp_infos=NULL;
			arraysSetValue(&icmp_infos,"type",&type,sizeof(unsigned char),0);
			arraysSetValue(&icmp_infos,"code",&code,sizeof(unsigned char),0);
			arraysSetValue(&icmp_infos,"data",data,reply_size,AARRAY_DONT_DUPLICATE);
			arraysSetValue(&icmp_infos,"size",&reply_size,sizeof(int),0);
			arraysSetValue(&icmp_infos,"ldst",&rev_source,sizeof(IPv4Address),0);
			eventsTrigger(picmp->event_out,icmp_infos);
		}
		free(data); return 0;
		break;
	case ICMPV4_TYPE_UNREACHABLE:
		if ( icmp->code == 	ICMPV4_UNREACHABLE_CODE_PORT ) {  // port introuvable
			unsigned char type=PROCESS_ERROR;
			unsigned char code= ICMPV4_CODE_NONE;

			// set udp_size
			int size_hdr=sizeof(UDP_fields)-1;
			int size_data=size-size_hdr;
			memmove(data,data+size_hdr,size_data);
			data=(unsigned char *)realloc(data,size_data);

			AssocArray *infos=NULL;
			arraysSetValue(&infos,"code",&code,sizeof(unsigned char),0);
			arraysSetValue(&infos,"type",&type,sizeof(unsigned char),0);
			arraysSetValue(&infos,"data",data,size_data,AARRAY_DONT_DUPLICATE);
			arraysSetValue(&infos,"size",&size_data,sizeof(int),0);
			eventsTrigger(picmp->event_out,infos);
		}
		free(data); return 0;
		break;
	default: break;
	}

	return 0;
}



//
// Send ICMPv4 packet
//

unsigned char icmpSendPacket(EventsEvent *event,EventsSelector *selector){
	printf("icmp send packet \n");
	// Get icmp data from the selector
	AssocArray *infos=(AssocArray *)selector->data_this;

	// Checking presence of ICMP attributes
	if( arraysTestIndex(infos,"type",0)<0 || arraysTestIndex(infos,"code",0)<0 ||
			arraysTestIndex(infos,"size",0)<0 || arraysTestIndex(infos,"data",0)<0 ||
			arraysTestIndex(infos,"ldst",0)<0 )
	{ arraysFreeArray(infos); return 1; }

	// Get the icmp layer
	StackLayers *picmp=stackFindProtoById(LEVEL_TRANSPORT,IPV4_PROTOCOL_ICMP);
	if(picmp==NULL || picmp->event_out<0){ arraysFreeArray(infos); return 0; }

	// Get ICMP attributes: type, code, data, ldst
	unsigned char type	=	*(unsigned char *)arraysGetValue(infos,"type",NULL,0); //type
	unsigned char code	=	*(unsigned char *)arraysGetValue(infos,"code",NULL,0); //code
	int 	data_size	=	*(int *)arraysGetValue(infos,"size",NULL,0); //size
	unsigned char *data	=	(unsigned char *)arraysGetValue(infos,"data",NULL,0); //data
	IPv4_fields 	*ip	=	(IPv4_fields *)arraysGetValue(infos,"ldst", NULL, 0); 	//ldst
	IPv4Address	 source = 	(IPv4Address) ip->source;  // src adresse related to the error
	IPv4Address	 target = 	IPV4_ADDRESS_NULL;  // set target adresse to NULL address

	// free infos datas
	arraysFreeArray(infos);

	// Fill ICMP Header 
	// -----------------------------------------------------------------------
	// Compute size_hicmp and size_icmp
	int size_hicmp = sizeof(ICMPv4_fields)-1;
	int size_icmp  = data_size + size_hicmp;

	// Reallocate data space memory and check if it's done well
	data=(unsigned char *) realloc(data, size_icmp);
	if (data == NULL) { perror("icmpSendPacket.realloc"); return 1; }

	// put icmp_ header before icmp data
	memmove(data+size_hicmp,data,data_size);
	bzero(data,size_hicmp);  // fill icmp header with zero

	// Apply the ICMP structure to the data by casting data
	ICMPv4_fields *icmp = (ICMPv4_fields *)data;

	// Set attributes of icmp structure
	icmp->type 	= type;
	icmp->code	= code;

	// Compute and set checksum attribute
	icmp->checksum = 0;
	unsigned short int checksum=genericChecksum(data,size_icmp);
	icmp = (ICMPv4_fields *)data; 
	icmp->checksum = checksum;

	/* TODO: verbose for debugging icmpi */

	// Call IP layer
	unsigned char protocol = IPV4_PROTOCOL_UDP;
	AssocArray *ip_options = NULL;
	arraysSetValue(&ip_options,"lsrc",&source,sizeof(IPv4Address),0);
	//Set ip infos
	AssocArray *ip_infos=NULL;
	arraysSetValue(&ip_infos,"ldst",&target,sizeof(IPv4Address),0);
	arraysSetValue(&ip_infos,"proto",&protocol,sizeof(unsigned char),0);
	arraysSetValue(&ip_infos,"data",data,size_icmp,AARRAY_DONT_DUPLICATE);
	arraysSetValue(&ip_infos,"size",&size_icmp,sizeof(int),0);
	arraysSetValue(&ip_infos,"opts",ip_options,sizeof(AssocArray *), AARRAY_DONT_DUPLICATE);
	eventsTrigger(picmp->event_out,ip_infos);

	return 0;
}
