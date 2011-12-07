/*
 * Code for TCP protocol implementation
 */

////
// Include files
////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <libarrays.h>
#include <libevents.h>

#include "netether.h"
#include "netip.h"
#include "nettcp.h"
#include "neticmp.h"
#include "stack.h"


////
//  Constantes utiles
////




////
// Global variables
////




////
// Prototypes
////




////
// Functions
////

#ifdef VERBOSE
//
// Display TCP packet
//

void displayTCPPacket(FILE *output, TCP_header_fields *tcph, int size){
	fprintf(output, "TCP Port source: %04x\n", ntohs(tcph->tcph_source));
	fprintf(output, "TCP Port target: %04x\n", ntohs(tcph->tcph_target));
	fprintf(output, "TCP SEQ:         %d\n"	 , tcph->tcph_flags_CWR);
	fprintf(output, "TCP ACK:         %d\n"  , tcph->tcph_flags_CWR);
	fprintf(output, "TCP Window: 	  %04x\n", tcph->tcph_window);  
	fprintf(output,	"TCP Checksum: 	  %04x\n", ntohs(tcph->tcph_checksum));
	fprintf(output, "TCP Urgent:	  %04x\n", tcph->tcph_urgptr);  
	display_tcph_flags(tcph);  		  // affichage des flags

	// Get options according to the option type
	TCP_options_fields *tcp_options = (TCP_options_fields *)tcph->options;
	display_tcp_options(output, tcp_options);  // Display options

	fprintf(output,"TCP Data:\n  ");
	int i;
	int data_size=size-sizeof(unsigned int)+1;		/* uint32_t(32bits)  for options */
	for(i=0;i<data_size;i++){
	  fprintf(output,"%02hhx ", tcp_options->data[i]);
	  if(i%MAX_BYTES_BY_ROW == MAX_BYTES_BY_ROW-1){
	    fprintf(output,"\n");
	    if(i<data_size-1) fprintf(output,"  ");
	    }
	  }
	if(i%MAX_BYTES_BY_ROW != 0) fprintf(output,"\n");
}
#endif

//
// Decode tcp packet
//

unsigned char tcpDecodePacket(EventsEvent *event,EventsSelector *selector){
	/* Get values from associative array */
	AssocArray *infos=(AssocArray *)selector->data_this;
	if(arraysTestIndex(infos,"data",0)<0 || arraysTestIndex(infos,"size",0)<0 ||
	arraysTestIndex(infos,"iph",0)<0)
	{ arraysFreeArray(infos); return 1; }
	unsigned char *data=(unsigned char *)arraysGetValue(infos,"data",NULL,0);
	int size=*((int *)arraysGetValue(infos,"size",NULL,0));
	IPv4_fields *iph=(IPv4_fields *)arraysGetValue(infos,"iph",NULL,0);
	arraysFreeArray(infos);

	// Get TCP header from IP packet 
	//int tcph_size = sizeof(TCP_Header_fields) -1;

	// move memory to get the TCP header (DATA + TCP_HEADER)
	//memmove(data);
	TCP_header_fields *tcph = (TCP_header_fields *) data;

	fprintf(stderr,":D Incoming TCP packet:\n");
	displayTCPPacket(stderr, tcph, size);
	return 0;
}

//
// Send tcp packet
//

unsigned char tcpSendPacket(EventsEvent *event,EventsSelector *selector){

	return 0;
}




// handle tcp options 
// --------------------------------------------------
// tcpo : tcp option field
/*unsigned char get_options_length ( TCP_options_fields *tcpo) {
	unsigned char tcpo_kind = tcpo->tcpo_kind;

	if ( tcpo_kind == TCP_OPTION_TYPE_MSS ) {
		// get option mss length 
		unsigned char tcpo_length = TCP_get_option_MSS_length(tcpo->data);
		return tcpo_length;
	}
	return 0;
}*/

// Display content of tcp option fields
void display_tcp_options(FILE *output, TCP_options_fields *tcpo) {	
	fprintf(output,"TCP Option:\n  ");
	if ( tcpo->tcpo_length > 0 ) {
		fprintf( output, " TCP_option Type:   	  %d\n", 	tcpo->tcpo_type);
		fprintf( output, " TCP_option Length:  	  %d\n", 	tcpo->tcpo_length);
		fprintf( output, " TCP_option Data:	  	  %04x\n", 	tcpo->tcpo_data);
	}
	else {
		fprintf( output, " TCP_option Type:   	  %d\n", 	tcpo->tcpo_type);
	}
}


// Handle tcp flags
// --------------------------------------------------
void init_tcph_lags( TCP_header_fields* tcph) {
  tcph->tcph_flags_CWR=0;    //
  tcph->tcph_flags_ECE=0;    //
  tcph->tcph_flags_URG=0;    //   
  tcph->tcph_flags_ACK=1;    //    TCP HEADER FLAGS (8 bits)
  tcph->tcph_flags_PSH=0;    //
  tcph->tcph_flags_RST=0;    //
  tcph->tcph_flags_SYN=0;    //
  tcph->tcph_flags_FIN=0;	 //
}

void display_tcph_flags(TCP_header_fields* t) {
  printf(" tcph->flags[CWR] = %d\n",t->tcph_flags_CWR);     //
  printf(" tcph->flags[ECE] = %d\n",t->tcph_flags_ECE);     //
  printf(" tcph->flags[URG] = %d\n",t->tcph_flags_URG);     //   
  printf(" tcph->flags[ACK] = %d\n",t->tcph_flags_ACK);     //    TCP HEADER FLAGS (8 bits)
  printf(" tcph->flags[PSH] = %d\n",t->tcph_flags_PSH);     //
  printf(" tcph->flags[RST] = %d\n",t->tcph_flags_RST);     //
  printf(" tcph->flags[SYN] = %d\n",t->tcph_flags_SYN);     //
  printf(" tcph->flags[FIN] = %d\n",t->tcph_flags_FIN); 	//
}

// set the flag to 1 depends on our needs
void put_tcph_flag_on( TCP_header_fields* tcph, unsigned char flag) {
	switch(flag) {
		case CWR : tcph->tcph_flags_CWR = 1;
			break;
		case ECE : tcph->tcph_flags_ECE = 1;
			break;
		case URG : tcph->tcph_flags_URG = 1;
			break;
		case ACK : tcph->tcph_flags_ACK = 1;
			break;
		case PSH : tcph->tcph_flags_PSH = 1;
			break;
		case RST : tcph->tcph_flags_RST = 1;
			break;
		case SYN : tcph->tcph_flags_SYN = 1;
			break;
		case FIN : tcph->tcph_flags_FIN = 1;
			break;
	}
}  

// set the flag to 0 depends on our needs
void put_tcph_flag_off( TCP_header_fields* tcph, unsigned char flag) {
	switch(flag) {
		case CWR : tcph->tcph_flags_CWR = 0;
			break;
		case ECE : tcph->tcph_flags_ECE = 0;
			break;
		case URG : tcph->tcph_flags_URG = 0;
			break;
		case ACK : tcph->tcph_flags_ACK = 0;
			break;
		case PSH : tcph->tcph_flags_PSH = 0;
			break;
		case RST : tcph->tcph_flags_RST = 0;
			break;
		case SYN : tcph->tcph_flags_SYN = 0;
			break;
		case FIN : tcph->tcph_flags_FIN = 0;
			break;
	}
} 

//
// Display IPv4 packet
//




