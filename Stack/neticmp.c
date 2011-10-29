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

//
// Send ICMPv4 packet
//

unsigned char icmpSendPacket(EventsEvent *event,EventsSelector *selector){

	
	return 0;
}
