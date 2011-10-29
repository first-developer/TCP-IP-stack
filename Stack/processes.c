/*
 * Code for virtual processes
 */

////
// Include files
////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libarrays.h>
#include <libevents.h>

#include "netether.h"
#include "netip.h"
#include "stack.h"

////
// Constants
////

////
// Global variables
////

////
// Processus implementing an UDP echo
////

#define UDP_ECHO_PROMPT		"> "
unsigned char udp_echo(  unsigned char type,  SocketAddress to,SocketAddress from,  unsigned char *data,int size){
	printf("udp_echo: type=%x\n",type);
	if(type==PROCESS_DATA){
		printf("udp_echo: (%s,%hu)",ipAddress2String(from.address),from.port);
		printf("->(%s,%hu)\n",ipAddress2String(to.address),to.port);
		printf(" size : %d\n", size);
		data=(unsigned char *)realloc(data,size+2);
		memmove(data+2,data,size);
		printf(" data after memmove : %s\n", data);
		memcpy(data,UDP_ECHO_PROMPT,strlen(UDP_ECHO_PROMPT));
		printf(" data after memcpy : : %s\n", data);
		return stackUDPSendDatagram(from.address,from.port,data,size+2);
	}
	return 0;
}
