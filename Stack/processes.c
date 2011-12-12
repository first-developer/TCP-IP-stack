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
	printf("\n%sudp_echo: %s type=%x\n", BMAGENTA, BLACK,type);
	if(type==PROCESS_DATA){
		printf("%sudp_echo: %s(%s,%hu)%s",BLUE, BBLACK, ipAddress2String(from.address),from.port, BLACK);
		printf("%s->(%s,%hu)%s\n", BBLUE, ipAddress2String(to.address),to.port, BLACK);
		printf("%s size : %d%s\n", BBLUE, size, BLACK);
		data=(unsigned char *)realloc(data,size+2);
		memmove(data+2,data,size);
		memcpy(data,UDP_ECHO_PROMPT,strlen(UDP_ECHO_PROMPT));
		return stackUDPSendDatagram(from.address,from.port,data,size+2);
	}
	/*if(type==PROCESS_ERROR){
		printf("Error port unreachable : (%s,%hu)",ipAddress2String(from.address),from.port);
		printf("->(%s,%hu)\n",ipAddress2String(to.address),to.port);
		printf(" size : %d\n", size);
		data=(unsigned char *)realloc(data,size+2);
		memmove(data+2,data,size);
		memcpy(data,UDP_ECHO_PROMPT,strlen(UDP_ECHO_PROMPT));
		return stackUDPSendDatagram(from.address,from.port,data,size+2);
	}*/
	return 0;
}
