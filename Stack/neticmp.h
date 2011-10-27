/*
 * Definitions for ICMP protocol implementation
 */

////
// Constants
////

#define	ICMPV4_TYPE_ECHO_REPLY			0
#define	ICMPV4_TYPE_UNREACHABLE			3
#define	ICMPV4_TYPE_ECHO_REQUEST		8
#define	ICMPV4_TYPE_TIME_EXCEEDED		11

#define	ICMPV4_UNREACHABLE_CODE_NETWORK		0
#define	ICMPV4_UNREACHABLE_CODE_MACHINE		1
#define	ICMPV4_UNREACHABLE_CODE_PROTOCOL	2
#define	ICMPV4_UNREACHABLE_CODE_PORT		3
#define	ICMPV4_UNREACHABLE_CODE_FRAGMENT	4

#define	ICMPV4_CODE_NONE			0

////
// Structures
////

#pragma pack(1)

typedef struct{
  unsigned char type;
  unsigned char code;
  unsigned short int checksum;
  unsigned char data[1];
  } ICMPv4_fields;

#pragma pack()

////
// Prototypes
////

#ifdef VERBOSE
void displayICMPv4Packet(FILE *output,ICMPv4_fields *icmp,int size);
#endif
unsigned char icmpDecodePacket(EventsEvent *event,EventsSelector *selector);
unsigned char icmpSendPacket(EventsEvent *event,EventsSelector *selector);
