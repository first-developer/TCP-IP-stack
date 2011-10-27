/*
 * Definitions for UDP protocol implementation
 */

////
// Constants
////

////
// Structures
////

#pragma pack(1)

typedef struct{
  unsigned short int source;
  unsigned short int target;
  unsigned short int length;
  unsigned short int checksum;
  unsigned char data[1];
  } UDP_fields;

#pragma pack()

////
// Prototypes
////

#ifdef VERBOSE
void displayUDPPacket(FILE *output,UDP_fields *udp,int size);
#endif
unsigned char udpDecodePacket(EventsEvent *event,EventsSelector *selector);
unsigned char udpSendPacket(EventsEvent *event,EventsSelector *selector);
