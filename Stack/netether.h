/*
 * Internal definitions for network interfaces
 */

////
// Constants
////

#define ETHERNET_ADDRESS_SIZE		6
#define ETHERNET_NAME_MAX_SIZE		16

#define	ETHERNET_PROTO_IP		0x0800
#define	ETHERNET_PROTO_ARP		0x0806
#define	ETHERNET_PROTO_RARP		0x8035

////
// Structures
////

#pragma pack(1)

typedef struct{
  unsigned char bytes[ETHERNET_ADDRESS_SIZE];
  } EthernetAddress;

typedef struct{
  EthernetAddress target;
  EthernetAddress sender;
  short int protocol;
  unsigned char data[1];
  } Ethernet_fields;

#pragma pack()

////
// Global variables
////

extern EthernetAddress ETHERNET_ADDRESS_NULL;
extern EthernetAddress ETHERNET_ADDRESS_BROADCAST;

////
// Prototypes
////

#ifdef VERBOSE
void displayEthernetPacket(FILE *output,Ethernet_fields *ethernet,int data_size);
#endif
unsigned char ethernetDecodePacket(EventsEvent *event,EventsSelector *selector);
unsigned char ethernetSendPacket(EventsEvent *event,EventsSelector *selector);
unsigned short int genericChecksum(unsigned char *bytes,int size);
EthernetAddress ethernetString2Address(char *string);
char *ethernetAddress2String(EthernetAddress ethernet);
EthernetAddress ethernetArray2Address(unsigned char *array);
void ethernetAddress2Array(EthernetAddress ethernet,unsigned char *field);
unsigned char ethernetCompare(EthernetAddress a1,EthernetAddress a2);
unsigned char ethernetBroadcast(EthernetAddress address);
unsigned char ethernetMulticast(EthernetAddress address);
unsigned char ethernetUnicast(EthernetAddress address);
