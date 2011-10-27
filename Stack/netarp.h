/*
 * Definitions for ARP/RARP protocol implementation
 */

////
// Constants
////

#define ARP_HW_TYPE_ETHERNET	0x0001
#define ARP_PROTO_TYPE_IPV4	0x0800

#define	ARP_OPCODE_REQUEST	0x0001
#define	ARP_OPCODE_ANSWER	0x0002
#define	RARP_OPCODE_REQUEST	0x0003
#define	RARP_OPCODE_ANSWER	0x0004

#define ARP_CACHE_TIMEOUT	120

////
// Structures
////

#pragma pack(1)

typedef struct{
  short int hw_type;  
  short int proto_type;  
  unsigned char hw_addr_len;
  unsigned char proto_addr_len;
  short int opcode;
  unsigned char addresses[1];
  } ARP_fields;

#pragma pack()

typedef struct{
  EthernetAddress ethernet;
  IPv4Address ipv4;
  time_t timestamp;
  } ARP_cache_entry;

typedef struct{
  int allocated;
  int size;
  ARP_cache_entry *entries;
  } ARP_cache;

////
// Prototypes
////

#ifdef VERBOSE
void displayARPPacket(FILE *output,ARP_fields *arp,int size);
#endif
unsigned char arpSendPacket(EventsEvent *event,EventsSelector *selector);
unsigned char arpDecodePacket(EventsEvent *event,EventsSelector *selector);
#ifdef VERBOSE
void arpDisplay(FILE *output);
#endif
void arpPurgeCache(void);
void arpAddToCache(IPv4Address ip,EthernetAddress ether,unsigned char force);
EthernetAddress arpFindInCache(IPv4Address ip);
IPv4Address arpReverseFindInCache(EthernetAddress ethernet);
