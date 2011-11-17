/*
 * Definitions for virtual stack
 */

////
// Constants
////

#define LEVEL_LINK		2
#define LEVEL_NETWORK		3
#define LEVEL_TRANSPORT		4

#define PROCESS_INIT		0
#define PROCESS_DATA		1
#define PROCESS_CONNECT		2
#define PROCESS_CLOSE		3
#define PROCESS_ERROR		4

////
// Structures
////

typedef struct{
  IPv4Address address;
  int netmask;
  } NetworkAddressesIPv4;

typedef struct{
  int descriptor;
  char name_int[ETHERNET_NAME_MAX_SIZE];
  char name_tap[ETHERNET_NAME_MAX_SIZE];
  int ether_in;
  EthernetAddress ether_addr;
  NetworkAddressesIPv4 *IPv4;
  } EthernetInterface;

typedef struct{
  EthernetAddress (*function)(IPv4Address);
  } AddressResolutionModule;

typedef struct{
  int level;
  int identity;
  unsigned char (*action_in)(EventsEvent *,EventsSelector *);
  unsigned char (*action_out)(EventsEvent *,EventsSelector *);
  int event_in;
  int event_out;
  } StackLayers;

typedef struct{
  IPv4Address address;
  short int port;
  } SocketAddress;

typedef struct{
  unsigned char protocol;
  IPv4Address address;
  short int port;
  unsigned char (*process)(
    unsigned char type,
    SocketAddress to,SocketAddress from,
    unsigned char *data,int size);
  int event;
  } StackProcess;

////
// Prototypes
////

EthernetInterface *stackFindDeviceByAddr(EthernetAddress src);
EthernetInterface *stackFindDeviceByName(char *name);
EthernetInterface *stackFindDeviceByIPv4(IPv4Address ip);
EthernetInterface *stackFindDeviceByIPv4Broadcast(IPv4Address ip);
EthernetInterface *stackFindDeviceByIPv4Network(IPv4Address ip);
void stackDisplayDevices(FILE *output);
StackLayers *stackFindProtoById(int level,int id);
EthernetAddress stackAddressResolution(IPv4Address address);
StackProcess *stackFindProcess(
  unsigned char protocol,IPv4Address address,short int port);
unsigned char stackUDPSendDatagram(
  IPv4Address to_ip,short int to_port,unsigned char *data,int size);
