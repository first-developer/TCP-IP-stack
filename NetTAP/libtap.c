/*
 * Common code for TAP network device handling
 */

////
// Include files
////

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

////
// Device manipulation functions
////

//
// Allocate TUN/TAP device
//

int allocateNetworkDevice(char *name,int flags){
struct ifreq ifr;
int fd,err;
char *clonedev = "/dev/net/tun";

/* Open the clone device */
if((fd=open(clonedev,O_RDWR))<0) return fd;

/* Preparation of the struct ifr, of type "struct ifreq" */
memset(&ifr,0,sizeof(ifr));
ifr.ifr_flags=flags;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */
if(name!=NULL) strncpy(ifr.ifr_name,name,IFNAMSIZ);

/* Try to create the device */
if((err=ioctl(fd,TUNSETIFF,(void *)&ifr))<0){ close(fd); return err; }

/* Write back the name of the * interface to the variable "name" */
if(name!=NULL) strcpy(name,ifr.ifr_name);

return fd;
}
