#include <fcntl.h>  /* O_RDWR */
#include <string.h> /* memset(), memcpy() */
#include <stdio.h> /* perror(), printf(), fprintf() */
#include <stdlib.h> /* exit(), malloc(), free() */
#include <sys/ioctl.h> /* ioctl() */
#include <event.h>
/* includes for struct ifreq, etc */
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_packet.h>

typedef unsigned int UINT16_t;
#define ETH_PPPOE_SESSION   0x8864
#define DEFAULT_IF  "eth0"

typedef enum
{   
  INTF_ETH,
  INTF_PPP 
} itf_t;

UINT16_t Eth_PPPOE_Session   = ETH_PPPOE_SESSION;
int tun_fd, raw_fd;
int tun_fd1, raw_fd1;

void extractIpAddress(unsigned char *sourceString, int sessid)
{   short ipAddress[4];
    unsigned short len=0;
    unsigned char  oct[4]={0},cnt=0,cnt1=0,i,buf[5];

    len=strlen(sourceString);
    for(i=0;i<len;i++)
    {
        if(sourceString[i]!='.'){
            buf[cnt++] =sourceString[i];
        }
        if(sourceString[i]=='.' || i==len-1){
            buf[cnt]='\0';
            cnt=0;
            oct[cnt1++]=atoi(buf);
        }
    }
    ipAddress[0]=oct[0];
    ipAddress[1]=oct[1];
    ipAddress[2]=oct[2];
    ipAddress[3]=oct[3] + sessid;
    sprintf(sourceString, "%d.%d.%d.%d", ipAddress[0], ipAddress[1], ipAddress[2], ipAddress[3]);
    printf("source string ip %s\n", sourceString);

}

void PrintData(unsigned char* data , int Size)
{
  int i, j;

  for(i = 0; i < Size; i++) {
    if(i != 0 && i%16 == 0) {
      fprintf(stdout,"         ");
      for(j = i-16 ; j < i ; j++) {
        if(data[j] >= 32 && data[j] <= 128)
          fprintf(stdout,"%c", (unsigned char)data[j]); //if its a number or alphabet
        else
          fprintf(stdout,"."); //otherwise print a dot 
      }
      fprintf(stdout,"\n");
    }
    if(i%16 == 0)
      fprintf(stdout,"   ");
    fprintf(stdout," %02X", (unsigned int)data[i]);
    if(i == Size-1) {
      for(j = 0; j < 15-i%16; j++)
        fprintf(stdout,"   "); //extra spaces
      fprintf(stdout,"         ");
      for(j = i-i%16; j <= i; j++) {
        if(data[j] >= 32 && data[j] <= 128)
          fprintf(stdout,"%c", (unsigned char)data[j]);
        else
          fprintf(stdout,".");
      }
      fprintf(stdout,"\n");
    }
  }
}

int create_socket(UINT16_t type, char ifname[IFNAMSIZ])
{
  int sockfd, ret;
  int sockopt = 1;
  struct event *ev;
  struct timeval tv;
  struct ifreq ifopts, if_ip, ifr;  /* set promiscuous mode */
  char ifName[IFNAMSIZ];
  struct sockaddr_ll sa;
  uint8_t buf[1528];

  //strcpy(ifName, DEFAULT_IF);
  strcpy(ifName, ifname);

  printf("ifName = %s\n", ifName);
  /* Header structures */

  memset(&if_ip, 0, sizeof(struct ifreq));

  /* Open PF_PACKET socket, listening for EtherType ETHER_TYPE */
  if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(type))) == -1) {
    perror("listener: socket");
    return -1;
  } else
    printf("socket create successfully\n");

  /* Set interface to promiscuous mode - do we need to do this every time? */
  strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
  ret = ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
  if(ret < 0) {
    perror("error on SIOCGIFFLAGS");
    return -1;
  }

  ifopts.ifr_flags |= IFF_PROMISC;
  ret = ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
  if(ret < 0 ) {
    perror("error on SIOCSIFFLAGS");
    return -1;
  }
  if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &sockopt, sizeof sockopt) == -1) {
    perror("setsockopt");
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  sa.sll_family = PF_PACKET;
  sa.sll_protocol = htons(type);

  strncpy(ifr.ifr_name, ifName, sizeof(ifr.ifr_name));
  if (ioctl(sockfd, SIOCGIFINDEX, &ifopts) < 0) {
    printf("ioctl(SIOCFIGINDEX): Could not get interface index\n");
    perror("SIOCGIFINDEX");
    return -1;
  }
  sa.sll_ifindex = ifopts.ifr_ifindex;
  /* Bind to device */
  if (bind(sockfd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
    printf("binding failed \n");
  } else {
    printf("binding successfully\n");
  }

  return sockfd;
}

void set_hwaddr(int eth_fd, char *tap_name, int type, struct ifreq *ifr)
{
  strncpy(ifr->ifr_name, tap_name, sizeof(ifr->ifr_name));
  //ifr->ifr_hwaddr.sa_family = ARPHRD_ETHER;
  if(INTF_ETH == type) {
    //memcpy(ifr->ifr_hwaddr.sa_data, port->mac, ETH_ALEN);
    if(ioctl(eth_fd, SIOCSIFHWADDR, ifr) == -1) {
      perror("Failed to set the MAC address!");
    }
  }

  if(ifr->ifr_flags | ~(IFF_UP)) {
    ifr->ifr_flags |= IFF_UP;
    if(ioctl(eth_fd, SIOCSIFFLAGS, ifr) <0) {
      perror("Failed to set if flags!");
      return;
    }
  }

  return;
}


int tun_open(char *dev, char *src_ip)
{
  struct sockaddr_in *sin;
  int error;
  int fd, ret;
  struct ifreq ifr;

  if(NULL == dev || *dev == '\0') {
    perror("Can't create a tap/tun dev with no name");
    return -1;
  }
  if((fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Error opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  if((ret = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    //error = errno;
    perror("Can't ioctl TUNSETIFF");
    close(fd);
    //return error*(-1);
    return -1;
  }

  if(fd) {
    set_hwaddr(raw_fd, dev, INTF_PPP, &ifr);
  }
  memset(&sin, 0, sizeof(sin));
  sin = (struct sockaddr_in *)&ifr.ifr_addr;
  sin->sin_family = AF_INET;
  sin->sin_addr.s_addr = inet_addr(src_ip);

  printf("eth fd = %d, ifr name = %s, src_ip %s\n", raw_fd, ifr.ifr_name, src_ip);
  if(ioctl(raw_fd, SIOCSIFADDR, &ifr) < 0) {
    perror("Cannot set ip address!");
    return -1;
  }
  sin->sin_addr.s_addr = inet_addr("255.255.255.0");

  if(ioctl(raw_fd, SIOCSIFNETMASK, &ifr) < 0) {
   perror("Cannot set netmask ip address!");
    return -1;
  }

  return fd;
}

#if 0
int tun_open(char *devname)
{
  struct ifreq ifr;
  int fd, err;

  //if ( (fd = open("/dev/net/tun", O_RDWR)) == -1 ) {
  if ( (fd = open("/dev/ppp", O_RDWR)) == -1 ) {
       perror("open /dev/net/tun");exit(1);
  }
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN;
  strncpy(ifr.ifr_name, devname, IFNAMSIZ);  

  /* ioctl will use if_name as the name of TUN 
   * interface to open: "tun0", etc. */
  if ( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) == -1 ) {
    perror("ioctl TUNSETIFF");close(fd);exit(1);
  }

  /* After the ioctl call the fd is "connected" to tun device specified
   * by devname */

  return fd;
}
#endif

void recvfrom_tun_device_sendto_ppp_cb(int fd, short ev, void *arg)
{
  struct ethhdr *ethHd;
  ssize_t numbytes;
  int n, plen, len = 0;
  uint8_t buffer[4096];
  //uint8_t buffer1[4096] = { 0x00, 0x21, 0xcc, 0xce, 0x15, 0x3c, 
  //                          0xf0, 0x1f, 0xaf, 0x4a, 0x00, 0x10, 0x88, 0x64};
  uint8_t buffer1[4096] = { 0xf8, 0xa9, 0x63, 0x12, 0xed, 0xfd, 
                            0xb8, 0x2a, 0x72, 0x98, 0xa4, 0xa0, 0x88, 0x64};

  printf("receiving packet from tun device \n");
  if ((numbytes =  read(tun_fd, buffer, sizeof(buffer))) < 0) {
    printf("received packet failed\n");
  } else {
    printf("listener: got packet %lu bytes\n", numbytes);
    PrintData(buffer, numbytes);
  }
 
  memcpy(buffer1 + 14, buffer, numbytes);
  if (send(raw_fd, buffer1, numbytes + 14, 0) < 0) {
    perror("send (sendPacket)");
  } else {
    printf("packet sent to virbr0\n");
    PrintData(buffer1, numbytes + 14);
  }

}

void recvfrom_tun_device_sendto_ppp_cb1(int fd, short ev, void *arg)
{
  struct ethhdr *ethHd;
  ssize_t numbytes;
  int n, plen, len = 0;
  uint8_t buffer[4096];
  uint8_t buffer1[4096] = {0xa0, 0x8c, 0xfd, 0xe8, 0xe6, 0x27, 
                          0x00, 0xe0, 0x4c, 0x53, 0x44, 0x58, 0x08, 0x00};

  printf("receiving packet from tun device \n");
  if ((numbytes =  read(tun_fd1, buffer, sizeof(buffer))) < 0) {
    printf("received packet failed\n");
  } else {
    printf("listener: got packet %lu bytes\n", numbytes);
    PrintData(buffer, numbytes);
  }
 
  memcpy(buffer1 + 14, buffer, numbytes);
  if (send(raw_fd1, buffer1, numbytes + 14, 0) < 0) {
    perror("send (sendPacket)");
  } else {
    printf("packet sent to virbr0\n");
    PrintData(buffer1, numbytes + 14);
  }

}

void recvfrom_ppp_sendto_tun_device_cb(int fd, short ev, void *arg)
{
  struct ethhdr *ethHd;
  ssize_t numbytes;
  int n, plen, len = 0;
  uint8_t buffer[4096];
  uint8_t buffer2[4096] = {0x00, 0x00, 0x00, 0x00};

  printf("receiving packet from virbr0\n");
  if ((numbytes =  read(fd, buffer, sizeof(buffer))) < 0) {
    printf("received packet failed\n");
  } else {
    printf("listener: got packet %lu bytes\n", numbytes);
    PrintData(buffer, numbytes);
  }
  memmove(buffer, buffer + 14, numbytes - 14);
  //memcpy(buffer2+4, buffer, numbytes); 
  printf("++++++++++writing to tun device tun_fd = %d+++++++++\n", tun_fd);
  if (write(tun_fd, buffer, numbytes - 14) < 0) {
    perror("send (sendPacket)");
  } else {
    printf("packet sent to ppp0\n");
    PrintData(buffer, numbytes - 14);
  }

}

void recvfrom_ppp_sendto_tun_device_cb1(int fd, short ev, void *arg)
{
  struct ethhdr *ethHd;
  ssize_t numbytes;
  int n, plen, len = 0;
  uint8_t buffer[4096];
  uint8_t buffer2[4096] = {0x00, 0x00, 0x00, 0x00};

  printf("receiving packet from virbr0\n");
  if ((numbytes =  read(fd, buffer, sizeof(buffer))) < 0) {
    printf("received packet failed\n");
  } else {
    printf("listener: got packet %lu bytes\n", numbytes);
    PrintData(buffer, numbytes);
  }
  memmove(buffer, buffer + 14, numbytes - 14);
  //memcpy(buffer2+4, buffer, numbytes); 
  printf("++++++++++writing to tun device tun_fd = %d+++++++++\n", tun_fd);
  if (write(tun_fd1, buffer, numbytes - 14) < 0) {
    perror("send (sendPacket)");
  } else {
    printf("packet sent to ppp0\n");
    PrintData(buffer, numbytes - 14);
  }

}

#define ETH_DISC 0x8864
unsigned int Eth_disc = ETH_DISC;

int main(int argc, char *argv[])
{
  int nbytes;
  char buf[1600], dev[10];
  char srcip[20];                     // = "192.168.20.1";
  char dstip[20];                     // = "192.168.20.50";
  struct event_base *evbase;
  struct event *ev;   
  int i = 0;
  char ifname[IFNAMSIZ];
  char ifname1[IFNAMSIZ];

  event_init();
  if((evbase = event_base_new()) == NULL) {
    printf("Unable to create event base ..!!\n");
    return -1;
  }
  
  if(argc < 1) {
    printf("Usage: ./tun [options]\n");
    printf("options:\n");
    printf("       ethernet name \n");
    return -1;
  }
  strcpy(ifname, argv[1]);
  //strcpy(ifname1, argv[2]);
#if 1
  printf("raw socket on %s created \n", ifname);
  raw_fd = create_socket(ETH_P_ALL, ifname);
  //raw_fd = create_socket(Eth_disc, ifname);
  if(raw_fd < 0) {
    perror("failed to create raw socket");
    return -1;
  }
#endif

#if 0
  printf("raw socket on %s created \n", ifname1);
  raw_fd1 = create_socket(ETH_P_ALL, ifname1);
  if(raw_fd1 < 0) {
    perror("failed to create raw socket");
    return -1;
  }
#endif
#if 1
  //printf("raw socket on %s created \n", ifname1);
  //for(i=0; i<2; i++) {
    sprintf(srcip, "20.20.20.5");
    sprintf(dstip, "20.20.20.20");
    //extractIpAddress(srcip, i);
    //extractIpAddress(dstip, i);
    sprintf(dev, "ppp%d", i);
    tun_fd = tun_open(dev, srcip);
    if(tun_fd < 0) {
      printf("failed to create tun device tun_fd = %d\n", tun_fd);
      return -1;
    }
    printf("Device %s opened\n", dev);
    printf("srcip = %s, dstip = %s\n", srcip, dstip);
    sprintf(buf, "ifconfig %s inet %s pointopoint %s up", dev, srcip, dstip);
    system(buf);
  //}
#endif

#if 0
    sprintf(srcip, "30.30.30.30");
    sprintf(dstip, "30.30.30.5");
    sprintf(dev, "ppp%d", 1);
    tun_fd1 = tun_open(dev, srcip);
    if(tun_fd1 < 0) {
      printf("failed to create tun device tun_fd = %d\n", tun_fd1);
      return -1;
    }
    printf("Device %s opened\n", dev);
    printf("srcip = %s, dstip = %s\n", srcip, dstip);
    sprintf(buf, "ifconfig %s inet %s pointopoint %s up", dev, srcip, dstip);
    system(buf);
#endif
#if 1
  ev = event_new(evbase, raw_fd, EV_READ|EV_PERSIST, recvfrom_ppp_sendto_tun_device_cb, NULL);
  if(ev < 0) {
    printf("event failed ..!!\n");
  }
  event_add(ev, NULL);

  ev = event_new(evbase, tun_fd, EV_READ|EV_PERSIST, recvfrom_tun_device_sendto_ppp_cb, NULL);
  if(ev < 0) {
    printf("event failed ..!!\n");
  }
  event_add(ev, NULL);
#endif

#if 0
  ev = event_new(evbase, raw_fd1, EV_READ|EV_PERSIST, recvfrom_ppp_sendto_tun_device_cb1, NULL);
  if(ev < 0) {
    printf("event failed ..!!\n");
  }
  event_add(ev, NULL);

  ev = event_new(evbase, tun_fd1, EV_READ|EV_PERSIST, recvfrom_tun_device_sendto_ppp_cb1, NULL);
  if(ev < 0) {
    printf("event failed ..!!\n");
  }
  event_add(ev, NULL);
#endif
  event_base_dispatch(evbase);
  event_base_free(evbase);

  return 0;
}

