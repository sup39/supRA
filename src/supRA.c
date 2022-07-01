/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 sup39 */

#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <netinet/icmp6.h>
#include <lua.h>
#include <lauxlib.h>
#include "icmpv6.h"
#include "ra.h"
#include "options.h"

#define NEXT_STRUCT(s, p) (struct s*)p; p += sizeof(struct s)
#define DEF_NEXT_STRUCT(s, v, p) struct s *v = NEXT_STRUCT(s, p);

static void init_ra_msg(int if_mtu, uint8_t if_macaddr[6]) {
  /** link addr **/
  ALLOC_RA_OPTION(struct icmpv6_linkaddr, linkaddr);
  linkaddr->type = ICMPV6_OPT_SRCLINKADDR;
  linkaddr->len = 1;
  memcpy(linkaddr->addr, if_macaddr, 6);

  /** MTU **/
  ALLOC_RA_OPTION(struct icmpv6_mtu, mtu);
  mtu->type = ICMPV6_OPT_MTU;
  mtu->len = ICMPV6_OPT_MTU_LEN;
  mtu->_rsvd = 0;
  mtu->mtu = htonl(if_mtu);
}

#define PERROR_EXIT(msg) {perror(msg); exit(errno);}
int main(int argc, char *argv[]) {
  if (argc <= 2) {
    fprintf(stderr, "Usage: %s IFNAME CONFIG.lua\n", argv[0]);
    return 1;
  }

  const char *ifname = argv[1];
  int ifid = if_nametoindex(ifname);
  if (ifid == 0) PERROR_EXIT("Bad Interface");

  /** get link info (man netdevice) **/
  int if_mtu;
  uint8_t if_macaddr[6];
  struct ifreq ifr;
  strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
  int iofd = socket(AF_INET6, SOCK_DGRAM, 0);
  if (iofd < 0) PERROR_EXIT("Fail to create socket");
  // macaddr
  if (ioctl(iofd, SIOCGIFHWADDR, &ifr)) PERROR_EXIT("Fail to ioctl(HWADDR)");
  memcpy(if_macaddr, &ifr.ifr_hwaddr.sa_data, sizeof(if_macaddr));
  // mtu
  if (if_mtu <= 0) {
    if (ioctl(iofd, SIOCGIFMTU, &ifr)) PERROR_EXIT("Fail to ioctl(MTU)");
    if_mtu = ifr.ifr_mtu;
  }
  // clean
  close(iofd);

  int sfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  if (sfd < 0) PERROR_EXIT("Fail to create socket");

  /* prepare ra message */
  init_ra_msg_buf(if_mtu-40); // sizeof ICMPv6 header = 40
  init_ra_msg(if_mtu, if_macaddr);
  if (supRA_read_option(argv[2])) return 1;

  /** join ff02::2 **/
  struct ipv6_mreq mreq;
  int hoplimit;
  inet_pton(AF_INET6, "ff02::2", &mreq.ipv6mr_multiaddr);
  mreq.ipv6mr_interface = ifid;
  if (setsockopt(sfd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
    PERROR_EXIT("Fail to setsockopt(ADD_MEMBERSHIP)");
  hoplimit = 255;
  if (setsockopt(sfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hoplimit, sizeof(hoplimit)) < 0)
    PERROR_EXIT("Fail to setsockopt(HOPS)");
  if (setsockopt(sfd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hoplimit, sizeof(hoplimit)) < 0)
    PERROR_EXIT("Fail to setsockopt(HOPS)");
  if (setsockopt(sfd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) < 0)
    PERROR_EXIT("Fail to setsockopt(BINDTODEVICE)");

  struct icmp6_filter filter;
  ICMP6_FILTER_SETBLOCKALL(&filter);
  ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filter);
  if (setsockopt(sfd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) < 0)
    PERROR_EXIT("Fail to setsockopt(ICMP6_FILTER)");

  /** ff02::1 **/
  struct sockaddr_in6 bcaddr;
  bcaddr.sin6_family = AF_INET6;
  bcaddr.sin6_port = 0;
  inet_pton(AF_INET6, "ff02::1", &bcaddr.sin6_addr);
  bcaddr.sin6_scope_id = ifid;
  socklen_t bcaddrlen = sizeof(bcaddr);

  /** epoll **/
  int epfd = epoll_create1(0);
  if (epfd < 0) PERROR_EXIT("Fail to create epoll");
  struct epoll_event ev = {
    .events = EPOLLIN,
    .data.fd = sfd,
  };
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev))
    PERROR_EXIT("Fail to epoll_ctl(ADD)");
  const int evcnt = 1;
  struct epoll_event evs[evcnt];

  /** loop **/
  srand(time(NULL));
  time_t tnext = time(NULL);
  while (1) {
    time_t now = time(NULL);
    if (now >= tnext) { // advertise right now
      send_ra(sfd, (struct sockaddr*)&bcaddr, bcaddrlen);
      tnext = now + 200 + 400*rand()/RAND_MAX; // TODO
      puts("to ff02::1");
    }

    int evc = epoll_wait(epfd, evs, evcnt, tnext-now);
    if (evc < 0) PERROR_EXIT("Fail to epoll_wait");
    while (evc--) {
      uint32_t fd = evs[evc].data.fd;
      uint8_t buf[4096];
      char caddr_p[INET6_ADDRSTRLEN];
      struct sockaddr_in6 caddr;
      socklen_t caddrlen = sizeof(caddr);
      ssize_t buflen = recvfrom(sfd, buf, sizeof(buf), 0, (struct sockaddr*)&caddr, &caddrlen);
      if (buflen < 0) PERROR_EXIT("Fail to recvfrom()");
      if (buflen < sizeof(struct icmpv6_head)) continue; // bad message
      // if (caddr.sin6_scope_id != ifid) continue;
      inet_ntop(AF_INET6, &caddr.sin6_addr, caddr_p, sizeof(caddr_p));
      // struct icmpv6_head *h = (struct icmpv6_head*)buf;
      send_ra(sfd, (struct sockaddr*)&caddr, caddrlen);
      printf("to %s%%%d\n", caddr_p, caddr.sin6_scope_id);
    }
  }
  return 0;
}
