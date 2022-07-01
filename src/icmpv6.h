/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 sup39 */

#ifndef sup_ICMPV6_H
#define sup_ICMPV6_H
#include <netinet/in.h>
#include <stdint.h>

struct icmpv6_head {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
};
#define ICMPV6_RS 133
#define ICMPV6_RA 134
#define ICMPV6_OPT_SRCLINKADDR   1
#define ICMPV6_OPT_TGTLINKADDR   2
#define ICMPV6_OPT_PFXINFO       3
#define ICMPV6_OPT_PFXINFO_LEN   4
#define ICMPV6_OPT_MTU           5
#define ICMPV6_OPT_MTU_LEN       1
#define ICMPV6_OPT_ADVINTVL      7
#define ICMPV6_OPT_ADVINTVL_LEN  1
#define ICMPV6_OPT_RTINFO       24
#define ICMPV6_OPT_RTINFO_LEN    3
#define ICMPV6_OPT_DNSINFO      25
struct icmpv6_rs {
  uint32_t _rsvd;
};
#define ICMPV6_RA_M     0x80
#define ICMPV6_RA_O     0x40
#define ICMPV6_RA_H     0x20
#define ICMPV6_RA_PRF_H 0x08
#define ICMPV6_RA_PRF_M 0x00
#define ICMPV6_RA_PRF_L 0x18
#define ICMPV6_RA_P     0x04
struct icmpv6_ra {
  uint8_t hop;
  uint8_t flags;
  uint16_t router_lft;
  uint32_t reachable_time;
  uint32_t retrans_timer;
};
struct icmpv6_option {
  uint8_t type;
  uint8_t len;
};
struct icmpv6_linkaddr {
  uint8_t type;
  uint8_t len;
  uint8_t addr[6];
};
#define ICMPV6_PFXINFO_L 0x80
#define ICMPV6_PFXINFO_A 0x40
struct icmpv6_pfxinfo {
  uint8_t type;
  uint8_t len;
  uint8_t pfxlen;
  uint8_t flags;
  uint32_t valid_lft;
  uint32_t preferred_lft;
  uint32_t _rsvd2;
  struct in6_addr prefix;
};
struct icmpv6_mtu {
  uint8_t type;
  uint8_t len;
  uint16_t _rsvd;
  uint32_t mtu;
};
struct icmpv6_advintvl {
  uint8_t type;
  uint8_t len;
  uint16_t _rsvd;
  uint32_t interval;
};
struct icmpv6_rtinfo {
  uint8_t type;
  uint8_t len;
  uint8_t pfxlen;
  uint8_t flags;
  uint32_t lft;
  struct in6_addr prefix;
};
struct icmpv6_dnsinfo {
  uint8_t type;
  uint8_t len;
  uint16_t _rsvd;
  uint32_t lft;
};

#endif
