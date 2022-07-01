/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 sup39 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include "ra.h"
#include "icmpv6.h"

static uint8_t
  *ra_msg_buf = NULL,
  *ra_msg_ptr = NULL,
  *ra_msg_buflim = NULL;

void init_ra_msg_buf(size_t bufsize) {
  free(ra_msg_buf); // free previous
  ra_msg_ptr = ra_msg_buf = malloc(bufsize);
  ra_msg_buflim = ra_msg_buf+bufsize;

  /* payload header */
  ALLOC_RA_OPTION(struct icmpv6_head, hw);
  hw->type = ICMPV6_RA;
  hw->code = 0;
  hw->checksum = 0;

  /* message header */
  ALLOC_RA_OPTION(struct icmpv6_ra, ra);
  ra->hop = 64;
  ra->flags = 0;
  ra->router_lft = htons(1800);
  ra->reachable_time = htonl(0);
  ra->retrans_timer = htonl(0);
}

void *alloc_ra_option(size_t size) {
  void *ptr = ra_msg_ptr;
  ra_msg_ptr += size;
  if (ra_msg_ptr > ra_msg_buflim) {
    fputs("Message is too long", stderr);
    exit(EMSGSIZE);
  }
  return ptr;
}

struct msg_header {
  struct icmpv6_head head;
  struct icmpv6_ra ra;
};
struct icmpv6_ra *get_ra_fields() {
  return &((struct msg_header*)ra_msg_buf)->ra;
}

ssize_t send_ra(int fd, struct sockaddr *caddr, socklen_t caddrlen) {
  return sendto(fd, ra_msg_buf, ra_msg_ptr-ra_msg_buf, 0, caddr, caddrlen);
}
