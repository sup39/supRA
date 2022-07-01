/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 sup39 */

#ifndef supRA_RA_H
#define supRA_RA_H
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>

void init_ra_msg_buf(size_t bufsize);
void *alloc_ra_option(size_t size);
#define ALLOC_RA_OPTION(TYPE, NAME) TYPE *NAME = alloc_ra_option(sizeof(TYPE))
#define ALLOC_RA_OPTION_(TYPE, NAME) NAME = alloc_ra_option(sizeof(TYPE))

struct icmpv6_ra *get_ra_fields();
ssize_t send_ra(int fd, struct sockaddr *caddr, socklen_t caddrlen);

#endif
