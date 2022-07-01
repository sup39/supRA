/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 sup39 */

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <lua.h>
#include <lauxlib.h>
#include "icmpv6.h"
#include "ra.h"

#define PREPARE_get_int() \
  lua_Integer val; \
  int isnum;
#define get_int_field(key, dft) (\
  lua_getfield(L, -1, key), \
  val = lua_tointegerx(L, -1, &isnum), \
  lua_pop(L, 1), \
  isnum ? val : dft )
#define has_int_field(key) (\
  lua_getfield(L, -1, key), \
  val = lua_tointegerx(L, -1, &isnum), \
  lua_pop(L, 1), \
  isnum)
#define get_flag_field(key, lhs, rhs) \
  lua_getfield(L, -1, key); \
  if (lua_toboolean(L, -1)) lhs |= rhs; \
  lua_pop(L, 1);

#define has_int_global(key) (\
  lua_getglobal(L, key), \
  val = lua_tointegerx(L, -1, &isnum), \
  lua_pop(L, 1), \
  isnum)

static void suplua_parse_prefix(lua_State *L, const char *raw, struct in6_addr *addr, uint8_t *pfxlen) {
  /* parse */
  char *ptrSlash = strchr(raw, '/');
  if (ptrSlash == NULL)
    luaL_error(L, "Prefix length is required");
  size_t strlenpfx = ptrSlash-raw;
  if (strlenpfx >= INET6_ADDRSTRLEN)
    luaL_error(L, "Invalid prefix: %s", raw);
  // parse prefix
  char strpfx[INET6_ADDRSTRLEN];
  strncpy(strpfx, raw, strlenpfx);
  strpfx[strlenpfx] = '\0';
  if (inet_pton(AF_INET6, strpfx, addr) <= 0)
    luaL_error(L, "Invalid prefix: %s", raw);
  // parse prefix len
  char *badlen = NULL;
  *pfxlen = strtol(ptrSlash+1, &badlen, 10);
  if (*badlen != '\0')
    luaL_error(L, "Bad prefix length: %s", badlen);
}

static int luaF_prefix_opt(lua_State *L) {
  int n = lua_gettop(L);
  if (!(n == 1 && lua_istable(L, 1)))
    luaL_error(L, "Invalid prefix options\nSyntax: prefix 'PREFIX/LEN' {OPTIONS}");
  struct icmpv6_pfxinfo *pfx = lua_touserdata(L, lua_upvalueindex(1));
  lua_pushvalue(L, 1); // options
  PREPARE_get_int();
  /* options */
  get_flag_field("A", pfx->flags, ICMPV6_PFXINFO_A);
  get_flag_field("L", pfx->flags, ICMPV6_PFXINFO_L);
  if (has_int_field("valid_lft")) pfx->valid_lft = htonl(val);
  if (has_int_field("preferred_lft")) pfx->preferred_lft = htonl(val);
  /* done */
  return 0;
}
static int luaF_prefix(lua_State *L) {
  int n = lua_gettop(L);
  if (!(n == 1 && lua_isstring(L, 1)))
    return luaL_error(L, "Invalid prefix: %s\nSyntax: prefix 'PREFIX/LEN' {OPTIONS}", lua_tostring(L, 1));
  const char *raw = lua_tostring(L, 1);
  // init pfx
  ALLOC_RA_OPTION(struct icmpv6_pfxinfo, pfx);
  pfx->type = ICMPV6_OPT_PFXINFO;
  pfx->len = ICMPV6_OPT_PFXINFO_LEN;
  pfx->flags = 0;
  pfx->valid_lft = htonl(-1);
  pfx->preferred_lft = htonl(-1);
  pfx->_rsvd2 = 0;
  suplua_parse_prefix(L, raw, &pfx->prefix, &pfx->pfxlen);
  // return
  lua_pushlightuserdata(L, pfx);
  lua_pushcclosure(L, luaF_prefix_opt, 1);
  return 1;
}

static int luaF_route_opt(lua_State *L) {
  int n = lua_gettop(L);
  if (!(n == 1 && lua_istable(L, 1)))
    luaL_error(L, "Invalid route options\nSyntax: route 'PREFIX/LEN' {OPTIONS}");
  struct icmpv6_rtinfo *rt = lua_touserdata(L, lua_upvalueindex(1));
  lua_pushvalue(L, 1); // options
  /* options */
  PREPARE_get_int();
  if(has_int_field("lft")) rt->lft = htonl(val);
  // prf
  lua_getfield(L, -1, "prf");
  if (lua_isinteger(L, -1)) {
    rt->flags = (lua_tointeger(L, -1)&3)<<3;
  } else if (lua_isstring(L, -1)) {
    const char *strprf = lua_tostring(L, -1);
    if (*strprf == 'L') rt->flags = ICMPV6_RA_PRF_L;
    else if (*strprf == 'H') rt->flags = ICMPV6_RA_PRF_H;
  }
  /* done */
  return 0;
}
static int luaF_route(lua_State *L) {
  int n = lua_gettop(L);
  if (!(n == 1 && lua_isstring(L, 1)))
    return luaL_error(L, "Invalid route\nSyntax: route 'PREFIX/LEN' {OPTIONS}");
  const char *raw = lua_tostring(L, 1);
  // init pfx
  ALLOC_RA_OPTION(struct icmpv6_rtinfo, rt);
  rt->type = ICMPV6_OPT_RTINFO;
  rt->len = ICMPV6_OPT_RTINFO_LEN;
  rt->flags = ICMPV6_RA_PRF_M;
  rt->lft = htonl(1800);
  suplua_parse_prefix(L, raw, &rt->prefix, &rt->pfxlen);
  // return
  lua_pushlightuserdata(L, rt);
  lua_pushcclosure(L, luaF_prefix_opt, 1);
  return 1;
}

static int luaF_ra(lua_State *L) {
  int n = lua_gettop(L);
  if (!(n == 1 && lua_istable(L, 1)))
    luaL_error(L, "Invalid ra options\nSyntax: ra {OPTIONS}");
  lua_pushvalue(L, 1); // options
  PREPARE_get_int();
  /* options */
  struct icmpv6_ra *ra = get_ra_fields();
  if (has_int_field("hop")) ra->hop = val;
  if (has_int_field("router_lft")) ra->router_lft = htons(val);
  if (has_int_field("reachable_time")) ra->reachable_time = htonl(val);
  if (has_int_field("retrans_timer")) ra->retrans_timer = htonl(val);
  get_flag_field("M", ra->flags, ICMPV6_RA_M);
  get_flag_field("O", ra->flags, ICMPV6_RA_O);
  /* done */
  return 0;
}

static int luaF_dns(lua_State *L) {
  int n = lua_gettop(L);
  if (!(n == 1 && lua_istable(L, 1)))
    luaL_error(L, "Invalid dns options\nSyntax: dns {server1, server2, ..., lft = xxx}");
  lua_pushvalue(L, 1); // options
  PREPARE_get_int();
  /* options */
  ALLOC_RA_OPTION(struct icmpv6_dnsinfo, dns);
  dns->type = ICMPV6_OPT_DNSINFO;
  dns->len = 1;
  dns->_rsvd = 0;
  dns->lft = htonl(get_int_field("lft", -1));
  // iterate dns server ip
  lua_pushnil(L); // dummy key
  while (lua_next(L, 1)) { // [-2]=key, [-1]=value
    // key should be number
    if (lua_isnumber(L, -2)) {
      ALLOC_RA_OPTION(struct in6_addr, addr);
      inet_pton(AF_INET6, lua_tostring(L, -1), addr);
      dns->len += 2; // 128 bit = 8 bytes *2
    }
    // pop value
    lua_pop(L, 1);
  }
  /* done */
  return 0;
}

#define lua_pushglobalfunc(L, name, f) (\
  lua_pushcfunction(L, f), \
  lua_setglobal(L, name))
int supRA_read_option(const char *path) {
  lua_State *L = luaL_newstate();

  // prepare
  lua_pushglobalfunc(L, "prefix", luaF_prefix);
  lua_pushglobalfunc(L, "route", luaF_route);
  lua_pushglobalfunc(L, "ra", luaF_ra);
  lua_pushglobalfunc(L, "dns", luaF_dns);

  // read options
  int rc = luaL_dofile(L, path);
  if (rc != LUA_OK)
    fprintf(stderr, "Fail to read options file (%d):\n%s\n", rc, lua_tostring(L, -1));

  /* vars */
  PREPARE_get_int();
  // interval
  if (has_int_global("interval")) {
    ALLOC_RA_OPTION(struct icmpv6_advintvl, intvl);
    intvl->type = ICMPV6_OPT_ADVINTVL;
    intvl->len = ICMPV6_OPT_ADVINTVL_LEN;
    intvl->_rsvd = 0;
    intvl->interval = htonl(val);
  }

  return rc;
}
