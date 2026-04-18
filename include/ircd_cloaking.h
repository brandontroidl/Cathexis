/** @file ircd_cloaking.h
 * @brief HMAC-SHA256 host cloaking.
 * Legacy MD5 cloaking removed in Cathexis 1.4.0.
 */
#ifndef INCLUDED_ircd_cloaking_h
#define INCLUDED_ircd_cloaking_h

#include "config.h"
#include "res.h"

extern char *hidehost_ipv4(struct irc_in_addr *ip);
extern char *hidehost_ipv6(struct irc_in_addr *ip);
extern char *hidehost_normalhost(char *host, int components);

#endif /* INCLUDED_ircd_cloaking_h */
