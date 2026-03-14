/** @file ircd_cloaking.h
 * @brief Public declarations and APIs for IP and host cloaking functions.
 * @version $Id$
 */
#ifndef INCLUDED_ircd_cloaking_h
#define INCLUDED_ircd_cloaking_h

#include "config.h"
#include "res.h"

extern char *hidehost_ipv4(struct irc_in_addr *ip);
extern char *hidehost_ipv6(struct irc_in_addr *ip);
extern char *hidehost_normalhost(char *host, int components);

#ifdef USE_SSL
extern char *hidehost_ipv4_hmac(struct irc_in_addr *ip);
extern char *hidehost_ipv6_hmac(struct irc_in_addr *ip);
extern char *hidehost_normalhost_hmac(char *host, int components);
#endif

#endif /* INCLUDED_ircd_cloaking_h */

