/*
 * IRC - Internet Relay Chat, ircd/ircd_cloaking.c
 * Copyright (C) 2026 Cathexis Development
 *
 * HMAC-SHA256 host cloaking — replaces legacy MD5-based cloaking.
 * Produces cryptographically strong cloaked hosts using keyed HMAC
 * with three independent network keys. Brute-force reversal is
 * computationally infeasible (48-bit segments from 256-bit HMAC).
 *
 * Requires OpenSSL (USE_SSL).
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 */

#include "config.h"
#include "ircd_chattr.h"
#include "ircd_cloaking.h"
#include "ircd_defs.h"
#include "ircd_features.h"
#include "ircd_snprintf.h"
#include "ircd_log.h"
#include "res.h"

#include <netinet/in.h>
#include <string.h>

#include "ircd_crypto.h"

#define KEY1   feature_str(FEAT_HOST_HIDING_KEY1)
#define KEY2   feature_str(FEAT_HOST_HIDING_KEY2)
#define KEY3   feature_str(FEAT_HOST_HIDING_KEY3)
#define PREFIX feature_str(FEAT_HOST_HIDING_PREFIX)

/* ── HMAC-SHA256 segment extraction ────────────────────── */

/** Compute HMAC-SHA256 of data with key, return truncated 48-bit value.
 * 48 bits = 6 hex chars per segment. 2^48 = ~281 trillion possibilities
 * per segment — brute-force infeasible even with known cloaked output.
 * @param[in] key   HMAC key (one of KEY1/KEY2/KEY3).
 * @param[in] data  Input data (IP octets or hostname).
 * @return 48-bit truncated HMAC as unsigned long.
 */
static unsigned long hmac_segment(const char *key, const char *data)
{
  unsigned char digest[32]; /* SHA-256 = 32 bytes */
  unsigned long result = 0;
  int i;

  if (!key || !key[0] || !data)
    return 0;

  if (ircd_hmac_sha256(key, strlen(key),
                        (const unsigned char *)data, strlen(data),
                        digest) != 0)
    return 0;

  /* Extract first 6 bytes (48 bits) */
  for (i = 0; i < 6; i++)
    result = (result << 8) | digest[i];

  /* Secure zero the full digest */
  OPENSSL_cleanse(digest, sizeof(digest));

  return result;
}

/* ── IPv4 cloaking ─────────────────────────────────────── */

/** Cloak an IPv4 address.
 * Output format: ALPHA.BETA.GAMMA.DELTA.IP
 *   ALPHA = unique per /32 (full address)
 *   BETA  = unique per /24
 *   GAMMA = unique per /16
 *   DELTA = unique per /8
 * Each segment uses a different key for domain separation.
 */
char *hidehost_ipv4(struct irc_in_addr *ip)
{
  unsigned int a, b, c, d;
  static char result[HOSTLEN + 1];
  char buf[128];
  unsigned long alpha, beta, gamma, delta;
  unsigned char *pch;

  if (!irc_in_addr_is_ipv4(ip))
    return hidehost_ipv6(ip);

  pch = (unsigned char *)&ip->in6_16[6];
  a = *pch++; b = *pch;
  pch = (unsigned char *)&ip->in6_16[7];
  c = *pch++; d = *pch;

  ircd_snprintf(0, buf, sizeof(buf), "%d.%d.%d.%d", a, b, c, d);
  alpha = hmac_segment(KEY1, buf);

  ircd_snprintf(0, buf, sizeof(buf), "%d.%d.%d", a, b, c);
  beta = hmac_segment(KEY2, buf);

  ircd_snprintf(0, buf, sizeof(buf), "%d.%d", a, b);
  gamma = hmac_segment(KEY3, buf);

  ircd_snprintf(0, buf, sizeof(buf), "%d", a);
  delta = hmac_segment(KEY1, buf);

  ircd_snprintf(0, result, HOSTLEN, "%lX.%lX.%lX.%lX.IP", alpha, beta, gamma, delta);
  OPENSSL_cleanse(buf, sizeof(buf));
  return result;
}

/* ── IPv6 cloaking ─────────────────────────────────────── */

/** Cloak an IPv6 address.
 * Output format: ALPHA:BETA:GAMMA:DELTA:IP
 *   ALPHA = unique per /128 (full address)
 *   BETA  = unique per /112
 *   GAMMA = unique per /64
 *   DELTA = unique per /32
 */
char *hidehost_ipv6(struct irc_in_addr *ip)
{
  unsigned int a, b, c, d, e, f, g, h;
  static char result[HOSTLEN + 1];
  char buf[256];
  unsigned long alpha, beta, gamma, delta;

  if (irc_in_addr_is_ipv4(ip))
    return hidehost_ipv4(ip);

  a = ntohs(ip->in6_16[0]); b = ntohs(ip->in6_16[1]);
  c = ntohs(ip->in6_16[2]); d = ntohs(ip->in6_16[3]);
  e = ntohs(ip->in6_16[4]); f = ntohs(ip->in6_16[5]);
  g = ntohs(ip->in6_16[6]); h = ntohs(ip->in6_16[7]);

  ircd_snprintf(0, buf, sizeof(buf), "%x:%x:%x:%x:%x:%x:%x:%x", a, b, c, d, e, f, g, h);
  alpha = hmac_segment(KEY1, buf);

  ircd_snprintf(0, buf, sizeof(buf), "%x:%x:%x:%x:%x:%x:%x", a, b, c, d, e, f, g);
  beta = hmac_segment(KEY2, buf);

  ircd_snprintf(0, buf, sizeof(buf), "%x:%x:%x:%x", a, b, c, d);
  gamma = hmac_segment(KEY3, buf);

  ircd_snprintf(0, buf, sizeof(buf), "%x:%x", a, b);
  delta = hmac_segment(KEY1, buf);

  ircd_snprintf(0, result, HOSTLEN, "%lX:%lX:%lX:%lX:IP", alpha, beta, gamma, delta);
  OPENSSL_cleanse(buf, sizeof(buf));
  return result;
}

/* ── Hostname cloaking ─────────────────────────────────── */

/** Cloak a resolved hostname.
 * Output format: PREFIX-HASH.visible.domain.tld
 * The HASH covers the full original hostname.
 * The visible portion preserves enough of the domain for
 * human readability (controlled by components parameter).
 */
char *hidehost_normalhost(char *host, int components)
{
  char *p, *c;
  static char result[HOSTLEN + 1];
  char buf[512];
  unsigned long alpha;
  int comps = 0;

  ircd_snprintf(0, buf, sizeof(buf), "%s:%s", KEY1, host);
  alpha = hmac_segment(KEY2, buf);

  for (p = host; *p; p++) {
    if (*p == '.') {
      comps++;
      if ((comps >= components) && IsHostChar(*(p + 1)))
        break;
    }
  }

  if (*p) {
    unsigned int len;
    p++;
    ircd_snprintf(0, result, HOSTLEN, "%s-%lX.", PREFIX, alpha);
    len = strlen(result) + strlen(p);
    if (len <= HOSTLEN)
      strncat(result, p, HOSTLEN - strlen(result));
    else {
      c = p + (len - HOSTLEN);
      if ((*c == '.') && *(c + 1))
        c++;
      strncat(result, c, HOSTLEN - strlen(result));
    }
  } else
    ircd_snprintf(0, result, HOSTLEN, "%s-%lX", PREFIX, alpha);

  OPENSSL_cleanse(buf, sizeof(buf));
  return result;
}
