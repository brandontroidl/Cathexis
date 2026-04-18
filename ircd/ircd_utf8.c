/*
 * Copyright (c) Cathexis Development
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * ircd/ircd_utf8.c — UTF-8 validation per RFC 3629.
 *
 * Validates that a byte string contains only valid UTF-8 sequences.
 * Rejects overlong encodings, surrogates (U+D800..U+DFFF), and
 * codepoints above U+10FFFF.
 */

#include "ircd_utf8.h"

int ircd_is_valid_utf8(const char *str, size_t len)
{
  const unsigned char *s = (const unsigned char *)str;
  size_t i = 0;

  if (!s)
    return 1; /* NULL is valid (nothing to reject) */

  /* If len is 0, use strlen-style scan */
  if (len == 0) {
    while (s[i])
      i++;
    len = i;
    i = 0;
  }

  while (i < len) {
    unsigned char c = s[i];
    unsigned int codepoint;
    int nbytes;

    if (c == 0x00) {
      /* Embedded NUL — end of C string, valid */
      break;
    } else if (c < 0x80) {
      /* ASCII: 0xxxxxxx */
      i++;
      continue;
    } else if ((c & 0xE0) == 0xC0) {
      /* 2-byte: 110xxxxx 10xxxxxx */
      nbytes = 2;
      codepoint = c & 0x1F;
    } else if ((c & 0xF0) == 0xE0) {
      /* 3-byte: 1110xxxx 10xxxxxx 10xxxxxx */
      nbytes = 3;
      codepoint = c & 0x0F;
    } else if ((c & 0xF8) == 0xF0) {
      /* 4-byte: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */
      nbytes = 4;
      codepoint = c & 0x07;
    } else {
      /* Invalid leading byte */
      return 0;
    }

    /* Check we have enough bytes */
    if (i + nbytes > len)
      return 0;

    /* Validate continuation bytes */
    for (int j = 1; j < nbytes; j++) {
      if ((s[i + j] & 0xC0) != 0x80)
        return 0;
      codepoint = (codepoint << 6) | (s[i + j] & 0x3F);
    }

    /* Reject overlong encodings */
    if (nbytes == 2 && codepoint < 0x80)
      return 0;
    if (nbytes == 3 && codepoint < 0x800)
      return 0;
    if (nbytes == 4 && codepoint < 0x10000)
      return 0;

    /* Reject surrogates (U+D800..U+DFFF) */
    if (codepoint >= 0xD800 && codepoint <= 0xDFFF)
      return 0;

    /* Reject above U+10FFFF */
    if (codepoint > 0x10FFFF)
      return 0;

    i += nbytes;
  }

  return 1;
}
