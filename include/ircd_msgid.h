/*
 * Copyright (c) Cathexis Development
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * include/ircd_msgid.h — IRCv3 message ID generation.
 */

#ifndef INCLUDED_ircd_msgid_h
#define INCLUDED_ircd_msgid_h

#include <stddef.h>

/** Length of a generated message ID (32 hex chars) */
#define MSGID_LEN 32

/** Generate a unique message ID (32-char hex string).
 *  Uses OpenSSL RAND_bytes via ircd_crypto.h.
 *  Thread-safe. */
void ircd_msgid_generate(char *buf, size_t buflen);

#endif /* INCLUDED_ircd_msgid_h */
