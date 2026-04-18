/*
 * Copyright (c) Cathexis Development
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * include/ircd_utf8.h — UTF-8 validation for IRCv3 utf8-only spec.
 */

#ifndef INCLUDED_ircd_utf8_h
#define INCLUDED_ircd_utf8_h

#include <stddef.h>

/** Validate that a string is valid UTF-8.
 *  Returns 1 if valid, 0 if invalid.
 *  NULL or empty strings are considered valid. */
int ircd_is_valid_utf8(const char *str, size_t len);

#endif /* INCLUDED_ircd_utf8_h */
