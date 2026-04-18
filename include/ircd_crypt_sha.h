/** @file ircd_crypt_sha.h
 * @brief SHA-256 and SHA-512 password hashing declarations.
 * Copyright (C) 2026 Brandon Troidl
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef INCLUDED_ircd_crypt_sha_h
#define INCLUDED_ircd_crypt_sha_h

extern const char *ircd_crypt_sha256(const char *key, const char *salt);
extern const char *ircd_crypt_sha512(const char *key, const char *salt);
extern void ircd_register_crypt_sha256(void);
extern void ircd_register_crypt_sha512(void);

#endif /* INCLUDED_ircd_crypt_sha_h */
