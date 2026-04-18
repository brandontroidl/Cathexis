/** @file ircd_crypt_argon2.h
 * @brief Argon2id password hashing for Cathexis IRCd.
 * Copyright (C) 2026 Cathexis Development
 *
 * Memory-hard, GPU/ASIC-resistant, quantum-safe password hashing.
 * Uses libargon2 (apt install libargon2-dev).
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 */
#ifndef INCLUDED_ircd_crypt_argon2_h
#define INCLUDED_ircd_crypt_argon2_h

/** Register the Argon2id crypt mechanism. */
extern void ircd_register_crypt_argon2(void);

/** Hash a password with Argon2id.
 * @param[in] password  Plaintext password.
 * @return Encoded hash string ($argon2id$...) or NULL on failure.
 *         Caller must NOT free — returns pointer to static buffer.
 */
extern const char *ircd_crypt_argon2(const char *password);

/** Verify a password against an Argon2id hash.
 * @param[in] password  Plaintext password to check.
 * @param[in] hash      Encoded Argon2id hash ($argon2id$...).
 * @return 0 if password matches, non-zero otherwise.
 */
extern int ircd_crypt_argon2_verify(const char *password, const char *hash);

#endif /* INCLUDED_ircd_crypt_argon2_h */
