/** @file ircd_crypt_sha.h
 * @brief SHA-256 and SHA-512 password hashing declarations.
 */
#ifndef INCLUDED_ircd_crypt_sha_h
#define INCLUDED_ircd_crypt_sha_h

extern const char *ircd_crypt_sha256(const char *key, const char *salt);
extern const char *ircd_crypt_sha512(const char *key, const char *salt);
extern void ircd_register_crypt_sha256(void);
extern void ircd_register_crypt_sha512(void);

#endif /* INCLUDED_ircd_crypt_sha_h */
