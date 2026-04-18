/*
 * IRC - Internet Relay Chat, include/oper_levels.h
 * Copyright (C) 2026 Cathexis Development
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
 *
 * Defines the official operator hierarchy and convenience macros.
 * #include after client.h where the FLAG_* values are defined.
 *
 * ═══════════════════════════════════════════════════════════════
 *                    OPERATOR HIERARCHY
 *
 * Level 1: Local IRCop (+O)
 *   - Local server operations only
 *   - KILL (local), KLINE, REHASH, CLOSE
 *   - Cannot propagate oper status across links
 *   - Oper block: local = yes; (no propagate privilege)
 *
 * Level 2: IRCop (+o)
 *   - Global network operations
 *   - KILL (global), GLINE, SHUN, ZLINE, CONNECT, SQUIT
 *   - Propagated across server links
 *   - Oper block: propagate = yes;
 *
 * Level 3: Server Administrator (+a)
 *   - Server administration
 *   - RESTART, DIE, SET, REHASH (remote)
 *   - Can see all hidden information (WHOIS, channels)
 *   - Oper block: admin = yes;
 *
 * Level 4: Network Administrator (+N)
 *   - Full network control
 *   - SA* commands (SAJOIN, SAPART, SANICK, SAMODE, SAQUIT, etc.)
 *   - OPMODE, CLEARMODE with FORCE privilege
 *   - Oper block: netadmin = yes;
 *
 *   CRITICAL: +N is NOT granted at /OPER time alone.
 *   The user stays +a (Server Admin) until they authenticate
 *   with NickServ. Only when BOTH conditions are met:
 *     1. Oper block has netadmin = yes  (PRIV_NETADMIN)
 *     2. User is identified with services (IsAccount)
 *   ...does the +N flag activate. If they log out, +N is
 *   revoked and they drop back to +a automatically.
 *
 * Services Integration:
 *   - Services Root Administrator (Synaxis opserv_level >= 900)
 *     MUST ALSO have +N on the IRCd to use SA* commands via services.
 *   - The dual-check prevents privilege escalation from either side.
 *   - +k (FLAG_SERVICE) is for service bots only, never human operators.
 *
 * ═══════════════════════════════════════════════════════════════
 */
#ifndef INCLUDED_oper_levels_h
#define INCLUDED_oper_levels_h

/*
 * Oper level constants for privilege comparison.
 * These match the user mode flags in client.h.
 */
#define OPER_LEVEL_NONE          0   /**< Not an operator */
#define OPER_LEVEL_LOCOP         1   /**< Local IRCop (+O) */
#define OPER_LEVEL_OPER          2   /**< Global IRCop (+o) */
#define OPER_LEVEL_ADMIN         3   /**< Server Administrator (+a) */
#define OPER_LEVEL_NETADMIN      4   /**< Network Administrator (+N) */
#define OPER_LEVEL_SERVICE       5   /**< Network Service (+k) — bots only */

/**
 * Get the numeric oper level of a client.
 * Returns the highest applicable level.
 * Used for comparison: "does this oper outrank that oper?"
 */
static inline int client_oper_level(struct Client *cptr)
{
  if (!cptr) return OPER_LEVEL_NONE;
  if (IsService(cptr))   return OPER_LEVEL_SERVICE;
  if (IsNetAdmin(cptr))  return OPER_LEVEL_NETADMIN;
  if (IsAdmin(cptr))     return OPER_LEVEL_ADMIN;
  if (IsOper(cptr))      return OPER_LEVEL_OPER;
  if (IsLocOp(cptr))     return OPER_LEVEL_LOCOP;
  return OPER_LEVEL_NONE;
}

/**
 * Check if oper A outranks oper B.
 * Used for kill protection, SA* command targeting, etc.
 */
static inline int oper_outranks(struct Client *a, struct Client *b)
{
  return client_oper_level(a) > client_oper_level(b);
}

/**
 * Check if a client has at least the given oper level.
 */
static inline int has_oper_level(struct Client *cptr, int level)
{
  return client_oper_level(cptr) >= level;
}

/**
 * Can this client use SA* commands?
 * Requires Network Administrator (+N) — the highest human oper level.
 * Services (+k) can always send SA* commands via S2S.
 */
#define CanUseSACommands(x) (IsNetAdmin(x) || IsService(x))

#endif /* INCLUDED_oper_levels_h */
