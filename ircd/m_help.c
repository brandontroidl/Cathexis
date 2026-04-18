/*
 * IRC - Internet Relay Chat, ircd/m_help.c
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
 * Comprehensive privilege-aware help system. The command index
 * shown by /HELP with no arguments is filtered based on the
 * user's privilege level:
 *
 *   Regular users:  User commands + Reference topics
 *   IRC Operators:  + Oper commands
 *   Network Admin:  + SA* commands + Server management
 *
 * Individual command lookups (/HELP <command>) always show the
 * full help text regardless of privilege, so users can learn
 * what commands exist. Each entry shows its requirements.
 *
 * /HELPOP is registered as an alias for /HELP.
 *
 * Uses RPL_HELPSTART (704), RPL_HELPTXT (705), RPL_ENDOFHELP (706).
 */
#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "s_user.h"

#include <string.h>

/* Privilege levels for index filtering */
#define HELP_USER    0   /* Everyone sees these */
#define HELP_OPER    1   /* Requires +o/+O/+a */
#define HELP_ADMIN   2   /* Requires +N (network admin) */
#define HELP_S2S     3   /* Server-only, never shown in index */

/** Extended help entry for a command or topic. */
struct HelpEntry {
  const char *name;
  const char *category;
  int         level;      /* HELP_USER/HELP_OPER/HELP_ADMIN/HELP_S2S */
  const char *lines[48];  /* NULL-terminated help text */
};

/** Send a help text line using RPL_HELPTXT (705). */
static void
help_line(struct Client *sptr, const char *topic, const char *text)
{
  send_reply(sptr, RPL_HELPTXT, topic, "", text);
}

/** Get the privilege level of a client for help filtering. */
static int
help_level(struct Client *sptr)
{
  if (IsNetAdmin(sptr))       return HELP_ADMIN;
  if (IsAnOper(sptr))         return HELP_OPER;
  return HELP_USER;
}

/*
 * ═══════════════════════════════════════════════════════════════
 *                    HELP DATABASE
 *
 * Every command registered in parse.c msgtab[] is documented here.
 * Server-internal commands (BURST, ACCOUNT, etc.) are level S2S
 * and never appear in the index.
 * ═══════════════════════════════════════════════════════════════
 */
static const struct HelpEntry helptab[] = {

  /* ═══ USER COMMANDS ═══════════════════════════════════════════ */

  { "PRIVMSG", "User", HELP_USER,
    { "Usage: PRIVMSG <target> :<message>",
      "  Alias: /MSG",
      " ",
      "  Send a message to a user or channel.",
      "  Target can be a nickname, #channel, @#channel (ops only),",
      "  %#channel (halfops+), or +#channel (voiced+).",
      " ",
      "  Examples:  /MSG #chat Hello   /MSG NickName Hi",
      NULL } },
  { "NOTICE", "User", HELP_USER,
    { "Usage: NOTICE <target> :<message>",
      " ",
      "  Send a notice. Clients must not auto-reply to notices.",
      "  Same target rules as PRIVMSG.",
      NULL } },
  { "JOIN", "User", HELP_USER,
    { "Usage: JOIN <#channel>[,#chan2] [<key>[,key2]]",
      " ",
      "  Join one or more channels. If a channel does not exist,",
      "  it is created and you become the channel operator.",
      "  Use JOIN 0 to part all channels.",
      " ",
      "  Examples:  /JOIN #chat   /JOIN #priv secretkey",
      NULL } },
  { "PART", "User", HELP_USER,
    { "Usage: PART <#channel>[,#chan2] [:<reason>]",
      " ",
      "  Leave one or more channels with an optional part message.",
      NULL } },
  { "NICK", "User", HELP_USER,
    { "Usage: NICK <newnick>",
      " ",
      "  Change your nickname. Must not exceed NICKLEN, start with",
      "  a letter or allowed special character.",
      NULL } },
  { "MODE", "User", HELP_USER,
    { "Usage: MODE <target> [<modes> [<params>]]",
      " ",
      "  View or change modes on a channel or user.",
      "  See: USERMODES, CHANMODES, CHANPREFIXES, EXTBANS",
      " ",
      "  Channel examples:",
      "    /MODE #chan +o Nick          Give op",
      "    /MODE #chan +b *!*@bad.host  Set ban",
      "    /MODE #chan +im              Invite-only + moderated",
      " ",
      "  User examples:",
      "    /MODE YourNick +ix           Invisible + cloaked host",
      "    /MODE YourNick +s +nKg       Oper notices: net/kills/glines",
      NULL } },
  { "TOPIC", "User", HELP_USER,
    { "Usage: TOPIC <#channel> [:<new topic>]",
      " ",
      "  View or change a channel topic. Requires +o if channel is +t.",
      NULL } },
  { "KICK", "User", HELP_USER,
    { "Usage: KICK <#channel> <nick> [:<reason>]",
      " ",
      "  Remove a user from a channel. Requires channel op (+o).",
      "  Protected (+a) and owner (+q) users cannot be kicked by ops.",
      NULL } },
  { "INVITE", "User", HELP_USER,
    { "Usage: INVITE <nick> <#channel>",
      " ",
      "  Invite a user to a channel. For +i channels, requires +o.",
      NULL } },
  { "WHO", "User", HELP_USER,
    { "Usage: WHO <mask> [<flags>]",
      " ",
      "  Search for users matching a mask. Supports WHOX extensions.",
      "  Flags: o (opers only), n (nick match), u (user match),",
      "         h (host match), a (account match), r (realname match).",
      NULL } },
  { "WHOIS", "User", HELP_USER,
    { "Usage: WHOIS [<server>] <nick>",
      " ",
      "  Detailed information about a user: channels, idle time,",
      "  server, account, SSL status, away message.",
      NULL } },
  { "WHOWAS", "User", HELP_USER,
    { "Usage: WHOWAS <nick> [<count>]",
      " ",
      "  Look up a user who has recently disconnected.",
      NULL } },
  { "LIST", "User", HELP_USER,
    { "Usage: LIST [<params>]",
      " ",
      "  List channels. Filters: >N (min users), <N (max users),",
      "  T>N / T<N (topic changed within N minutes).",
      "  /LIST ? for full filter help.",
      NULL } },
  { "NAMES", "User", HELP_USER,
    { "Usage: NAMES <#channel>",
      "  Show all visible users in a channel with prefixes (~&@%+).",
      NULL } },
  { "AWAY", "User", HELP_USER,
    { "Usage: AWAY [:<message>]",
      "  Mark yourself away, or clear away with no argument.",
      NULL } },
  { "QUIT", "User", HELP_USER,
    { "Usage: QUIT [:<reason>]",
      "  Disconnect from the server.",
      NULL } },
  { "WATCH", "User", HELP_USER,
    { "Usage: WATCH [+|-]<nick>  |  WATCH S|L|C",
      " ",
      "  Notification list for user signon/signoff.",
      "  +Nick = add, -Nick = remove, C = clear, S = status, L = list.",
      NULL } },
  { "SILENCE", "User", HELP_USER,
    { "Usage: SILENCE [+|-]<mask>",
      " ",
      "  Server-side ignore. Messages from matching masks are dropped",
      "  before reaching you. No argument shows current list.",
      NULL } },
  { "WALLCHOPS", "User", HELP_USER,
    { "Usage: WALLCHOPS <#channel> :<message>",
      "  Notice to all channel ops (+o/+h) on a channel.",
      NULL } },
  { "WALLVOICES", "User", HELP_USER,
    { "Usage: WALLVOICES <#channel> :<message>",
      "  Notice to all voiced (+v) and above on a channel.",
      NULL } },
  { "WALLHOPS", "User", HELP_USER,
    { "Usage: WALLHOPS <#channel> :<message>",
      "  Notice to all halfops (+h) and above on a channel.",
      NULL } },
  { "CPRIVMSG", "User", HELP_USER,
    { "Usage: CPRIVMSG <nick> <#channel> :<message>",
      "  Private message via shared channel (bypasses target limits).",
      NULL } },
  { "CNOTICE", "User", HELP_USER,
    { "Usage: CNOTICE <nick> <#channel> :<message>",
      "  Notice via shared channel (bypasses target limits).",
      NULL } },
  { "ISON", "User", HELP_USER,
    { "Usage: ISON <nick> [<nick2> ...]",
      "  Check which nicknames are online. Returns those that are.",
      NULL } },
  { "USERHOST", "User", HELP_USER,
    { "Usage: USERHOST <nick> [<nick2> ...]",
      "  Return user@host for up to 5 nicknames.",
      NULL } },
  { "USERIP", "User", HELP_USER,
    { "Usage: USERIP <nick> [<nick2> ...]",
      "  Return user@ip for up to 5 nicknames.",
      "  IP is visible to opers or if you query yourself.",
      NULL } },
  { "LUSERS", "User", HELP_USER,
    { "Usage: LUSERS",
      "  Network stats: users, invisible, opers, channels, servers.",
      NULL } },
  { "MAP", "User", HELP_USER,
    { "Usage: MAP",
      "  Visual map of all servers with user counts and lag.",
      NULL } },
  { "LINKS", "User", HELP_USER,
    { "Usage: LINKS [<mask>]",
      "  Show servers linked to the network.",
      NULL } },
  { "TIME", "User", HELP_USER,
    { "Usage: TIME [<server>]",
      "  Show current date and time on the server.",
      NULL } },
  { "VERSION", "User", HELP_USER,
    { "Usage: VERSION [<server>]",
      "  Show IRC server software version and features.",
      NULL } },
  { "ADMIN", "User", HELP_USER,
    { "Usage: ADMIN [<server>]",
      "  Show administrative contact information.",
      NULL } },
  { "INFO", "User", HELP_USER,
    { "Usage: INFO [<server>]",
      "  Show server version, compile options, credits.",
      NULL } },
  { "MOTD", "User", HELP_USER,
    { "Usage: MOTD [<server>]",
      "  Show the Message of the Day.",
      NULL } },
  { "RULES", "User", HELP_USER,
    { "Usage: RULES",
      "  Show the network rules file.",
      NULL } },
  { "PING", "User", HELP_USER,
    { "Usage: PING <server>",
      "  Test connection latency. Server responds with PONG.",
      NULL } },
  { "TRACE", "User", HELP_USER,
    { "Usage: TRACE [<server>]",
      "  Show connection path between you and a server.",
      NULL } },
  { "STATS", "User", HELP_USER,
    { "Usage: STATS <letter> [<server>]",
      " ",
      "  Query server statistics. Letters:",
      "    c = connects   f = features    g = G-lines     i = clients",
      "    k = K-lines    l = connections  m = commands    o = oper blocks",
      "    p = ports      u = uptime       t = traffic     y = classes",
      "    z = memory     G = shuns        Z = Z-lines",
      " ",
      "  Some letters require oper. /STATS ? for full list.",
      NULL } },
  { "IRCOPS", "User", HELP_USER,
    { "Usage: IRCOPS",
      "  List all visible IRC operators currently online.",
      NULL } },
  { "MKPASSWD", "User", HELP_USER,
    { "Usage: MKPASSWD <password> [ARGON2|BCRYPT|SHA512|SHA256|PLAIN]",
      " ",
      "  Generate a hashed password for ircd.conf.",
      "  Default: ARGON2 (if available), SHA512 otherwise.",
      "  Recommended: ARGON2 (memory-hard, quantum-safe).",
      "  Legacy MD5/SMD5 removed in Cathexis 1.4.0.",
      NULL } },
  { "ISNEF", "User", HELP_USER,
    { "Usage: ISNEF",
      "  Check if server is running Cathexis IRCd.",
      NULL } },
  { "SETHOST", "User", HELP_USER,
    { "Usage: SETHOST <new.host>",
      " ",
      "  Change your visible hostname.",
      "  Requires SETHOST or FREEFORM privilege.",
      NULL } },

  /* ═══ IRCV3 COMMANDS ═════════════════════════════════════════ */

  { "CAP", "IRCv3", HELP_USER,
    { "Usage: CAP <subcommand> [:<capabilities>]",
      " ",
      "  IRCv3 capability negotiation.",
      "    CAP LS [302]   List capabilities    CAP REQ <caps>  Request",
      "    CAP LIST        List enabled         CAP END         Finish",
      " ",
      "  Available capabilities:",
      "    multi-prefix  userhost-in-names  extended-join  away-notify",
      "    account-notify  account-tag  sasl  tls  cap-notify",
      "    server-time  message-tags  echo-message  invite-notify",
      "    chghost  setname  batch  labeled-response  standard-replies",
      "    sts (Strict Transport Security — informational, not requestable)",
      " ",
      "  STS: Advertised in CAP LS 302 as sts=port=<port>,duration=<secs>.",
      "  Tells clients to reconnect via TLS and remember the policy.",
      " ",
      "  Example:  CAP LS 302 / CAP REQ :multi-prefix sasl / CAP END",
      NULL } },
  { "AUTHENTICATE", "IRCv3", HELP_USER,
    { "Usage: AUTHENTICATE <mechanism|data>",
      " ",
      "  SASL authentication during registration.",
      "  Requires CAP sasl. Mechanisms: PLAIN, EXTERNAL.",
      " ",
      "  PLAIN:    AUTHENTICATE PLAIN / AUTHENTICATE <base64>",
      "  EXTERNAL: AUTHENTICATE EXTERNAL / AUTHENTICATE +",
      " ",
      "  Successful auth sets account (+r). Logged to SNO +a.",
      NULL } },
  { "SETNAME", "IRCv3", HELP_USER,
    { "Usage: SETNAME :<new realname>",
      "  Change your realname (GECOS). Requires setname capability.",
      NULL } },
  { "TAGMSG", "IRCv3", HELP_USER,
    { "Usage: TAGMSG <target>",
      "  Tag-only message (typing indicators, reactions).",
      "  Requires message-tags capability.",
      NULL } },



  /* ═══ OPER COMMANDS ══════════════════════════════════════════ */

  { "OPER", "Oper", HELP_OPER,
    { "Usage: OPER <name> <password>",
      " ",
      "  Authenticate as an IRC operator using ircd.conf credentials.",
      "  Levels: +O local, +o global, +a admin, +N netadmin.",
      "  Use /PRIVS to see granted privileges after opering.",
      NULL } },
  { "KILL", "Oper", HELP_OPER,
    { "Usage: KILL <nick> :<reason>",
      " ",
      "  Forcefully disconnect a user. Logged to SNO +K.",
      " ",
      "  Requires: IRC Operator (+o) with KILL privilege",
      NULL } },
  { "GLINE", "Oper", HELP_OPER,
    { "Usage: GLINE [!]<user@host> [<duration> :<reason>]",
      " ",
      "  Network-wide ban. Duration: <N>s/m/h/d, 0=permanent.",
      "    /GLINE +*@bad.host 1d :Spamming",
      "    /GLINE -*@bad.host                (remove)",
      "  Logged to SNO +g. Auto-G-lines logged to +G.",
      " ",
      "  Requires: IRC Operator with GLINE privilege",
      NULL } },
  { "SHUN", "Oper", HELP_OPER,
    { "Usage: SHUN [!]<user@host> [<duration> :<reason>]",
      " ",
      "  Network-wide shun. User can connect but not send commands.",
      "    /SHUN +*@troll.host 6h :Flooding",
      "  Logged to SNO +S.",
      " ",
      "  Requires: IRC Operator with SHUN privilege",
      NULL } },
  { "ZLINE", "Oper", HELP_OPER,
    { "Usage: ZLINE [!]<ip> [<duration> :<reason>]",
      " ",
      "  IP-based ban. Checked before full registration.",
      "    /ZLINE +1.2.3.4 1d :Brute force",
      "    /ZLINE +1.2.3.0/24 7d :Botnet range",
      "  Logged to SNO +Z.",
      " ",
      "  Requires: IRC Operator with ZLINE privilege",
      NULL } },
  { "TEMPSHUN", "Oper", HELP_OPER,
    { "Usage: TEMPSHUN <nick> :<reason>",
      " ",
      "  Temporary shun lasting until the user disconnects.",
      " ",
      "  Requires: IRC Operator with TEMPSHUN privilege",
      NULL } },
  { "REMOVE", "Oper", HELP_OPER,
    { "Usage: REMOVE <type> <mask>",
      " ",
      "  Force-remove a G-line, Shun, or Z-line by mask.",
      " ",
      "  Requires: IRC Operator with REMOVE privilege",
      NULL } },
  { "WALLOPS", "Oper", HELP_OPER,
    { "Usage: WALLOPS :<message>",
      "  Broadcast to all users with +w mode.",
      "  Requires: IRC Operator",
      NULL } },
  { "WALLUSERS", "Oper", HELP_OPER,
    { "Usage: WALLUSERS :<message>",
      "  Broadcast to ALL connected users.",
      "  Requires: IRC Operator",
      NULL } },
  { "OPMODE", "Oper", HELP_OPER,
    { "Usage: OPMODE <#channel> <modes> [<params>]",
      " ",
      "  Channel modes with operator override. Logged to SNO +h.",
      " ",
      "  Requires: IRC Operator with OPMODE privilege",
      "  See also: SAMODE, CLEARMODE",
      NULL } },
  { "CLEARMODE", "Oper", HELP_OPER,
    { "Usage: CLEARMODE <#channel> <modes>",
      " ",
      "  Remove ALL instances of specified modes from a channel.",
      "    /CLEARMODE #chan b      Clear all bans",
      "    /CLEARMODE #chan ovhb   Clear ops, voices, halfops, bans",
      " ",
      "  Requires: IRC Operator with OPMODE privilege",
      NULL } },
  { "CHECK", "Oper", HELP_OPER,
    { "Usage: CHECK <nick|#channel|host|ip>",
      " ",
      "  Detailed inspection of a user, channel, or hostmask.",
      "  Shows IPs, modes, bans, members, marks, and more.",
      " ",
      "  Requires: IRC Operator with CHECK privilege",
      NULL } },
  { "PRIVS", "Oper", HELP_OPER,
    { "Usage: PRIVS [<nick>]",
      "  Show IRC operator privileges for yourself or another oper.",
      "  Requires: IRC Operator",
      NULL } },
  { "SQUIT", "Oper", HELP_OPER,
    { "Usage: SQUIT <server> :<reason>",
      "  Disconnect a server from the network.",
      "  Requires: IRC Operator",
      NULL } },
  { "CONNECT", "Oper", HELP_OPER,
    { "Usage: CONNECT <server> [<port> [<remote>]]",
      "  Instruct a server to connect to another.",
      "  Requires: IRC Operator",
      NULL } },
  { "REHASH", "Oper", HELP_OPER,
    { "Usage: REHASH [<server>]",
      "  Reload the server configuration file.",
      "  Requires: IRC Operator with REHASH privilege",
      NULL } },
  { "RESTART", "Oper", HELP_OPER,
    { "Usage: RESTART [:<reason>]",
      "  Restart the IRC server process.",
      "  Requires: IRC Operator with RESTART privilege",
      NULL } },
  { "DIE", "Oper", HELP_OPER,
    { "Usage: DIE [:<reason>]",
      "  Shut down the IRC server.",
      "  Requires: IRC Operator with DIE privilege",
      NULL } },
  { "SET", "Oper", HELP_OPER,
    { "Usage: SET <feature> [<value>]",
      "  View or change a runtime feature. /STATS f for all features.",
      "  Requires: IRC Operator with SET privilege",
      NULL } },
  { "GET", "Oper", HELP_OPER,
    { "Usage: GET <feature>",
      "  View a runtime feature value.",
      "  Requires: IRC Operator",
      NULL } },
  { "RESET", "Oper", HELP_OPER,
    { "Usage: RESET <feature>",
      "  Reset a feature to its default.",
      "  Requires: IRC Operator with SET privilege",
      NULL } },
  { "CLOSE", "Oper", HELP_OPER,
    { "Usage: CLOSE",
      "  Close all unregistered connections to this server.",
      "  Requires: IRC Operator",
      NULL } },
  { "JUPE", "Oper", HELP_OPER,
    { "Usage: JUPE <server> [<duration> :<reason>]",
      "  Prevent a server name from being used on the network.",
      "  Requires: IRC Operator with JUPE privilege",
      NULL } },
  { "OPERMOTD", "Oper", HELP_OPER,
    { "Usage: OPERMOTD",
      "  Show the Operator Message of the Day.",
      "  Requires: IRC Operator",
      NULL } },
  { "SETTIME", "Oper", HELP_OPER,
    { "Usage: SETTIME <timestamp> [<server>]",
      "  Synchronize server clocks.",
      "  Requires: IRC Operator with SET privilege",
      NULL } },
  { "RPING", "Oper", HELP_OPER,
    { "Usage: RPING <server>",
      "  Measure round-trip time to a remote server via IRC protocol.",
      "  Requires: IRC Operator",
      NULL } },
  { "UPING", "Oper", HELP_OPER,
    { "Usage: UPING <server>",
      "  Measure round-trip time via UDP ping.",
      "  Requires: IRC Operator",
      NULL } },
  { "ASLL", "Oper", HELP_OPER,
    { "Usage: ASLL <server>",
      "  Show asymmetric link latency to a server.",
      "  Requires: IRC Operator",
      NULL } },
  { "XQUERY", "Oper", HELP_OPER,
    { "Usage: XQUERY <service> :<query>",
      "  Send a query to a network service.",
      "  Requires: IRC Operator",
      NULL } },

  /* ═══ NETWORK ADMIN (SA*) COMMANDS ═══════════════════════════ */

  { "SAJOIN", "Admin", HELP_ADMIN,
    { "Usage: SAJOIN <nick> <#channel[,#channel2,...]>",
      " ",
      "  Force a user to join channels, bypassing ALL restrictions:",
      "  +i, +b, +l, +k, +r, +Z, and all extbans.",
      "  Logged to SNO +C.",
      " ",
      "  Requires: Network Administrator (+N)",
      NULL } },
  { "SAPART", "Admin", HELP_ADMIN,
    { "Usage: SAPART <nick> <#channel[,#chan2]> [:<reason>]",
      " ",
      "  Force a user to part channels. Logged to SNO +C.",
      " ",
      "  Requires: Network Administrator (+N)",
      NULL } },
  { "SACYCLE", "Admin", HELP_ADMIN,
    { "Usage: SACYCLE <nick> <#channel[,#chan2]>",
      " ",
      "  Force a user to part and rejoin channels (cycle).",
      "  The user is parted with reason \"Cycling\" then",
      "  immediately rejoined. Logged to SNO +C.",
      " ",
      "  Requires: Network Administrator (+N)",
      NULL } },
  { "SANICK", "Admin", HELP_ADMIN,
    { "Usage: SANICK <nick> <newnick>",
      " ",
      "  Force a nickname change. Logged to SNO +C.",
      " ",
      "  Requires: Network Administrator (+N)",
      NULL } },
  { "SAMODE", "Admin", HELP_ADMIN,
    { "Usage: SAMODE <target> <modes> [<params>]",
      " ",
      "  Force mode changes on channel or user. Bypasses all checks.",
      "  This is the primary way to set owner/protect modes:",
      "    /SAMODE #chan +q Nick   Set owner (~)",
      "    /SAMODE #chan +a Nick   Set protect (&)",
      "  Logged to SNO +C.",
      " ",
      "  Requires: Network Administrator (+N)",
      "  See also: OPMODE",
      NULL } },
  { "SAQUIT", "Admin", HELP_ADMIN,
    { "Usage: SAQUIT <nick> [:<reason>]",
      " ",
      "  Force a user to disconnect. Logged to SNO +C.",
      " ",
      "  Requires: Network Administrator (+N)",
      NULL } },
  { "SATOPIC", "Admin", HELP_ADMIN,
    { "Usage: SATOPIC <#channel> :<topic>",
      " ",
      "  Force a topic change. Logged to SNO +C.",
      " ",
      "  Requires: Network Administrator (+N)",
      NULL } },
  { "SAWHOIS", "Admin", HELP_ADMIN,
    { "Usage: SAWHOIS <nick> [:<text>]",
      " ",
      "  Set or clear a custom WHOIS line. Omit text to clear.",
      "  Logged to SNO +C.",
      " ",
      "  Requires: Network Administrator (+N)",
      NULL } },
  { "SAIDENT", "Admin", HELP_ADMIN,
    { "Usage: SAIDENT <nick> <newident>",
      " ",
      "  Force a user's ident change. Logged to SNO +C.",
      " ",
      "  Requires: Network Administrator (+N)",
      NULL } },
  { "SAINFO", "Admin", HELP_ADMIN,
    { "Usage: SAINFO <nick> :<new realname>",
      " ",
      "  Force a user's realname (GECOS) change. Logged to SNO +C.",
      " ",
      "  Requires: Network Administrator (+N)",
      NULL } },
  { "SANOOP", "Admin", HELP_ADMIN,
    { "Usage: SANOOP <server> <+|->",
      " ",
      "  Toggle NOOP on a server (prevent local opers).",
      "    + = enable NOOP, - = disable.",
      "  Logged to SNO +C.",
      " ",
      "  Requires: Network Administrator (+N)",
      NULL } },

  /* ═══ CONNECTION/REGISTRATION (pre-connect) ══════════════════ */


  { "KNOCK", "User", HELP_USER,
    { "Usage: KNOCK <#channel>",
      " ",
      "  Request an invite to an invite-only (+i) channel.",
      "  Channel operators will see your request.",
      "  Blocked if the channel has mode +K (no knock).",
      "  Rate limited to once per 60 seconds.",
      NULL } },
  { "MONITOR", "IRCv3", HELP_USER,
    { "Usage: MONITOR [+|-]<nick>[,nick,...] | C | L | S",
      " ",
      "  IRCv3 online notification system (modern WATCH replacement).",
      "  + nick[,nick] Add targets    - nick[,nick] Remove targets",
      "  C Clear list   L List targets   S Show online status",
      NULL } },
  { "CHATHISTORY", "IRCv3", HELP_USER,
    { "Usage: CHATHISTORY <subcommand> <target> <reference> [<limit>]",
      " ",
      "  IRCv3 message history retrieval (proxied to services).",
      "  Subcommands: LATEST, BEFORE, AFTER, AROUND, BETWEEN",
      "  Requires services (Synaxis/Sigil) with history support.",
      NULL } },
  { "ACCEPT", "User", HELP_USER,
    { "Usage: ACCEPT [+nick|-nick|*]",
      " ",
      "  CallerID accept list. When user mode +G is set, only users",
      "  on your accept list can send you private messages.",
      "  +nick Add to list   -nick Remove   * Show list",
      NULL } },
  { "DLINE", "Oper", HELP_OPER,
    { "Usage: DLINE <ip> [<duration> :<reason>]",
      " ",
      "  Local IP-only deny line. Checked before registration.",
      "  Unlike ZLINE, DLINE is not propagated across the network.",
      " ",
      "  Requires: IRC Operator",
      NULL } },
  { "KLINE", "Oper", HELP_OPER,
    { "Usage: KLINE <user@host> [<duration> :<reason>]",
      " ",
      "  Local host ban (alias for local GLINE).",
      " ",
      "  Requires: IRC Operator with LOCAL_GLINE privilege",
      NULL } },
  { "UNDLINE", "Oper", HELP_OPER,
    { "Usage: UNDLINE <ip>",
      " ",
      "  Remove a local DLINE (IP deny line).",
      " ",
      "  Requires: IRC Operator",
      NULL } },
  { "UNKLINE", "Oper", HELP_OPER,
    { "Usage: UNKLINE <user@host>",
      " ",
      "  Remove a local KLINE.",
      " ",
      "  Requires: IRC Operator with LOCAL_GLINE privilege",
      NULL } },
  { "LOCOPS", "Oper", HELP_OPER,
    { "Usage: LOCOPS :<message>",
      " ",
      "  Send a message to operators on this server only.",
      "  Not propagated to other servers (unlike WALLOPS).",
      " ",
      "  Requires: IRC Operator",
      NULL } },

  { "STARTTLS", "Connection", HELP_USER,
    { "Usage: STARTTLS",
      "  Upgrade connection to TLS. Must be sent before registration.",
      NULL } },
  { "WEBIRC", "Connection", HELP_S2S,
    { "Usage: WEBIRC <password> <gateway> <hostname> <ip>",
      "  Web gateway identification. Configured via WebIRC blocks.",
      NULL } },
  { "PASS", "Connection", HELP_S2S,
    { "Usage: PASS <password>",
      "  Set connection password. Must be sent before NICK/USER.",
      NULL } },

  /* ═══ REFERENCE TOPICS ═══════════════════════════════════════ */

  { "USERMODES", "Reference", HELP_USER,
    { "User Modes (a-z, A-Z):",
      " ",
      "  +a  Server Administrator    +d  Deaf (no channel msgs)",
      "  +h  Custom vhost set        +i  Invisible (hide from WHO/NAMES)",
      "  +k  Network Service         +o  Global IRC Operator",
      "  +p  Hide channels (WHOIS)   +q  Common channels only",
      "  +r  Registered (NickServ)   +s  Server notice mask (+s <mask>)",
      "  +w  Receive wallops         +x  Hidden host (cloaked)",
      "  +z  Connected via SSL/TLS",
      " ",
      "  +B  Bot flag                +D  Private deaf (no privmsgs)",
      "  +I  Hide idle time          +L  No auto-redirect",
      "  +N  Network Administrator   +O  Local IRC Operator",
      "  +R  Registered-only msgs    +S  SSL-only PMs",
      "  +W  WHOIS notification      +X  Extra oper privileges",
      " ",
      " ",
      "  See also: SNOMASK, CHANMODES, OPERLEVELS",
      NULL } },
  { "CHANMODES", "Reference", HELP_USER,
    { "Channel Modes (a-z, A-Z):",
      " ",
      "  --- Prefix modes (status) ---",
      "  +q <nick>  Owner (~)         +a <nick>  Protect (&)",
      "  +o <nick>  Operator (@)      +h <nick>  Halfop (%)",
      "  +v <nick>  Voice (+)",
      " ",
      "  --- List modes ---",
      "  +b <mask>  Ban               +e <mask>  Ban exception",
      "  +I <mask>  Invite exception",
      " ",
      "  --- Parameter modes ---",
      "  +k <key>   Channel key       +l <N>     User limit",
      "  +L <#chan>  Overflow redirect +j <n:t>   Join throttle",
      "  +f <args>  Flood protection",
      " ",
      "  --- Simple modes (a-z) ---",
      "  +c  No color codes          +d  Delayed join visible",
      "  +i  Invite only             +m  Moderated",
      "  +n  No external messages    +p  Private",
      "  +r  Registered-only         +s  Secret",
      "  +t  Topic lock (ops only)   +z  Persistent (no auto-destroy)",
      " ",
      "  --- Simple modes (A-Z) ---",
      "  +C  No CTCP                 +D  Delayed joins (hide until speak)",
      "  +K  No KNOCK                +M  Registered-moderated",
      "  +N  No nick changes         +O  Oper-only (oplevels)",
      "  +Q  No quit/part messages   +R  Registered channel flag",
      "  +S  Strip color codes       +T  No multi-target msgs",
      "  +Z  SSL-only",
      " ",
      "  Encryption tiers:",
      "    +Z  SSL required to join. Users must have +z.",
      " ",
      "  See also: CHANTYPES, EXTBANS, CHANPREFIXES, USERMODES",
      NULL } },
  { "CHANTYPES", "Reference", HELP_USER,
    { "Channel Types:",
      " ",
      "  #channel  — Global channel. Network-wide, full mode support.",
      "              Always enabled. Standard IRC channel type.",
      " ",
      "  &channel  — Local channel. Server-only, not propagated to",
      "              other servers. Full mode support. Enable with",
      "              FEAT_LOCAL_CHANNELS = TRUE.",
      " ",
      "  Current CHANTYPES shown in ISUPPORT (005) on connect.",
      "  See also: CHANMODES, CHANPREFIXES",
      NULL } },
  { "CHANPREFIXES", "Reference", HELP_USER,
    { "Channel Prefix Hierarchy (highest to lowest):",
      " ",
      "  OWNERPROTECT = TRUE:",
      "    ~  +q  Owner      &  +a  Protect    @  +o  Operator",
      "    %  +h  Halfop     +  +v  Voice",
      " ",
      "  OWNERPROTECT = FALSE:  @  +o  Operator  %  +h  Halfop  +  +v  Voice",
      " ",
      "  +q/+a are services-only. Set via /SAMODE or services.",
      "  ISUPPORT PREFIX reflects current config (e.g. PREFIX=(qaohv)~&@%+)",
      NULL } },
  { "EXTBANS", "Reference", HELP_USER,
    { "Extended Bans (prefix ~ then type letter):",
      " ",
      "  --- Match user properties (use with +b, +e, +I) ---",
      "  ~a:<account>      Account name       ~c:<channel>  Channel membership",
      "  ~j:<#channel>     Cross-channel ban   ~r:<realname> Realname/GECOS",
      "  ~m:<mark>         MARK (all)          ~M:<mark>     MARK (unauthed)",
      "  ~s:<server>       Server name         ~f:<certfp>   TLS fingerprint",
      "  ~o:<mask>         IRC operators        ~R:<mask>     Registered users",
      " ",
      "  --- Control behavior (applied to matching users) ---",
      "  ~q:<mask>   Quiet (block msgs)    ~n:<mask>   Block nick change",
      "  ~T:<pattern> Block text pattern    ~C:<mask>   Block CTCPs",
      "  ~N:<mask>   Block notices",
      " ",
      "  --- Modifier ---",
      "  ~!   Negate match (users who do NOT match)",
      " ",
      "  Examples:",
      "    +b ~q:*!*@*.dialup.net    +e ~o:*    +I ~R:*    +b ~!~a:*",
      "    +b ~s:bad.server    +b ~T:block:*badword*    +b ~C:*!*@bot.net",
      NULL } },
  { "SNOMASK", "Reference", HELP_USER,
    { "Server Notice Mask (/MODE <nick> +s <mask>):",
      " ",
      "  --- Lowercase (a-z) ---",
      "  a = SASL authentication     c = client connect/exit",
      "  d = debug messages           e = TCP/socket errors",
      "  f = too many connections     g = G-lines",
      "  h = Uworld actions           i = IP mismatches",
      "  k = server kills (collisions) n = net join/break",
      "  o = old unsorted messages    r = oper-only messages",
      "  s = temporary desyncs        t = throttle notices",
      "  u = unauthorized connections w = WebIRC notices",
      " ",
      "  --- Uppercase (A-Z) ---",
      "  A = IAuth notices            C = SA* command usage",
      "  F = flood/excess notices     G = auto G-lines",
      "  K = oper kills               N = nick changes",
      "  P = spamfilter matches       R = account changes",
      "  S = shun notices             T = TLS connection info",
      "  Z = Z-line notices",
      " ",
      "  Quick setup:  /MODE <nick> +s +nKgDtcSaCFER",
      "  All notices:  /MODE <nick> +s +okcDsuedfhgnitrGdNAwSZaCFTRPE",
      " ",
      "  See also: USERMODES, OPERLEVELS",
      NULL } },
{ "OPERLEVELS", "Reference", HELP_USER,
    { "Operator Hierarchy (lowest to highest):",
      " ",
      "  Level 1: Local IRCop (+O)",
      "    Local server operations: KILL (local), KLINE, REHASH, CLOSE",
      "    Cannot propagate across server links",
      "    Oper block: local = yes;",
      " ",
      "  Level 2: IRCop (+o)",
      "    Global network operations: KILL, GLINE, SHUN, ZLINE, CONNECT",
      "    SQUIT, JUPE, CHECK, OPMODE, CLEARMODE",
      "    Propagated to all servers",
      "    Oper block: propagate = yes;",
      " ",
      "  Level 3: Server Administrator (+a)",
      "    Server administration: RESTART, DIE, SET, remote REHASH",
      "    Full visibility: hidden channels, hidden opers, all IPs",
      "    Oper block: admin = yes;",
      " ",
      "  Level 4: Network Administrator (+N)",
      "    Full network control including all SA* commands:",
      "    SAJOIN SAPART SACYCLE SANICK SAMODE SAQUIT SATOPIC SAWHOIS",
      "    SAIDENT SAINFO SANOOP",
      "    Oper block: netadmin = yes;",
      "    ** +N requires NickServ authentication to activate. **",
      "    ** Until identified, netadmin opers stay at +a. **",
      " ",
      "  Services (managed by NickServ/OpServ, not oper blocks):",
      "    Services Operator       — Basic services administration",
      "    Services Administrator  — Full services management",
      "    Services Root Admin     — All services + SA* (requires +N)",
      " ",
      "  +k: Network Service — reserved for service bots (ChanServ,",
      "    NickServ, etc.). Never assigned to human operators.",
      " ",
      "  Higher levels always outrank lower. Network Administrators",
      "  cannot be killed/shunned/glined by Server Administrators.",
      "  Services Root Admins need +N on IRC to use SA* commands.",
      " ",
      "  Use /PRIVS to view your current privileges after opering.",
      "  See also: USERMODES, SNOMASK",
      NULL } },
  { "FEATURES", "Reference", HELP_USER,
    { "Key Feature Toggles (ircd.conf):",
      "  HALFOPS         +h halfop mode",
      "  OWNERPROTECT    +q/+a owner/protect modes",
      "  EXTBANS         Extended ban system (~q, ~a, ~s, etc.)",
      "  EXCEPTS         Ban exceptions (+e)",
      "  HOST_HIDING     Host cloaking (+x)",
      "  DNSBL           DNS Blacklist checking",
      "  KNOCK           Allow KNOCK on +i channels",
      "  JOINTHROTTLE    +j join throttle mode",
      "  FLOODPROT       +f flood protection mode",
      "  CALLERID        +G CallerID / server-side filtering",
      "  MONITOR         IRCv3 MONITOR command",
      " ",
      "  IRCv3 CAP Features (toggleable):",
      "    CAP_echo_message  CAP_batch  CAP_labeled_response",
      "    CAP_standard_replies  CAP_chghost  CAP_setname",
      " ",
      "  Strict Transport Security (STS):",
      "    STS_PORT          TLS port to advertise (default: 0 / disabled)",
      "    STS_DURATION      Policy duration in seconds (default: 2592000 / 30 days)",
      " ",
      " ",
      "  Use /STATS f to see all feature values.",
      NULL } },

  /* ═══ SASL REFERENCE ═════════════════════════════════════════ */

  { "SASL", "Reference", HELP_USER,
    { "SASL Authentication:",
      " ",
      "  Authenticate before registration completes. Protects your",
      "  password from server logs. Most modern clients support this.",
      " ",
      "  Mechanisms: PLAIN (user+pass), EXTERNAL (TLS client cert)",
      "  See also: AUTHENTICATE, CAP",
      NULL } },

  { "HELPOP", "User", HELP_USER,
    { "Usage: HELPOP [<topic>]",
      "  Alias for /HELP. Shows index or detailed help for a topic.",
      NULL } },

  /* Sentinel */
  { NULL, NULL, 0, { NULL } }
};

/** Find extended help entry by name. */
static const struct HelpEntry *
find_help(const char *name)
{
  int i;
  for (i = 0; helptab[i].name; i++)
    if (!ircd_strcmp(name, helptab[i].name))
      return &helptab[i];
  return NULL;
}

/**
 * m_help - /HELP and /HELPOP command handler
 *
 * With no arguments: shows privilege-filtered command index.
 * With an argument:  shows detailed help (always shown regardless of level).
 */
int m_help(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  const struct HelpEntry *entry;
  int i, j, lvl;
  char *cmd;

  lvl = help_level(sptr);

  if (parc < 2) {
    /* ── Privilege-filtered command index ────────────────────── */
    send_reply(sptr, RPL_HELPSTART, "*", "Cathexis Help System");
    help_line(sptr, "*", " ");
    help_line(sptr, "*", "Usage: /HELP <topic>  Show detailed help for a topic");
    help_line(sptr, "*", " ");

    /* User commands — everyone sees these */
    help_line(sptr, "*", "--- User Commands ---");
    help_line(sptr, "*", "  PRIVMSG  NOTICE  JOIN  PART  NICK  MODE  TOPIC  KICK  INVITE");
    help_line(sptr, "*", "  WHO  WHOIS  WHOWAS  LIST  NAMES  AWAY  QUIT  WATCH  SILENCE");
    help_line(sptr, "*", "  WALLCHOPS  WALLVOICES  WALLHOPS  CPRIVMSG  CNOTICE");
    help_line(sptr, "*", "  ISON  USERHOST  USERIP  PING  TRACE  MAP  LINKS  IRCOPS");
    help_line(sptr, "*", "  LUSERS  TIME  VERSION  ADMIN  INFO  MOTD  RULES  STATS");
    help_line(sptr, "*", "  MKPASSWD  SETHOST  SETNAME  TAGMSG  CAP  AUTHENTICATE");
    help_line(sptr, "*", "  KNOCK  MONITOR  CHATHISTORY  ACCEPT  STARTTLS  ISNEF");
    help_line(sptr, "*", " ");
    help_line(sptr, "*", " ");

    /* Oper commands — only for opers */
    if (lvl >= HELP_OPER) {
      help_line(sptr, "*", "--- Operator Commands ---");
      help_line(sptr, "*", "  OPER  KILL  GLINE  SHUN  ZLINE  TEMPSHUN  REMOVE");
      help_line(sptr, "*", "  WALLOPS  WALLUSERS  OPMODE  CLEARMODE  CHECK  PRIVS");
      help_line(sptr, "*", "  SQUIT  CONNECT  REHASH  RESTART  DIE  CLOSE  JUPE");
      help_line(sptr, "*", "  SET  GET  RESET  OPERMOTD  SETTIME  RPING  UPING  ASLL");
      help_line(sptr, "*", "  DLINE  KLINE  UNDLINE  UNKLINE  LOCOPS  XQUERY");
      help_line(sptr, "*", " ");
    }

    /* Admin commands — only for network admins */
    if (lvl >= HELP_ADMIN) {
      help_line(sptr, "*", "--- Network Admin Commands (requires +N) ---");
      help_line(sptr, "*", "  SAJOIN   Force user to join channel(s)");
      help_line(sptr, "*", "  SAPART   Force user to part channel(s)");
      help_line(sptr, "*", "  SACYCLE  Force user to cycle channel(s)");
      help_line(sptr, "*", "  SANICK   Force nickname change");
      help_line(sptr, "*", "  SAMODE   Force mode change (sets +q/+a owner/protect)");
      help_line(sptr, "*", "  SAQUIT   Force user disconnect");
      help_line(sptr, "*", "  SATOPIC  Force topic change");
      help_line(sptr, "*", "  SAWHOIS  Set/clear custom WHOIS line");
      help_line(sptr, "*", "  SAIDENT  Force ident change");
      help_line(sptr, "*", "  SAINFO   Force realname change");
      help_line(sptr, "*", "  SANOOP   Toggle NOOP on a server");
      help_line(sptr, "*", " ");
    }

    /* Reference topics — everyone */
    help_line(sptr, "*", "--- Reference Topics ---");
    help_line(sptr, "*", "  USERMODES   CHANMODES   CHANPREFIXES   EXTBANS");
    help_line(sptr, "*", "  SNOMASK     OPERLEVELS  FEATURES       SASL");
    help_line(sptr, "*", " ");

    return send_reply(sptr, RPL_ENDOFHELP, "*", "End of /HELP");
  }

  /* ── Specific command/topic lookup ─────────────────────────── */
  cmd = parv[1];
  for (i = 0; cmd[i]; i++) {
    if (cmd[i] >= 'a' && cmd[i] <= 'z')
      cmd[i] -= 32; /* uppercase */
  }

  /* Check helptab first */
  entry = find_help(cmd);
  if (entry) {
    send_reply(sptr, RPL_HELPSTART, cmd, "Cathexis Help System");
    for (j = 0; entry->lines[j]; j++)
      help_line(sptr, cmd, entry->lines[j]);
    /* Show category tag */
    if (entry->level == HELP_OPER)
      help_line(sptr, cmd, "  [Requires: IRC Operator]");
    else if (entry->level == HELP_ADMIN)
      help_line(sptr, cmd, "  [Requires: Network Administrator (+N)]");
    return send_reply(sptr, RPL_ENDOFHELP, cmd, "End of /HELP");
  }

  /* Fall back to one-liner from msgtab */
  for (i = 0; msgtab[i].cmd; i++) {
    if (!ircd_strcmp(cmd, msgtab[i].cmd) && msgtab[i].help && msgtab[i].help[0]) {
      send_reply(sptr, RPL_HELPSTART, cmd, "Cathexis Help System");
      help_line(sptr, cmd, msgtab[i].help);
      help_line(sptr, cmd, " ");
      help_line(sptr, cmd, "No extended help available. Use /HELP for index.");
      return send_reply(sptr, RPL_ENDOFHELP, cmd, "End of /HELP");
    }
  }

  /* Not found */
  send_reply(sptr, RPL_HELPSTART, cmd, "Cathexis Help System");
  help_line(sptr, cmd, "No help available for that topic.");
  help_line(sptr, cmd, "Use /HELP with no arguments for the command index.");
  return send_reply(sptr, RPL_ENDOFHELP, cmd, "End of /HELP");
}
