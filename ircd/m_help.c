/*
 * IRC - Internet Relay Chat, ircd/m_help.c
 * Copyright (C) 2026 Cathexis Development
 *
 * Rewritten help system with command categories and detailed
 * multi-line help for each command.
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

#include <string.h>

/** Extended help entry for a command or topic. */
struct HelpEntry {
  const char *name;
  const char *category;
  const char *lines[30]; /* NULL-terminated array of help lines */
};

/** Send a single help text line using RPL_HELPTXT. */
static void
help_line(struct Client *sptr, const char *topic, const char *text)
{
  send_reply(sptr, RPL_HELPTXT, topic, "", text);
}

/** Extended help database. */
static const struct HelpEntry helptab[] = {

  /* ===== Core User Commands ===== */
  { "PRIVMSG", "User",
    { "Usage: /PRIVMSG <target> :<message>",
      "  Aliases: /MSG",
      " ",
      "  Sends a message to a user or channel.",
      "  Target can be a nickname, #channel, or @#channel (ops only).",
      " ",
      "  Examples:",
      "    /MSG #channel Hello everyone",
      "    /MSG NickName Hey there",
      "    /MSG @#channel Ops-only message",
      NULL } },
  { "JOIN", "User",
    { "Usage: /JOIN <#channel>[,#chan2] [<key>[,key2]]",
      " ",
      "  Join one or more channels. If the channel doesn't exist,",
      "  it is created and you become the channel operator.",
      " ",
      "  Examples:",
      "    /JOIN #chat",
      "    /JOIN #private secretkey",
      "    /JOIN #a,#b,#c",
      NULL } },
  { "NICK", "User",
    { "Usage: /NICK <newnickname>",
      " ",
      "  Change your nickname. Nicknames must start with a letter",
      "  or special character, and cannot exceed the server's NICKLEN.",
      NULL } },
  { "MODE", "User",
    { "Usage: /MODE <target> [<modes> [<params>]]",
      " ",
      "  View or set modes on a channel or user.",
      "  Use /HELP CHANMODES or /HELP USERMODES for mode lists.",
      " ",
      "  Channel mode examples:",
      "    /MODE #channel +o Nick        Give operator to Nick",
      "    /MODE #channel +v Nick        Give voice to Nick",
      "    /MODE #channel +im           Set invite-only + moderated",
      "    /MODE #channel +b *!*@*.bad   Ban a hostmask",
      " ",
      "  User mode examples:",
      "    /MODE YourNick +i             Set invisible",
      "    /MODE YourNick +x             Enable host cloaking",
      " ",
      "  Owner/Protect modes (if OWNERPROTECT enabled):",
      "    +q <nick>   Channel owner (~)  — services or /SAMODE only",
      "    +a <nick>   Channel admin (&)  — services or /SAMODE only",
      " ",
      "  See also: CHANMODES, USERMODES, SAMODE",
      NULL } },
  { "TOPIC", "User",
    { "Usage: /TOPIC <#channel> [:<new topic>]",
      " ",
      "  View or change a channel's topic.",
      "  Without a new topic, shows the current one.",
      "  Changing the topic may require +o if the channel is +t.",
      NULL } },
  { "KICK", "User",
    { "Usage: /KICK <#channel> <nick> [:<reason>]",
      " ",
      "  Remove a user from a channel. Requires channel operator (+o).",
      "  Protected (+a) and owner (+q) users cannot be kicked by",
      "  regular operators (when OWNERPROTECT is enabled).",
      NULL } },
  { "WHO", "User",
    { "Usage: /WHO <mask> [<flags>]",
      " ",
      "  Search for users matching a mask. Supports WHOX extended flags.",
      "  Prefixes shown: ~ (owner), & (protect), @ (op), % (halfop), + (voice)",
      " ",
      "  See also: WHOIS, WHOWAS",
      NULL } },
  { "WHOIS", "User",
    { "Usage: /WHOIS [<server>] <nick>",
      " ",
      "  Look up detailed information about a user including channels,",
      "  idle time, server, and away status.",
      "  Channel prefixes: ~ & @ % + (owner, protect, op, halfop, voice)",
      NULL } },

  /* ===== SA* Commands (Network Administrator) ===== */
  { "SAJOIN", "Admin",
    { "Usage: /SAJOIN <nick> <#channel[,#channel2,...]>",
      " ",
      "  Forces a user to join one or more channels, bypassing ALL",
      "  restrictions: invite-only (+i), bans (+b), limits (+l),",
      "  keys (+k), registered-only (+r), SSL-only (+Z), and all",
      "  extended bans (~a, ~c, ~n, etc.).",
      " ",
      "  The user receives topic and names as if they joined normally.",
      "  Action is logged to SNO_OLDSNO for all network operators.",
      " ",
      "  For remote users, the command propagates across server links.",
      " ",
      "  Examples:",
      "    /SAJOIN BadUser #jail",
      "    /SAJOIN NewUser #help,#welcome",
      " ",
      "  Requires: Network Administrator (+N, netadmin = yes)",
      "  See also: SAPART, SAMODE",
      NULL } },
  { "SAPART", "Admin",
    { "Usage: /SAPART <nick> <#channel[,#channel2]> [:<reason>]",
      " ",
      "  Forces a user to part one or more channels.",
      "  An optional part message can be provided.",
      "  Action is logged to SNO_OLDSNO.",
      " ",
      "  Examples:",
      "    /SAPART Troll #mainchat",
      "    /SAPART User #chan1,#chan2 :Moved to other channels",
      " ",
      "  Requires: Network Administrator (+N)",
      "  See also: SAJOIN",
      NULL } },
  { "SANICK", "Admin",
    { "Usage: /SANICK <nick> <newnick>",
      " ",
      "  Forces a user to change their nickname. The new nick must",
      "  be valid (pass nick validation rules), not in use, and not",
      "  juped/reserved.",
      " ",
      "  Examples:",
      "    /SANICK OffensiveNick GoodNick",
      " ",
      "  Requires: Network Administrator (+N)",
      NULL } },
  { "SAMODE", "Admin",
    { "Usage: /SAMODE <#channel|nick> <modes> [<params>]",
      " ",
      "  Forces mode changes on a channel or user, bypassing all",
      "  permission checks. This is the primary way to set the",
      "  services-only prefix modes:",
      " ",
      "  Channel member modes:",
      "    /SAMODE #channel +q Nick    Set owner (~)",
      "    /SAMODE #channel +a Nick    Set protect/admin (&)",
      "    /SAMODE #channel +o Nick    Set operator (@)",
      "    /SAMODE #channel +h Nick    Set halfop (%)",
      "    /SAMODE #channel +v Nick    Set voice (+)",
      " ",
      "  Channel flag modes:",
      "    /SAMODE #channel +imsn      Set invite/moderated/secret/noextmsg",
      "    /SAMODE #channel -b *!*@*   Remove a ban",
      " ",
      "  User modes:",
      "    /SAMODE BadOper -oN         Remove oper and netadmin flags",
      "    /SAMODE User +x             Force host cloaking",
      " ",
      "  +q (owner) and +a (protect) require OWNERPROTECT to be",
      "  enabled in ircd.conf. These modes can only be set via SAMODE",
      "  or by services over server-to-server links.",
      " ",
      "  Requires: Network Administrator (+N)",
      "  See also: MODE, OPMODE",
      NULL } },
  { "SAQUIT", "Admin",
    { "Usage: /SAQUIT <nick> [:<reason>]",
      " ",
      "  Forces a user to disconnect from the network.",
      "  An optional quit reason can be provided.",
      "  Action is logged to SNO_OLDSNO.",
      " ",
      "  Examples:",
      "    /SAQUIT Spammer :Spamming is not allowed",
      "    /SAQUIT BotNet",
      " ",
      "  Requires: Network Administrator (+N)",
      "  See also: KILL",
      NULL } },
  { "SATOPIC", "Admin",
    { "Usage: /SATOPIC <#channel> :<topic>",
      " ",
      "  Forces a topic change on a channel, bypassing +t and all",
      "  other topic restrictions.",
      " ",
      "  Requires: Network Administrator (+N)",
      "  See also: TOPIC",
      NULL } },
  { "SAWHOIS", "Admin",
    { "Usage: /SAWHOIS <nick> [:<text>]",
      " ",
      "  Sets or clears a custom WHOIS line for a user.",
      "  Omit the text to clear it.",
      " ",
      "  Examples:",
      "    /SAWHOIS Staff :is a network helper",
      "    /SAWHOIS Staff",
      " ",
      "  Requires: Network Administrator (+N)",
      NULL } },
  { "SAIDENT", "Admin",
    { "Usage: /SAIDENT <nick> <newident>",
      " ",
      "  Forces a user's ident (username) change. The new ident must",
      "  contain only valid ident characters and not exceed USERLEN.",
      " ",
      "  Examples:",
      "    /SAIDENT User newuser",
      " ",
      "  Requires: Network Administrator (+N)",
      NULL } },
  { "SAINFO", "Admin",
    { "Usage: /SAINFO <nick> :<new realname>",
      " ",
      "  Forces a user's realname (GECOS) change.",
      " ",
      "  Examples:",
      "    /SAINFO User :New Real Name",
      " ",
      "  Requires: Network Administrator (+N)",
      "  See also: SETNAME",
      NULL } },
  { "SANOOP", "Admin",
    { "Usage: /SANOOP <server> <+/->",
      " ",
      "  Toggles NOOP mode on a server, preventing it from",
      "  creating local operators.",
      " ",
      "  Examples:",
      "    /SANOOP irc.example.com +    Enable NOOP",
      "    /SANOOP irc.example.com -    Disable NOOP",
      " ",
      "  Requires: Network Administrator (+N)",
      NULL } },

  /* ===== IRCv3 Commands ===== */
  { "SETNAME", "IRCv3",
    { "Usage: /SETNAME :<new realname>",
      " ",
      "  Change your realname (GECOS) on an active connection.",
      "  Requires the setname IRCv3 capability to be negotiated.",
      " ",
      "  The server will notify all common channel members of the",
      "  change via the SETNAME message (for clients that support it).",
      " ",
      "  Maximum length is shown in ISUPPORT NAMELEN.",
      " ",
      "  See also: SAINFO",
      NULL } },
  { "TAGMSG", "IRCv3",
    { "Usage: /TAGMSG <target>",
      " ",
      "  Send a tag-only message (no text body) to a user or channel.",
      "  Used for typing indicators, reactions, and other metadata.",
      "  Requires the message-tags IRCv3 capability.",
      NULL } },
  { "CAP", "IRCv3",
    { "Usage: CAP <subcommand> [<params>]",
      " ",
      "  IRCv3 capability negotiation.",
      " ",
      "  Subcommands:",
      "    CAP LS [302]   List server capabilities",
      "    CAP REQ <caps>  Request capabilities",
      "    CAP LIST        List enabled capabilities",
      "    CAP END         End capability negotiation",
      " ",
      "  Example registration with capabilities:",
      "    CAP LS 302",
      "    NICK mynick",
      "    USER myuser 0 * :My Name",
      "    CAP REQ :multi-prefix sasl",
      "    CAP END",
      NULL } },

  /* ===== Reference Topics ===== */
  { "USERMODES", "Reference",
    { "User Modes:",
      "  +a  Server Administrator     +d  Deaf (no channel messages)",
      "  +g  Debug notices             +h  Custom host (SETHOST)",
      "  +i  Invisible                 +k  Channel service",
      "  +N  Network Administrator     +o  Global IRC Operator",
      "  +O  Local IRC Operator        +p  Hide channels in WHOIS",
      "  +q  Common channels only      +r  Registered (account set)",
      "  +s  Server notices            +w  Receive wallops",
      "  +x  Hidden host (cloaked)     +z  Connected via SSL/TLS",
      "  +B  Bot                       +D  Private deaf",
      "  +H  Hide oper status          +I  Hide idle time",
      "  +L  No auto-redirect          +R  Registered users only",
      "  +W  WHOIS notifications       +X  Extra oper privileges",
      " ",
      "  See also: SNOMASK, CHANMODES, CHANPREFIXES",
      NULL } },
  { "CHANMODES", "Reference",
    { "Channel Modes:",
      "  +b <mask>   Ban                +e <mask>   Ban exception",
      "  +i          Invite only        +k <key>    Channel key",
      "  +l <limit>  User limit         +m          Moderated",
      "  +n          No external msgs   +o <nick>   Channel operator",
      "  +h <nick>   Half operator      +v <nick>   Voice",
      "  +p          Private            +s          Secret",
      "  +t          Topic lock         +r          Registered only",
      " ",
      "  Owner/Protect modes (requires OWNERPROTECT = TRUE):",
      "  +q <nick>   Channel owner (~)  — services or /SAMODE only",
      "  +a <nick>   Channel admin (&)  — services or /SAMODE only",
      " ",
      "  Extended modes:",
      "  +C  No CTCPs      +D  Old redirect    +L  Large ban list",
      "  +M  Reg. moderated +N  No nick changes +Q  No kicks",
      "  +S  Strip colors   +T  No notices      +Z  SSL-only",
      " ",
      "  When OWNERPROTECT is disabled, +a is admin-only join (old behavior).",
      " ",
      "  See also: USERMODES, CHANPREFIXES",
      NULL } },
  { "CHANPREFIXES", "Reference",
    { "Channel Prefix Hierarchy (highest to lowest):",
      " ",
      "  When OWNERPROTECT = TRUE:",
      "    ~  +q  Owner      Services / SAMODE only",
      "    &  +a  Protect    Services / SAMODE only",
      "    @  +o  Operator   Channel ops can grant",
      "    %  +h  Halfop     Channel ops can grant (if HALFOPS = TRUE)",
      "    +  +v  Voice      Channel ops / halfops can grant",
      " ",
      "  When OWNERPROTECT = FALSE:",
      "    @  +o  Operator",
      "    %  +h  Halfop     (if HALFOPS = TRUE)",
      "    +  +v  Voice",
      " ",
      "  +q and +a are designed for services (X3, Atheme, Anope)",
      "  to assign permanent channel ownership. Regular channel",
      "  operators cannot set or unset these modes.",
      " ",
      "  Network Administrators (+N) can set them via /SAMODE.",
      " ",
      "  ISUPPORT PREFIX reflects the current configuration, e.g.:",
      "    PREFIX=(qaohv)~&@%+     OWNERPROTECT + HALFOPS",
      "    PREFIX=(qaov)~&@+       OWNERPROTECT only",
      "    PREFIX=(ohv)@%+         HALFOPS only",
      "    PREFIX=(ov)@+           Neither",
      " ",
      "  See also: CHANMODES, SAMODE",
      NULL } },
  { "SNOMASK", "Reference",
    { "Server Notice Mask (set with /MODE <nick> +s <letters>):",
      " ",
      "  c = Client connect/exit     k = Server kills (collisions)",
      "  K = Oper kills              D = Desyncs",
      "  s = Temporary desyncs       u = Unauthorized connections",
      "  e = TCP/socket errors       f = Too many connections",
      "  h = Uworld actions          g = G-lines",
      "  n = Net join/break          i = IP mismatches",
      "  t = Throttle notices        r = Oper-only messages",
      "  G = Auto G-lines            d = Debug messages",
      "  N = Nick changes            A = IAuth notices",
      "  w = WebIRC notices          o = Old unsorted messages",
      " ",
      "  Examples: /MODE nick +s +nKgDtc",
      "            /MODE nick +s -c",
      NULL } },
  { "OPERLEVELS", "Reference",
    { "Operator Levels (highest to lowest):",
      " ",
      "  +k  Network Service   - Service bots (ChanServ, NickServ)",
      "  +N  Network Admin     - SA* commands, full network control",
      "  +a  Server Admin      - Server administration",
      "  +o  Global Operator   - Network-wide oper privileges",
      "  +O  Local Operator    - Server-local oper privileges",
      " ",
      "  Privileges are configured per Operator block in ircd.conf.",
      "  Use /PRIVS to view your current privileges.",
      "  See also: USERMODES",
      NULL } },
  { "FEATURES", "Reference",
    { "Key Feature Toggles (set in ircd.conf Features block):",
      " ",
      "  HALFOPS = TRUE/FALSE",
      "    Enables channel halfop mode (+h, % prefix).",
      " ",
      "  OWNERPROTECT = TRUE/FALSE",
      "    Enables channel owner (+q, ~) and protect (+a, &) modes.",
      "    These modes can only be set by services or /SAMODE.",
      "    When disabled, +a reverts to admin-only channel mode.",
      " ",
      "  HOST_HIDING = TRUE/FALSE",
      "    Enables host cloaking (+x user mode).",
      " ",
      "  EXCEPTS = TRUE/FALSE",
      "    Enables channel ban exceptions (+e).",
      " ",
      "  Use /STATS f to see all feature values.",
      NULL } },

  /* Sentinel */
  { NULL, NULL, { NULL } }
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
 * m_help - /HELP command handler
 *
 * /HELP             - Show categorized command index with submenu
 * /HELP <command>   - Show detailed multi-line help
 * /HELP USERMODES   - User mode reference
 * /HELP CHANMODES   - Channel mode reference
 * /HELP CHANPREFIXES - Channel prefix hierarchy
 * /HELP SNOMASK     - Server notice mask reference
 * /HELP OPERLEVELS  - Oper hierarchy reference
 * /HELP FEATURES    - Feature toggle reference
 */
int m_help(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  const struct HelpEntry *entry;
  int i, j;
  char *cmd;

  if (parc < 2) {
    /* No argument: show categorized command index with submenus */
    send_reply(sptr, RPL_HELPSTART, "*", "Cathexis Help System");
    help_line(sptr, "*", " ");
    help_line(sptr, "*", "Usage: /HELP <topic>  — Show detailed help for a topic");
    help_line(sptr, "*", " ");
    help_line(sptr, "*", "--- User Commands ---");
    help_line(sptr, "*", "  PRIVMSG  JOIN  PART  NICK  MODE  TOPIC  KICK  WHO  WHOIS");
    help_line(sptr, "*", "  WHOWAS  NAMES  LIST  INVITE  AWAY  QUIT  NOTICE  USERHOST");
    help_line(sptr, "*", "  ISON  WATCH  SILENCE  PING  SETNAME  TAGMSG  CAP");
    help_line(sptr, "*", " ");
    help_line(sptr, "*", "--- Oper Commands ---");
    help_line(sptr, "*", "  OPER  KILL  GLINE  SHUN  ZLINE  OPMODE  CLEARMODE  REHASH");
    help_line(sptr, "*", "  CONNECT  SQUIT  DIE  RESTART  SET  GET  RESET  CHECK  STATS");
    help_line(sptr, "*", " ");
    help_line(sptr, "*", "--- Network Admin Commands (requires +N) ---");
    help_line(sptr, "*", "  SAJOIN   Force user to join channel(s)");
    help_line(sptr, "*", "  SAPART   Force user to part channel(s)");
    help_line(sptr, "*", "  SANICK   Force nickname change");
    help_line(sptr, "*", "  SAMODE   Force mode change (user or channel)");
    help_line(sptr, "*", "  SAQUIT   Force user disconnect");
    help_line(sptr, "*", "  SATOPIC  Force topic change");
    help_line(sptr, "*", "  SAWHOIS  Set/clear custom WHOIS line");
    help_line(sptr, "*", "  SAIDENT  Force ident change");
    help_line(sptr, "*", "  SAINFO   Force realname change");
    help_line(sptr, "*", "  SANOOP   Toggle NOOP on a server");
    help_line(sptr, "*", " ");
    help_line(sptr, "*", "--- Reference Topics ---");
    help_line(sptr, "*", "  USERMODES     User mode reference table");
    help_line(sptr, "*", "  CHANMODES     Channel mode reference table");
    help_line(sptr, "*", "  CHANPREFIXES  Channel prefix hierarchy (~&@%+)");
    help_line(sptr, "*", "  SNOMASK       Server notice mask letter reference");
    help_line(sptr, "*", "  OPERLEVELS    Oper hierarchy reference");
    help_line(sptr, "*", "  FEATURES      Feature toggle reference");
    help_line(sptr, "*", " ");

    return send_reply(sptr, RPL_ENDOFHELP, "*", "End of /HELP");
  }

  /* Specific command/topic help */
  cmd = parv[1];
  for (i = 0; cmd[i]; i++) {
    if (cmd[i] >= 'a' && cmd[i] <= 'z')
      cmd[i] -= 32; /* uppercase */
  }

  /* Check extended help database first */
  entry = find_help(cmd);
  if (entry) {
    send_reply(sptr, RPL_HELPSTART, cmd, "Cathexis Help System");
    for (j = 0; entry->lines[j]; j++)
      help_line(sptr, cmd, entry->lines[j]);
    return send_reply(sptr, RPL_ENDOFHELP, cmd, "End of /HELP");
  }

  /* Fall back to msgtab one-liner */
  for (i = 0; msgtab[i].cmd; i++) {
    if (!ircd_strcmp(cmd, msgtab[i].cmd)) {
      send_reply(sptr, RPL_HELPSTART, cmd, "Cathexis Help System");
      help_line(sptr, cmd, msgtab[i].help);
      help_line(sptr, cmd, " ");
      help_line(sptr, cmd, "No extended help available for this command.");
      help_line(sptr, cmd, "Use /HELP for the command index.");
      return send_reply(sptr, RPL_ENDOFHELP, cmd, "End of /HELP");
    }
  }

  /* Not found */
  send_reply(sptr, RPL_HELPSTART, cmd, "Cathexis Help System");
  help_line(sptr, cmd, "No help available for that topic.");
  help_line(sptr, cmd, "Use /HELP with no arguments for the command index.");
  return send_reply(sptr, RPL_ENDOFHELP, cmd, "End of /HELP");
}
