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
  const char *lines[16]; /* NULL-terminated array of help lines */
};

/** Send a single help text line using RPL_HELPTXT. */
static void
help_line(struct Client *sptr, const char *topic, const char *text)
{
  send_reply(sptr, RPL_HELPTXT, topic, "", text);
}

/** Extended help database. */
static const struct HelpEntry helptab[] = {
  /* ===== SA* Commands (Network Admin) ===== */
  { "SAJOIN", "Network Admin",
    { "Usage: /SAJOIN <nick> <#channel[,#channel2,...]>",
      " ",
      "Forces a user to join one or more channels, bypassing",
      "all restrictions (invite-only, bans, limits, keys).",
      " ",
      "Requires: Network Administrator (+N)",
      "See also: SAPART, SANICK",
      NULL } },
  { "SAPART", "Network Admin",
    { "Usage: /SAPART <nick> <#channel[,#channel2]> [:<reason>]",
      " ",
      "Forces a user to part one or more channels.",
      "An optional part message can be provided.",
      " ",
      "Requires: Network Administrator (+N)",
      "See also: SAJOIN",
      NULL } },
  { "SANICK", "Network Admin",
    { "Usage: /SANICK <nick> <newnick>",
      " ",
      "Forces a user to change their nickname. The new nick",
      "must be valid and not in use or juped.",
      " ",
      "Requires: Network Administrator (+N)",
      NULL } },
  { "SAMODE", "Network Admin",
    { "Usage: /SAMODE <#channel|nick> <modes> [params]",
      " ",
      "Forces mode changes on a channel or user, bypassing",
      "all permission checks. For channels, this is equivalent",
      "to OPMODE. For users, it can set/unset any user mode.",
      " ",
      "Examples:",
      "  /SAMODE #channel +o SomeUser",
      "  /SAMODE #channel +im",
      "  /SAMODE BadUser -o",
      " ",
      "Requires: Network Administrator (+N)",
      "See also: MODE, OPMODE",
      NULL } },
  { "SAQUIT", "Network Admin",
    { "Usage: /SAQUIT <nick> [:<reason>]",
      " ",
      "Forces a user to disconnect from the network.",
      "An optional quit reason can be provided.",
      " ",
      "Requires: Network Administrator (+N)",
      "See also: KILL",
      NULL } },
  { "SATOPIC", "Network Admin",
    { "Usage: /SATOPIC <#channel> :<topic>",
      " ",
      "Forces a topic change on a channel, bypassing +t",
      "and other topic restrictions.",
      " ",
      "Requires: Network Administrator (+N)",
      "See also: TOPIC",
      NULL } },
  { "SAWHOIS", "Network Admin",
    { "Usage: /SAWHOIS <nick> [:<text>]",
      " ",
      "Sets or clears a custom WHOIS line for a user.",
      "The text appears in WHOIS as an extra information line.",
      "Omit the text or use an empty string to clear it.",
      " ",
      "Examples:",
      "  /SAWHOIS Staff :is a network helper",
      "  /SAWHOIS Staff",
      " ",
      "Requires: Network Administrator (+N)",
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
      "See also: SNOMASK, CHANMODES",
      NULL } },
  { "CHANMODES", "Reference",
    { "Channel Modes:",
      "  +b <mask>   Ban                +e <mask>   Ban exception",
      "  +i          Invite only        +k <key>    Channel key",
      "  +l <limit>  User limit         +m          Moderated",
      "  +n          No external msgs   +o <nick>   Channel operator",
      "  +p          Private            +s          Secret",
      "  +t          Topic lock         +v <nick>   Voice",
      " ",
      "Extended modes (Nefarious/Cathexis):",
      "  +a          Admin only         +c          No colors",
      "  +C          No CTCPs           +D          Old +d redirect",
      "  +L          Large ban list     +M          Registered moderated",
      "  +N          No nick changes    +Q          No kicks",
      "  +S          Strip colors       +T          No notices",
      "  +Z          SSL-only",
      " ",
      "See also: USERMODES",
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
      "Examples: /MODE nick +s +nKgDtc",
      "          /MODE nick +s -c",
      "          /MODE nick +s all",
      NULL } },
  { "OPERLEVELS", "Reference",
    { "Operator Levels (highest to lowest):",
      " ",
      "  +k  Network Service   - Service bots (ChanServ, NickServ)",
      "  +N  Network Admin     - Full network control, SA* commands",
      "  +a  Server Admin      - Server administration",
      "  +o  Global Operator   - Network-wide oper privileges",
      "  +O  Local Operator    - Server-local oper privileges",
      " ",
      "Privileges are configured per Operator block in ircd.conf.",
      "Use /PRIVS to view your current privileges.",
      "See also: USERMODES",
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
 * /HELP           - Show categorized command index
 * /HELP <command> - Show detailed help for a command
 * /HELP USERMODES - Show user mode reference
 * /HELP CHANMODES - Show channel mode reference
 * /HELP SNOMASK   - Show server notice mask reference
 */
int m_help(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  const struct HelpEntry *entry;
  int i, j;
  char *cmd;

  if (parc < 2) {
    /* No argument: show categorized command index */
    send_reply(sptr, RPL_HELPSTART, "*", "Cathexis IRC Help System");
    help_line(sptr, "*", "Use /HELP <command> for detailed help on a command.");
    help_line(sptr, "*", "Use /HELP USERMODES, CHANMODES, SNOMASK, or OPERLEVELS for references.");
    help_line(sptr, "*", " ");

    /* Walk msgtab and print commands grouped loosely */
    help_line(sptr, "*", "--- User Commands ---");
    for (i = 0; msgtab[i].cmd; i++) {
      if (!EmptyString(msgtab[i].help) && msgtab[i].help[0] != '(')
        send_reply(sptr, RPL_HELPTXT, "*", msgtab[i].cmd, msgtab[i].help);
    }

    help_line(sptr, "*", " ");
    help_line(sptr, "*", "--- Network Admin Commands (requires +N) ---");
    for (i = 0; msgtab[i].cmd; i++) {
      if (msgtab[i].help && strstr(msgtab[i].help, "+N"))
        send_reply(sptr, RPL_HELPTXT, "*", msgtab[i].cmd, msgtab[i].help);
    }

    help_line(sptr, "*", " ");
    help_line(sptr, "*", "--- Reference Topics ---");
    help_line(sptr, "*", "USERMODES CHANMODES SNOMASK OPERLEVELS");

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
    send_reply(sptr, RPL_HELPSTART, cmd, "Cathexis IRC Help System");
    for (j = 0; entry->lines[j]; j++)
      help_line(sptr, cmd, entry->lines[j]);
    return send_reply(sptr, RPL_ENDOFHELP, cmd, "End of /HELP");
  }

  /* Fall back to msgtab one-liner */
  for (i = 0; msgtab[i].cmd; i++) {
    if (!ircd_strcmp(cmd, msgtab[i].cmd)) {
      send_reply(sptr, RPL_HELPSTART, cmd, "Cathexis IRC Help System");
      send_reply(sptr, RPL_HELPTXT, cmd, msgtab[i].cmd, msgtab[i].help);
      return send_reply(sptr, RPL_ENDOFHELP, cmd, "End of /HELP");
    }
  }

  /* Not found */
  send_reply(sptr, RPL_HELPSTART, cmd, "Cathexis IRC Help System");
  help_line(sptr, cmd, "No help available for that command.");
  help_line(sptr, cmd, "Use /HELP with no arguments for a command list.");
  return send_reply(sptr, RPL_ENDOFHELP, cmd, "End of /HELP");
}
