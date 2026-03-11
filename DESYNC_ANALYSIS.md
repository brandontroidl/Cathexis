# DESYNC_ANALYSIS.md — Pass 6: Protocol Desynchronization
## Cathexis / Nefarious IRCd

---

## Overview

The P10 protocol relies on timestamps and network-wide consensus to resolve state conflicts. Desynchronization occurs when two servers hold inconsistent views of channels, users, or operator state.

---

## DS-01 — Nickname Collision: Timestamp Race

**Scenario:** Two servers introduce the same nick with identical timestamps (or one is crafted to match).

**Behavior in `m_nick.c`:**
- When a NICK collision is detected (`FindClient` finds existing nick), the server compares introduction timestamps.
- Lower TS wins; higher TS user is killed.
- If timestamps are **equal**, both users receive a collision kill.

**Attack vector:** A rogue or clock-skewed server introduces a NICK at timestamp `T` where `T` equals the timestamp of a legitimate user already online. The legitimate user is killed alongside the rogue user — effective denial of service without authentication.

**Mitigation in place:** NTP synchronization warning in docs; `SETTIME` command for manual correction.

**Residual risk:** NTP not enforced at the code level. A server with a deliberately misset clock can reliably collide nicks at the cost of its own users.

---

## DS-02 — Channel Timestamp Arbitration During Netsplit Rejoin

**Scenario:** Channel `#test` exists on both sides of a netsplit with different membership sets and mode sets.

**Behavior:**
- On rejoin (`ms_burst`), the server compares channel creation timestamps (TS).
- Lower TS wins; the side with higher TS loses all its modes and op status.
- If both TSes are equal, modes are merged.

**Attack vector:** During a netsplit, a rogue server creates a channel clone with a lower TS than the original. On rejoin, it replaces the original channel's mode/op state network-wide. All operators on the original channel lose their status; the rogue server's users gain it.

**Required capability:** A rogue server already introduced into the network (past the password check).

---

## DS-03 — Server Introduction Conflicts / Numeric Squatting

**In `m_server.c`:**
```c
// Check for numeric collision:
if (acptr != cptr && !IsServer(acptr))
    // conflict with existing server using this numeric
    exit_client(cptr, cptr, &me, "Server numeric conflict");
```

**Attack vector:** If two servers are configured with the same numeric (1–4095), and both connect simultaneously, one will be squit. A rogue server knowing another server's numeric can attempt to preempt it during a netsplit, effectively squatting the numeric.

**Impact:** After the legitimate server reconnects, its users retain the old numeric in other servers' tables for a brief window, leading to routing failures and ghost users.

---

## DS-04 — Fake QUIT / JOIN Events

**In `parse_server`:**
Prefix validation ensures `cli_from(from) == cptr`. This prevents spoofing messages from a server on a different link.

However, any directly-linked server can send QUIT, JOIN, or PART for any user it introduced (or that arrived via it). During a netsplit, a rogue server can:
1. Send fake QUIT for all users on the legitimate half of the split.
2. Reintroduce them with modified hosts, flags, or oper status.

**Impact:** Ghost users, privilege modification, host spoofing — all with no cryptographic integrity check on S2S messages.

---

## DS-05 — ACCOUNT Propagation Without Validation

The `ms_account` handler propagates account (services) login state across the network. Any linked server can send:
```
:NUMNICK ACCOUNT targetuser accountname timestamp
```
This sets `cli_user(target)->account` without any verification that the target user actually authenticated. A rogue server can silently set or clear account names for any user.

**Impact:** Services-based channel access controls (`+r`, `+R` modes) can be bypassed by injecting a fake ACCOUNT message.

---

## DS-06 — MARK and FAKE Messages Without Client Consent

`ms_mark` and `ms_fake` allow a server to attach metadata marks or fake hostmasks to any client:
```
:SERVER MARK target DNSBL_SPAMHAUS 1
:SERVER FAKE target fake.hostname.com
```

These are server-only commands with no authentication beyond the server link trust. A rogue or compromised server can mark users as banned (triggering downstream ban-on-join logic) or fake their hostname to bypass IP-based bans.

---

## Summary

| ID | Type | Requires Rogue Server | Severity |
|----|------|----------------------|---------|
| DS-01 | Nick collision DoS | No (clock skew sufficient) | **HIGH** |
| DS-02 | Channel takeover on netsplit | Yes | **HIGH** |
| DS-03 | Numeric squatting | Partial (timing) | **MEDIUM** |
| DS-04 | Ghost users / privilege injection | Yes | **HIGH** |
| DS-05 | Account spoofing | Yes | **HIGH** |
| DS-06 | Host/mark spoofing | Yes | **MEDIUM** |

All DS-04 through DS-06 issues are structural to the P10 protocol's server-trust model and cannot be fixed without adding cryptographic message authentication (e.g., server-to-server signing).
