# PRIVILEGE_ANALYSIS.md — Pass 7: Privilege Escalation Analysis
## Cathexis / Nefarious IRCd

---

## PA-01 — OPER Authentication: Missing Constant-Time Comparison

### Location
`ircd/m_oper.c`, password comparison via `ircd_crypt.c`

### Analysis
Password is hashed client-side (bcrypt/smd5/crypt) and compared with `strcmp(crypted, aconf->passwd)`. `strcmp` is not constant-time; timing side-channels can reveal prefix matches in the hashed string.

**Practical impact:** bcrypt output is fixed-length and always ASCII; timing difference is minimal but measurable over many attempts. `PRIV_GLINE`/`PRIV_KILL` acquisition.

---

## PA-02 — Server-to-Server PRIVS: Arbitrary Privilege Injection

### Location
`ircd/m_privs.c`, `ms_privs()`

### Analysis
```c
// Any linked server can send:
:SERVER PRIVS <numeric_nick> +PRIV_NETADMIN +PRIV_KILL +PRIV_GLINE ...
```

`ms_privs` reads the privilege list from P10 message parameters and calls `client_modify_priv_by_name`. No verification that the sending server has authority to grant these privileges.

**Impact:** Any linked server (authenticated only by a shared password) can grant full `PRIV_NETADMIN` to any user on the network. This includes SA* commands (force-join, force-nick, force-quit), `KILL`, `GLINE`, `ZLINE`, `DIE`, `RESTART`.

**Severity: CRITICAL** — full network takeover from any compromised or rogue server link.

---

## PA-03 — WEBIRC: IP Spoof Bypasses Oper Host Mask Checks

### Location
`ircd/m_webirc.c`

### Analysis
`m_webirc` replaces `cli_ip(sptr)` and `cli_sockhost(sptr)` before authentication. If an oper block uses a host mask like `*@trusted-network.internal`, and an attacker controls a WebIRC-enabled gateway:

1. Connect via the WebIRC gateway.
2. Send `WEBIRC password gateway trusted-network.internal <any-ip>`.
3. After IP replacement, `cli_sockhost` = `trusted-network.internal`.
4. Attempt `OPER <name> <password>` — host mask check against `trusted-network.internal` passes.

**Required:** Knowledge of a valid WebIRC password (may be reused or guessed).

**Impact:** Bypass oper host mask; gain operator privileges.

---

## PA-04 — SVS* Commands: Service-Level Privilege Without Service Authentication

### Location
`ircd/m_svs*.c` family (`ms_svsident`, `ms_svsmode`, `ms_svsnick`, `ms_svsjoin`, `ms_svspart`, `ms_svsquit`)

### Analysis
These commands are `SERVER` handler only (clients cannot use them). Any linked server can:
- Change a user's ident (`SVSIDENT`)
- Force-join users to channels (`SVSJOIN`)
- Force-mode changes (`SVSMODE`) including `+o` (IRC operator flag)
- Force nick changes (`SVSNICK`)
- Disconnect users (`SVSQUIT`)

No distinction is made between a "services server" and a regular linked server. Any server in the network can exercise SVS* authority.

**Impact:** Full user identity manipulation, privilege escalation (via `SVSMODE +o`), targeted disconnection.

---

## PA-05 — OPMODE / CLEARMODE: Channel Op Bypass Available to All Opers

### Location
`ircd/m_opmode.c`, `ircd/m_clearmode.c`

### Analysis
`OPMODE` requires `PRIV_OPMODE` (set per oper block). `CLEARMODE` requires `PRIV_OPMODE` as well. Both commands bypass channel operator requirements.

**Risk:** An oper with `OPMODE` privilege on a local server that does not have admin/netadmin can still manipulate any channel globally if propagated via `ms_opmode`. The privilege check is on the **local** oper's flags, but the command is propagated to all servers without re-checking at each hop.

---

## PA-06 — DIE / RESTART Without Network Notification

### Location
`ircd/m_die.c`, `ircd/m_restart.c`

### Analysis
`mo_die` and `mo_restart` do not broadcast a warning to operators on other servers before shutting down. A single oper with `PRIV_DIE` can silently kill a server node, causing a network split and disrupting all users on that server.

---

## Summary

| ID | Vector | Requires | Impact | Severity |
|----|--------|---------|--------|---------|
| PA-02 | S2S PRIVS injection | Rogue server link | Full oper takeover | **CRITICAL** |
| PA-04 | SVS* from any server | Linked server | Identity/mode manipulation | **HIGH** |
| PA-03 | WEBIRC host spoof + OPER | WebIRC password | Bypass host mask | **HIGH** |
| PA-05 | OPMODE propagation | Local oper w/ OPMODE | Channel takeover globally | **MEDIUM** |
| PA-01 | OPER timing side-channel | Network position | Minor; bcrypt mitigates | **LOW** |
| PA-06 | DIE without warning | PRIV_DIE | Server DoS | **LOW** |
