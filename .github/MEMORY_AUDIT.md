# MEMORY_AUDIT.md — Pass 5: Memory Safety Deep Audit
## Cathexis / Nefarious IRCd

---

## Finding MA-01 — CRITICAL: Static Buffer Overflow in `ircd_cloaking.c`

### Location
`ircd/ircd_cloaking.c` — `hidehost_ipv4()`, `hidehost_ipv6()`, `hidehost_normalhost()`

### Vulnerable Code Pattern (all three functions share this pattern)

```c
// hidehost_ipv4, line ~108:
static char buf[512], res[512], res2[512], result[128];  // line ~79

DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
strcpy(res+16, KEY1);   // KEY1 = feature_str(FEAT_HOST_HIDING_KEY1)
n = strlen(res+16) + 16;
DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
```

Repeated for `KEY2` and `KEY3` in the same function.

### Root Cause
`res[512]` is a 512-byte static buffer. `DoMD5` writes exactly 16 bytes into `res[0..15]`. Then `strcpy(res+16, KEY)` writes a key string starting at `res[16]`. The maximum safe key length is therefore **496 bytes** (`512 - 16 - 1` for null terminator). No length check is performed before the `strcpy`.

`KEY1/2/3` are runtime feature strings fetched via `feature_str(FEAT_HOST_HIDING_KEY*)`. These can be set to any length:
- Via `ircd.conf` F: line at startup
- Via IRC operator `/SET HOST_HIDING_KEY1 <value>` at runtime (requires `SET` privilege)

### Adjacent Static Variables Overwritten on Overflow
Within each function, the static variables declared on the same line are likely laid out contiguously by the compiler:
```
res[512]  → res2[512]  → result[128]
```
An overflow of `res` by N bytes overwrites the first N bytes of `res2`, then `result`.

### Exploitation Possibility
**Crash:** A key of 497+ bytes guarantees a write past the end of `res`. With a 512-byte key, the entire `res2[512]` is overwritten with attacker-controlled data. With a 1024-byte key, `result[128]` is additionally overwritten.

**Code execution:** Since `res`, `res2`, and `result` are static (in `.bss`/`.data`), this is a global buffer overflow. Adjacent global data depends on the compiler's layout. On architectures where function pointers or GOT entries are near `.bss`, this may be redirectable. With ASLR and no nearby function pointers in this section, exploitation is primarily a denial-of-service (crash).

**Trigger condition:** A local admin with `SET` privilege, or a rogue config file, or a compromised config delivery mechanism (e.g., linesync) can trigger this. The cloaking function is called for every new client connection when host cloaking is enabled (`FEAT_HOST_HIDING = YES`).

---

## Finding MA-02 — HIGH: `strcpy` in `m_watch.c` — Accumulation Pattern

### Location
`ircd/m_watch.c`, lines 157–170

### Vulnerable Code

```c
char line[BUFSIZE * 2];   // 1024 bytes
strcpy(line, lp->value.wptr->wt_nick);   // first nick
count = strlen(parv[0]) + strlen(cli_name(&me)) + 10 + strlen(line);
while ((lp = lp->next)) {
    if ((count + strlen(lp->value.wptr->wt_nick) + 1) > 512) {
        send_reply(sptr, RPL_WATCHLIST, line);
        *line = '\0';
        count = strlen(cli_name(sptr)) + strlen(cli_name(&me)) + 10;
    }
    strcat(line, " ");
    strcat(line, lp->value.wptr->wt_nick);
    count += (strlen(lp->value.wptr->wt_nick) + 1);
}
```

### Analysis
- `line[1024]`: buffer capacity.
- Flush threshold: `count > 512`.
- `count` starts as `strlen(parv[0]) + strlen(cli_name(&me)) + 10 + strlen(first_nick)`.
- `parv[0]` is the sender prefix (up to `NICKLEN=30`), `cli_name(&me)` is server name (up to `HOSTLEN=75`), overhead is 10. First-nick up to 30.
- Maximum `count` before loop: ~30 + 75 + 10 + 30 = 145.
- Each iteration: adds up to 31 bytes to both `count` and `line`.
- Flush when `count > 512`. From 145, that's up to `(512-145)/31 ≈ 11` nicks before flush.
- Max bytes accumulated: 11 × 31 = 341 bytes. Plus initial nick = 371 bytes. Well within 1024.

**Assessment:** The flush threshold (512) combined with initial overhead (145) prevents the 1024-byte buffer from overflowing. **Safe in current form**, but the safety margin is implicit and fragile — a longer server name or a refactoring that removes the count check would break it.

---

## Finding MA-03 — MEDIUM: `strcat` accumulation in `client.c` without strict bounds check

### Location
`ircd/client.c`, `client_check_privs()` / `client_send_privs()`, lines 328–384

### Vulnerable Code

```c
static char privbufp[BUFSIZE] = "";   // 512 bytes
for (i = 0; privtab[i].name; i++) {
    if (HasPriv(client, privtab[i].priv)) {
        if (strlen(privbufp) + strlen(privtab[i].name) + 2 > 70) {
            // flush and reset privbufp
            memset(&privbufp, 0, BUFSIZE);
        }
        strcat(privbufp, privtab[i].name);   // no direct overflow check
        strcat(privbufp, " ");
    }
}
```

### Analysis
The flush condition is `> 70` (cosmetic line-length limit for display), not a hard buffer-safety check. If `privtab[i].name` is longer than `BUFSIZE - 70 - strlen(privbufp)` after a flush, the `strcat` would overflow.

**Practical risk:** `privtab` is a static compile-time array of privilege names (e.g., `"KILL"`, `"GLINE"`, `"NETADMIN"` — all short fixed strings). No external input reaches `privtab[i].name`. **Not directly exploitable via untrusted input**, but the pattern is unsafe by construction.

---

## Finding MA-04 — MEDIUM: `strcpy` in `m_map.c` with `prompt_length` guard

### Location
`ircd/m_map.c`, `dump_map()`, line ~143

### Vulnerable Code

```c
static char prompt[64];
char *p = prompt + prompt_length;
// ...
if (prompt_length > 60) return;   // early return
strcpy(p, "|-");
```

### Analysis
`prompt` is 64 bytes. `p = prompt + prompt_length`. If `prompt_length` is 62 or 63, `strcpy(p, "|-")` writes `|-\0` (3 bytes) at offset 62 or 63. At offset 63, this writes `|` to `prompt[63]` and `-` to `prompt[64]` — a 1-byte overflow past the array.

**Guard analysis:** `if (prompt_length > 60) return` prevents entry when `prompt_length > 60`. So maximum entering `prompt_length` is 60. `strcpy(p, "|-")` at offset 60 writes to `prompt[60]`, `prompt[61]`, `prompt[62]` — within bounds.

**Assessment:** The guard is correct by analysis (max 60 + 2-byte string + null = 3 bytes at offset 60, end = offset 62 ≤ 63). **Safe** in current form, but relies on `prompt_length` increments happening in controlled steps of 2 per recursion level.

---

## Finding MA-05 — LOW: `strcat` in `m_privs.c` — Server-originating parameters

### Location
`ircd/m_privs.c`, `ms_privs()`, lines 104–107

### Vulnerable Code

```c
char buf[512] = "";
for (i=2; i<parc; i++) {
    strcat(buf, parv[i]);
    strcat(buf, " ");
}
```

### Analysis
As analyzed in TF-04: server messages are bounded by the 512-byte line limit in `server_dopacket`. All `parv[i]` values together cannot sum to more than the available space in a 512-byte line. **Safe in practice**, but the code has no explicit bounds check.

---

## Finding MA-06 — INFORMATIONAL: `strncpy` in `ircd_crypt_smd5.c`

### Location
`ircd/ircd_crypt_smd5.c`, line ~143

```c
char passwd[120];
memset(passwd, 0, 120);
strncpy(passwd, sp, sl);   // sl = min(ep-sp, 8)
strcat(passwd, "$");
```

Salt length `sl` is bounded to 8 by `for (ep = sp; *ep && *ep != '$' && ep < (sp + 8); ep++)`. `strncpy(passwd, sp, 8)` + `strcat("$")` = max 9 bytes. **Safe.**

---

## Finding MA-07 — HIGH: Channel `redir` field overflow from over-length server channel name

### Location
Latent; triggered by MA-01/TF-01 combined with mode parsing

### Scenario

```c
// In channel.h:
char redir[CHANNELLEN + 1];   // 201 bytes

// If a server introduces a channel with name > 200 chars:
chptr->chname = "X"*300  (stored at exact malloc'd size)

// Later, channel_modes() writes redir into modebuf:
append_mode_param(pbuf, &pbuf_pos, buflen, chptr->mode.redir, ...)
// redir is properly bounded, but chptr->chname copied elsewhere:
ircd_strncpy(target, chptr->chname, CHANNELLEN+1)   // truncates silently
```

A more dangerous scenario: if `mode.redir` is set to a channel name from a server link without validation (the `+L` mode redirect target), and a server-introduced channel has name > 200 bytes, the `mode.redir` copy could overflow when written into a `CHANNELLEN+1` buffer.

**Assessment:** Requires a rogue server; medium severity given the server trust model.

---

## Dangerous Function Summary

| Function | File | Line | Risk | Classification |
|----------|------|------|------|----------------|
| `strcpy(res+16, KEY1)` | `ircd_cloaking.c` | ~108 | Overflow if key >496 bytes | **CRITICAL** |
| `strcpy(res+16, KEY2)` | `ircd_cloaking.c` | ~116 | Same | **CRITICAL** |
| `strcpy(res+16, KEY3)` | `ircd_cloaking.c` | ~124 | Same | **CRITICAL** |
| `strcpy(res+16, KEY*)` | `ircd_cloaking.c` (ipv6) | ~175–199 | Same | **CRITICAL** |
| `strcat(privbufp, name)` | `client.c` | 328,329 | Fragile flush-not-bound pattern | **MEDIUM** |
| `strcat(buf, parv[i])` | `m_privs.c` | 105,106 | No explicit bound, capped by line limit | **LOW** |
| `strcpy(p, "\|-")` | `m_map.c` | ~143 | Safe with current guard | **LOW** |
| `strcat(capbufp, name)` | `m_cap.c` | 425,426 | Flush at 70; `name` length bounded | **LOW** |
