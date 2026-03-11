# TAINT_ANALYSIS.md — Pass 4: Taint Tracking
## Cathexis / Nefarious IRCd

---

## Taint Sources

| Source ID | Origin | Initial Entry Point |
|-----------|--------|---------------------|
| T-CLIENT | IRC client message | `os_recv_nonb` → `client_dopacket` |
| T-SERVER | S2S P10 message | `server_dopacket` → `parse_server` |
| T-DNS | DNS resolver response | `ircd_reslib.c` → `auth_dns_callback` |
| T-IDENT | Ident server reply | `s_auth.c` check_ident_reply |
| T-IAUTH | iAuth daemon response | `s_auth.c` iauth_parse |
| T-CONFIG | `ircd.conf` / F: lines | `s_conf.c`, `ircd_features.c` |
| T-ENV | Docker env vars | `dockerentrypoint.sh` → `base.conf` |

---

## Taint Flow Traces

### TF-01: Client channel name → `strcpy` in `channel.c`

```
T-CLIENT
→ parse_client: para[1] = channel name string from buffer
→ m_join.c: m_join(cptr, sptr, parc, parv)
    → get_channel(cptr, parv[1], CGT_CREATE)
        → len = strlen(chname)
        → if (MyUser(cptr) && len > CHANNELLEN): truncate   ← LOCAL USER ONLY
        → chptr = MyMalloc(sizeof(Channel) + len)
        → strcpy(chptr->chname, chname)   ← safe: exact allocation
```

```
T-SERVER (BURST/CREATE/JOIN from linked server)
→ parse_server: parv[N] = channel name
→ ms_burst / ms_create / ms_join
    → get_channel(cptr, channame, CGT_CREATE)
        → len = strlen(chname)
        → if (MyUser(cptr) && ...): NOT ENTERED  ← NO LENGTH CHECK FOR SERVERS
        → chptr = MyMalloc(sizeof(Channel) + len)  ← allocates exact len
        → strcpy(chptr->chname, chname)   ← allocation = len, safe
```

**Assessment:** The `strcpy` itself is safe because the heap allocation exactly matches `strlen(chname)`. However, a server-introduced channel name longer than `CHANNELLEN` (200) will be stored with an over-length name. Any subsequent code that copies this name into a fixed `CHANNELLEN+1` buffer (e.g., `mode.redir[CHANNELLEN+1]`) would then overflow. **Latent risk: medium.**

---

### TF-02: Config feature string → `strcpy` in `ircd_cloaking.c`

```
T-CONFIG (F: line or /SET by oper)
→ ircd_features.c: feature_str(FEAT_HOST_HIDING_KEY1/2/3) returns char*
→ ircd_cloaking.c:hidehost_ipv4 / hidehost_ipv6 / hidehost_normalhost
    static char res[512];           ← 512 bytes total, global/static
    DoMD5(res, buf, n)              ← fills first 16 bytes with hash
    strcpy(res+16, KEY1)            ← KEY1 written starting at byte 16
                                    ← available space: 496 bytes
```

**Taint path:** `T-CONFIG` → feature string value → `strcpy` into fixed 496-byte window of a 512-byte static buffer.

If `KEY1`, `KEY2`, or `KEY3` exceeds 496 bytes, the `strcpy` writes past the end of `res[512]`. The adjacent static variables in the same function (`res2[512]`, `result[128]`) are then overwritten.

**Reachability:**
- Admin sets long key in `ircd.conf` before startup → triggered on first connection attempt when cloaking is enabled.
- Oper with `SET` privilege issues `/SET HOST_HIDING_KEY1 <long string>` → triggered on next connection or mode change involving cloaking.
- **No length validation** on feature string values at set-time.

**Severity: HIGH** — reliable buffer overflow in globally-accessible static storage; adjacent data corruption; potential crash or code execution.

---

### TF-03: Client away message → `strcpy` in `m_away.c`

```
T-CLIENT
→ parse_client: para[1] = away message (up to ~500 bytes from buffer)
→ m_away.c:
    unsigned int len = strlen(message)
    if (len > AWAYLEN): message[AWAYLEN] = '\0'; len = AWAYLEN;   ← truncated
    away = MyMalloc(len + 1)
    strcpy(away, message)   ← safe: allocation = len+1, message[len] = '\0'
```

**Assessment:** Safe. Explicit truncation before `malloc`+`strcpy` pattern.

---

### TF-04: S2S PRIVS message → `strcat` loop in `m_privs.c`

```
T-SERVER
→ parse_server: up to MAXPARA=15 parameters
→ ms_privs(cptr, sptr, parc, parv):
    char buf[512] = ""
    for (i=2; i<parc; i++):
        strcat(buf, parv[i])   ← no bounds check
        strcat(buf, " ")
```

**Taint path:** Server message parameters → `strcat` into `buf[512]`.

**Bounds analysis:** The entire P10 message is capped at 512 bytes by `server_dopacket`. All parameters together plus command and prefix cannot exceed ~490 bytes total. `buf[512]` cannot be overflowed by this path in practice.

**Assessment:** Low practical risk given 512-byte line limit, but the code pattern is fragile and would be dangerous if line-length enforcement were ever relaxed.

---

### TF-05: DNS hostname → `ircd_strncpy` in `s_auth.c`

```
T-DNS
→ ircd_res.c: hostname resolution
→ auth_dns_callback(auth, hoststr, TTL)
    → auth_verify_hostname(hoststr, HOSTLEN)   ← validates chars and length
    → ircd_strncpy(cli_user(cptr)->host, hoststr, HOSTLEN+1)
    → ircd_strncpy(cli_user(cptr)->realhost, hoststr, HOSTLEN+1)
```

**Assessment:** `auth_verify_hostname` validates that the hostname is `HOSTLEN` characters or fewer and contains only valid hostname chars. `ircd_strncpy` is a safe variant. **Safe.**

---

### TF-06: WEBIRC hostname/IP → `ircd_strncpy` in `m_webirc.c`

```
T-CLIENT (pre-registration)
→ m_webirc(cptr, sptr, parc, parv):
    password = parv[1], username = parv[2], hostname = parv[3], ipaddr = parv[4]
    → password verified via find_webirc_conf()
    → ipmask_parse(ipaddr, &addr, NULL)          ← validates IP format
    → valid_hostname(hostname)                    ← validates hostname chars
    → ircd_strncpy(cli_sockhost(sptr), hostname, HOSTLEN+1)   ← safe
    → ircd_strncpy(cli_sock_ip(sptr), ircd_ntoa(&cli_ip), SOCKIPLEN+1)  ← safe
```

**Assessment:** Validation is present for both IP and hostname before storage. **Safe.**

---

### TF-07: Config mark → `strcpy` in `s_conf.c`

```
T-SERVER (ms_mark)
→ add_mark(sptr, mark):
    lp->value.cp = MyMalloc(strlen(mark) + 1)
    strcpy(lp->value.cp, mark)   ← allocation = strlen+1, safe
```

**Assessment:** Exact-size allocation before `strcpy`. **Safe.**

---

### TF-08: Config / oper SET cloaking keys → `strcpy` in `ircd_cloaking.c` (IPv6 path)

```
T-CONFIG
→ hidehost_ipv6():
    static char res[512], res2[512], result[128];
    DoMD5(res, buf, n)             ← 16-byte MD5 into res[0..15]
    strcpy(res+16, KEY1)           ← KEY1 at res[16]; overflow if KEY1 > 496 chars
    strcpy(res+16, KEY2)           ← same buffer reused; overflow if KEY2 > 496
    strcpy(res+16, KEY3)           ← same buffer; overflow if KEY3 > 496
```

**Same vulnerability as TF-02, IPv6 variant.** The IPv6 cloaking function has the same static buffer layout and `strcpy` pattern.

---

### TF-09: Docker env var → `sed` substitution → `ircd.conf`

```
T-ENV
→ dockerentrypoint.sh:
    escaped_value = printf '%s\n' "$value" | sed -e 's/[\\/&]/\\\\&/g'
    sed -i "s|${placeholder}|${escaped_value}|g" "$BASECONF"
```

**Taint path:** Docker environment variable → partial escaping → sed substitution into config file.

**Unescaped characters:** `|`, `\n` (newline), `;`, `{`, `}`, `"`.

- **`|` injection:** If `$escaped_value` contains `|`, the `sed -i "s|...|...|g"` command treats it as a delimiter, breaking the substitution and potentially causing sed to apply incomplete commands.
- **Newline injection:** A newline in `IRCD_GENERAL_DESCRIPTION` would split the line during substitution, closing the config statement and allowing subsequent lines to be interpreted as new config directives.
- **Config block injection via `IRCD_GENERAL_NUMERIC`:** This field is unquoted in the template (`numeric = %IRCD_GENERAL_NUMERIC%;`). Setting it to `1; Oper { name = "x"; password = "x"; host = "*@*"; class = "Opers"; }` would inject a valid oper block. This is a **deployment-time configuration injection** vulnerability.

---

## Summary: High-Risk Taint Flows

| ID | Path | Type | Severity |
|----|------|------|----------|
| TF-02 | Config key → `strcpy` into `res[512]` in cloaking | Buffer overflow (static) | **HIGH** |
| TF-08 | Same as TF-02, IPv6 path | Buffer overflow (static) | **HIGH** |
| TF-09 | Docker env var → config injection via unescaped newline/`|` | Config injection | **HIGH** |
| TF-01 | Server-sent long channel name | Latent: over-length string in struct | **MEDIUM** |
| TF-04 | S2S PRIVS strcat | Fragile pattern (currently safe) | **LOW** |
