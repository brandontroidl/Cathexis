# PATCH_DIFFS.md / SECURE_REWRITE.md — Pass 10: Secure Refactor
## Cathexis / Nefarious IRCd

---

## Patch 1 — ircd_cloaking.c: Bounded Key Copy

### Problem
`strcpy(res+16, KEY)` can overflow `res[512]` if KEY > 496 bytes.

### Fix

```c
// In ircd_features.c, add to feature_set for HOST_HIDING_KEY*:
#define HOST_HIDING_KEY_MAXLEN 256

// In ircd_cloaking.c, replace every:
//   strcpy(res+16, KEY1);
// with:

static void safe_copy_key(char *dest, const char *src, size_t dest_total, size_t offset)
{
    size_t avail = (dest_total > offset) ? dest_total - offset - 1 : 0;
    strncpy(dest + offset, src, avail);
    dest[offset + avail] = '\0';
}

// Usage:
DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
safe_copy_key(res, KEY1, sizeof(res), 16);
n = strlen(res+16) + 16;
if (n > sizeof(res)) n = sizeof(res);
DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
```

Additionally, add validation in `ircd_features.c` at feature SET time:

```c
// In the feature string set callback or validation:
case FEAT_HOST_HIDING_KEY1:
case FEAT_HOST_HIDING_KEY2:
case FEAT_HOST_HIDING_KEY3:
    if (strlen(value) > HOST_HIDING_KEY_MAXLEN) {
        send_reply(sptr, ERR_INVALIDFEAT, "Key too long (max 256 chars)");
        return 1; // reject
    }
    break;
```

---

## Patch 2 — dockerentrypoint.sh: Safe env var substitution

### Problem
Newlines, `|`, and `;` in env var values are not escaped before sed substitution.

### Fix

```bash
# Replace the substitution loop with a Python-based safe substitution:

python3 - <<'EOF'
import os, re

template_path = os.environ.get('BASECONFDIST', '/home/nefarious/ircd/base.conf-dist')
output_path   = os.environ.get('BASECONF',     '/home/nefarious/ircd/base.conf')

with open(template_path, 'r') as f:
    content = f.read()

def replace_placeholder(m):
    varname = m.group(1)
    value = os.environ.get(varname, '')
    # Validate: no newlines allowed in any substituted value
    if '\n' in value or '\r' in value:
        raise ValueError(f"Environment variable {varname} contains illegal newline")
    return value

content = re.sub(r'%([A-Za-z_][A-Za-z0-9_]*)%', replace_placeholder, content)

with open(output_path, 'w') as f:
    f.write(content)
EOF
```

Additionally, validate the `IRCD_GENERAL_NUMERIC` value is a valid integer before substitution:

```bash
if ! [[ "$IRCD_GENERAL_NUMERIC" =~ ^[0-9]+$ ]] || [ "$IRCD_GENERAL_NUMERIC" -gt 4095 ]; then
    echo "ERROR: IRCD_GENERAL_NUMERIC must be an integer 0-4095"
    exit 1
fi
```

---

## Patch 3 — m_privs.c: Bounds-checked buffer construction

### Problem
`strcat(buf, parv[i])` without explicit overflow check.

### Fix

```c
// Replace:
char buf[512] = "";
for (i=2; i<parc; i++) {
    strcat(buf, parv[i]);
    strcat(buf, " ");
}

// With:
char buf[512] = "";
size_t buf_used = 0;
for (i = 2; i < parc; i++) {
    size_t plen = strlen(parv[i]);
    if (buf_used + plen + 2 > sizeof(buf) - 1)
        break;
    memcpy(buf + buf_used, parv[i], plen);
    buf_used += plen;
    buf[buf_used++] = ' ';
    buf[buf_used] = '\0';
}
```

---

## Patch 4 — channel.c: Enforce CHANNELLEN for server-introduced channels

### Problem
`get_channel()` only enforces `CHANNELLEN` for `MyUser(cptr)`, not for server-originated channels.

### Fix

```c
// In get_channel():
len = strlen(chname);
if (len > CHANNELLEN) {   // REMOVE the MyUser(cptr) guard
    len = CHANNELLEN;
    *(chname + CHANNELLEN) = '\0';
}
```

This ensures no channel name exceeding `CHANNELLEN` is ever stored, regardless of source.

---

## Patch 5 — s_auth.c / ircd_features.c: Add feature string length validation

### Problem
No maximum length enforced on runtime feature string values.

### Fix

```c
// In ircd_features.c, add to feature_set handler:
static int feature_str_set(struct Client *sptr, int opt, const char *str, ...) {
    // Before storing:
    if (strlen(str) > FEAT_STR_MAXLEN) {
        if (sptr)
            send_reply(sptr, ERR_INVALIDFEAT, "Feature string value too long");
        return 1;
    }
    // ... existing set logic
}

#define FEAT_STR_MAXLEN 256
```

---

## Patch 6 — client.c: Replace fragile strcat in privilege accumulation

### Problem
`strcat(privbufp, privtab[i].name)` with a cosmetic-only flush threshold.

### Fix

```c
// Replace in client_check_privs():
size_t pos = 0;
for (i = 0; privtab[i].name; i++) {
    if (HasPriv(client, privtab[i].priv)) {
        size_t nlen = strlen(privtab[i].name);
        if (pos + nlen + 2 > sizeof(privbufp) - 1) {
            // Flush the current buffer
            ircd_snprintf(0, outbuf, sizeof(outbuf), "     Privileges:: %s", privbufp);
            send_reply(replyto, RPL_DATASTR, outbuf);
            pos = 0;
        }
        memcpy(privbufp + pos, privtab[i].name, nlen);
        pos += nlen;
        privbufp[pos++] = ' ';
        privbufp[pos] = '\0';
    }
}
```

---

## Patch 7 — m_server.c: Rate-limit server introduction attempts

### Problem
No rate limiting on failed server introduction attempts allows brute-force of C: line passwords.

### Fix

```c
// Track failed intro attempts per source IP
static struct { struct irc_in_addr addr; time_t last; int count; } intro_fails[256];

// In mr_server(), after password check failure:
if (record_intro_fail(&cli_ip(cptr)) > 3) {
    exit_client(cptr, cptr, &me, "Too many failed server introductions");
    return 0;
}
```

---

## Summary of Security Improvements

| Patch | Addresses | Severity Mitigated |
|-------|-----------|-------------------|
| Patch 1 | MA-01: Cloaking key buffer overflow | CRITICAL |
| Patch 2 | TF-09: Docker config injection | HIGH |
| Patch 3 | MA-05: PRIVS strcat | LOW |
| Patch 4 | TF-01: Server channel name length | MEDIUM |
| Patch 5 | MA-01 (preventive): Feature string limits | CRITICAL |
| Patch 6 | MA-03: client.c strcat pattern | MEDIUM |
| Patch 7 | PA-01: Server password brute-force | LOW |

**Structural issues not patchable without protocol redesign:**
- DS-04/DS-05/DS-06: S2S messages lack cryptographic authentication (P10 design limitation).
- PA-02: PRIVS injection from any server (requires network-level trust model redesign).
- PA-04: SVS* commands available to all servers (requires designated "services server" trust class).
