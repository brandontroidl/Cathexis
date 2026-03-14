# PARSER_STATE_MACHINE.md — Pass 3: Protocol Parser Analysis
## Cathexis / Nefarious IRCd

---

## Overview

The daemon has two parallel parse paths sharing a common parameter extraction loop and a common trie-based command dispatch. Lines are byte-by-byte extracted in `packet.c` and fed as null-terminated C strings to the parsers.

---

## 1. Line Framing (`packet.c`)

```
readbuf[SERVER_TCP_WINDOW]  ←  os_recv_nonb / ssl_recv
  for each byte:
    if IsEol(byte):            # \r or \n
      if endp == client_buffer: skip (empty line)
      *endp = '\0'
      → parse_client / parse_server
      endp = client_buffer     # reset for next line
    elif endp < client_buffer + BUFSIZE:
      *endp++ = byte           # BUFSIZE = 512; stop accumulating at 511
    # else: byte silently dropped; line continues to accumulate past 510
```

**State transitions:**

| State | Trigger | Next State |
|-------|---------|------------|
| ACCUMULATING | `endp < BUFSIZE` and non-EOL byte | ACCUMULATING |
| ACCUMULATING | EOL byte, `endp > client_buffer` | DISPATCHING (call parser) |
| ACCUMULATING | EOL byte, `endp == client_buffer` | ACCUMULATING (skip empty line) |
| OVERFLOW | `endp >= BUFSIZE`, non-EOL byte | OVERFLOW (bytes silently discarded) |
| OVERFLOW | EOL byte | DISPATCHING (parse truncated line) |

**Edge case:** A client sending a 511-byte command with no newline will have its data silently accepted into the buffer across multiple `read_packet` calls (state preserved via `cli_count`). Only when a newline arrives does parsing fire, on a truncated line.

For user connections: `dbuf_getmsg` enforces 510 bytes per message; oversized lines send `ERR_INPUTTOOLONG` and clear the receive buffer.

---

## 2. Client Parser (`parse_client`)

```
Input: null-terminated line in cli_buffer

Stage 1 — IRCv3 Tag stripping:
  if *ch == '@':
    advance ch until ' ' or '\0'   # entire tag block skipped as opaque bytes
    advance over spaces

Stage 2 — Prefix skip:
  if *ch == ':':
    advance ch until ' ' or '\0'   # sender prefix from client is ignored
    advance over spaces

Stage 3 — Empty message check:
  if *ch == '\0': return -1 (empty message)

Stage 4 — Command extraction:
  s = strchr(ch, ' ')
  if s: *s++ = '\0'               # null-terminate command in-place
  ch points to command string

Stage 5 — Shun check:
  if registered user with username+host:
    if IsTempShun(cptr) || shun_lookup(cptr, 0): isshun = 1

Stage 6 — Command lookup:
  msg_tree_parse(ch, &msg_tree)    # trie lookup, case-sensitive (& 0x1f mask)
  if NULL and !isshun: ERR_UNKNOWNCOMMAND

Stage 7 — Shun gate:
  if isshun && !(mptr->flags & MFLG_NOSHUN): return 0 (silently drop)

Stage 8 — Lag accounting:
  cli_since(cptr) += lagmin + strlen(params) / lagfactor

Stage 9 — Parameter tokenisation:
  para[0] = cli_name(from)
  i = 0 (or 1 if MFLG_EXTRA, where para[1] = mptr->extra)
  while s is not exhausted and i < paramcount (≤ MAXPARA=15):
    skip spaces (replace with '\0')
    if *s == ':': para[++i] = s+1; break  (trailing param)
    else: para[++i] = s; advance s to next space

Stage 10 — Dispatch:
  handler = mptr->handlers[cli_handler(cptr)]
  return handler(cptr, from, i+1, para)
```

**Error states:**
- Unknown command → `ERR_UNKNOWNCOMMAND`, return -1.
- Shunned + non-exempt → silently drop, return 0.
- `cptr` dead → return 0 immediately.

**Edge cases:**
- IRCv3 tags are entirely skipped without any length validation; a `@`-prefixed line with 511 bytes of tags and no command will result in `*ch == '\0'` after tag stripping → empty message return.
- A command followed immediately by a trailing `:` parameter (no space-separated params) yields `i=1` with `para[1]` pointing to the empty string after `:`.
- Multiple consecutive spaces between params all collapse to `\0` bytes in the buffer.

---

## 3. Server Parser (`parse_server`)

```
Input: null-terminated line

Stage 1 — Prefix detection:
  if *ch == ':':
    para[0] = ch+1
    advance ch to next space; null-terminate
    from = FindClient(para[0])          # by name
    if from == NULL:
      special-case: allow upstream SQUIT ('Q')
      else return 0 (ignore lag artifact)
    if cli_from(from) != cptr: return 0 (wrong direction / fake prefix)
  else:
    extract numeric prefix (up to 5 chars, stop at space or '\0')
    if 1-char or 2-char: from = FindNServer(prefix)
    if 3-char or 5-char: from = findNUser(prefix)
    if from == NULL:
      special-case NICK change ('N') → send upstream KILL for unknown numeric
      allow upstream SQUIT/DESYNCH/KILL to pass
    if cli_from(from) != cptr: return 0

Stage 2 — Advance past prefix

Stage 3 — Numeric vs command:
  s = strchr(ch, ' ')
  len = s - ch
  if len == 3 && IsDigit(*ch):
    numeric = 3-digit decimal
    paramcount = 2
    mptr = NULL
  else:
    *s++ = '\0'
    mptr = msg_tree_parse(ch, &tok_tree)   # try token first
    if NULL: mptr = msg_tree_parse(ch, &msg_tree)   # fall back to long name
    if NULL: return -1

Stage 4 — Parameter tokenisation: (same loop as client parser)
  For numeric: para[++i] = s  (preserving leading ':')
  For commands: para[++i] = s+1  (stripping ':')

Stage 5 — Dispatch:
  if numeric: do_numeric(numeric, ...)
  else: mptr->handlers[cli_handler(cptr)](cptr, from, i+1, para)
```

**Error states:**
- Unknown prefix → ignored (return 0); SQUIT/KILL/DESYNCH allowed to travel upstream.
- Wrong direction (fake source) → silently ignored (return 0).
- Unknown command → return -1 (server stats `is_unco` incremented).

**Edge cases:**
- A single-character prefix `X` is treated as a 1-char server numeric (`FindNServer`).
- Prefix `X ` (X then space) hits the `'\\0' == ch[0]` path → `protocol_violation` and `from = cptr`.
- A numeric response (`001`, `433`, etc.) arriving from a server to a user is handled by `do_numeric`, which routes it to the target client without further parsing; the `:` is preserved on the last parameter.

---

## 4. Trie Lookup (`msg_tree_parse`)

```c
for (mtree = root; mtree; mtree = mtree->pointers[(*cmd++) & (MAXPTRLEN-1)]) {
    if (*cmd == '\0' && mtree->msg)
        return mtree->msg;
    else if (!IsNickChar(*cmd))
        return NULL;
}
```

**Key behaviours:**
- Index into child array: `c & 0x1f`. This maps `A-Z` and `a-z` to the same 26 slots (since `'A'=0x41 & 0x1f = 1`, `'a'=0x61 & 0x1f = 1`). Commands are effectively case-insensitive.
- Non-nick characters immediately terminate the search with NULL. This prevents over-long inputs from traversing deep into the trie.
- No recursion depth limit; bounded by command name length in practice.

---

## 5. Inconsistent State Scenarios

| Scenario | Risk |
|----------|------|
| IRCv3 tags not parsed, only skipped | Tags containing `\r` or `\n` — impossible due to line framing, but tags with unexpected `;key=val` patterns are silently ignored even if malformed |
| Long command string not in trie | Returns NULL → ERR_UNKNOWNCOMMAND; no crash |
| `paramcount > MAXPARA` | Clamped to MAXPARA (15) before loop; extra content goes into `para[MAXPARA]` as trailing text |
| `para[]` array: declared as `para[MAXPARA + 2]` | 17 slots; `i` can reach at most `paramcount+1` = 16 before the `++i` with NULL terminator makes it 16 total, fitting in para[17] |
| Server sends numeric nick as prefix but client sends `:name` | Handled in different branches; mismatch in `cli_from` check catches wrong-direction messages |
| `from == NULL` after numeric prefix lookup | KILL sent upstream for 'N' commands; all others return 0 without crash |
