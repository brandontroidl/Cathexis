# SYSTEM_ARCHITECTURE.md — Pass 1: Architecture Reconstruction
## Cathexis / Nefarious IRCd (based on ircu / P10 protocol)

---

## 1. Subsystem Map

### 1.1 Networking Layer
- **Listener** (`listener.c`): Binds TCP sockets, accepts incoming connections, branches on port type (client vs. server).
- **Platform event engines** (selected at compile time):
  - `engine_epoll.c` (Linux — primary)
  - `engine_kqueue.c` (FreeBSD)
  - `engine_devpoll.c` (Solaris)
  - `engine_poll.c`, `engine_select.c` (fallbacks)
- **Socket I/O** (`s_bsd.c`): `add_connection()` creates client structs; `read_packet()` reads up to `SERVER_TCP_WINDOW` bytes into `readbuf`; `deliver_it()` sends outbound data via scatter-gather I/O.
- **SSL** (`ssl.c`): Wraps `os_recv_nonb`/`os_sendv_nonb` with `ssl_recv`/`ssl_sendv`. STARTTLS negotiation before registration completes.

### 1.2 Event Loop
- `ircd_events.c`: Timer and socket event dispatch. Callback-based; `client_sock_callback` and `client_timer_callback` registered per-connection.
- All I/O is non-blocking (`os_set_nonblocking`).

### 1.3 Protocol Parser
- **`packet.c`**: Routes raw bytes into `server_dopacket`, `connect_dopacket`, or `client_dopacket` depending on connection state. Frames lines at CR or LF, then calls `parse_server` or `parse_client`.
- **`parse.c`**: Two entry points:
  - `parse_client()` — handles client connections; strips IRCv3 `@tags`, ignores `:prefix`, tokenises command and up to `MAXPARA=15` parameters.
  - `parse_server()` — handles server links; resolves numeric or `:name` prefix to a `struct Client *from`; dispatches via token trie.
- **Command lookup**: Dual trie (`msg_tree` for long names, `tok_tree` for P10 tokens) built from `msgtab[]` in `parse.c`. Lookup is `O(length)`.

### 1.4 Authentication System
- **`s_auth.c`**: Per-connection `AuthRequest` struct. Three parallel sub-queries:
  - Reverse DNS (`gethost_byaddr`)
  - Ident (RFC 1413 TCP query to port 113)
  - iAuth (optional external daemon via Unix socket, `iauthd.pl`)
- DNS hostname validity enforced via `auth_verify_hostname()`.
- Username cleaned via `clean_username()` (strips non-printable, prepends `~` for unidented).
- SASL support: `m_authenticate.c` / `ms_sasl.c`. SASL account name stored in `cli_saslaccount`.

### 1.5 Channel State Management
- **`channel.c`** (~5100 LOC): Central channel structure (`struct Channel`). Channel name stored in flexible array at end of heap allocation. Mode parsing via `ModeBuf` abstraction.
- Key modes: `+b` (ban), `+k` (key), `+l` (limit), `+i` (invite-only), `+m` (moderated), `+r` (registered), `+p`/`+s` (private/secret), op levels (`+o`/`+h`/`+v`).
- Channel creation: `get_channel()` → `FindChannel()` hash lookup → `MyMalloc(sizeof(Channel) + len)` + `strcpy(chptr->chname, chname)`.

### 1.6 Operator Command Handlers
- `ircd/m_oper.c`: `do_oper()` sets flags via `client_set_privs()`, assigns `cli_handler(sptr) = OPER_HANDLER`.
- Privilege system: bitmask in `struct Privs`. Set from O: (oper) block in `ircd.conf` via `client_set_privs()`.
- SA* family (`m_sajoin.c`, `m_sanick.c`, `m_samode.c`, `m_saquit.c`, etc.): Require `PRIV_NETADMIN` (`+N`).
- Elevated commands: `OPMODE`, `CLEARMODE`, `KILL`, `GLINE`, `ZLINE`, `SHUN`, `JUPE`, `DIE`, `RESTART`.

### 1.7 Server-to-Server Link Logic
- **`m_server.c`**: `mr_server` (initial handshake), `ms_server` (server burst). Checks hub/leaf masks, numeric uniqueness, password authentication.
- **`s_serv.c`**: Server introduction, squit propagation.
- Server numerics: 1–2 character base64 for servers, 3–5 for clients (`numnicks.c`).
- Burst sequence: `PASS` → `SERVER` → `BURST` (channels/users) → `END_OF_BURST` → `END_OF_BURST_ACK`.

### 1.8 Configuration Loading
- **`s_conf.c`** (~1700 LOC): Parses `ircd.conf` block format. Stores `ConfItem` structs for C: (connect), O: (oper), U: (uworld), K: (kill), G: (gline), etc.
- Docker: `tools/docker/dockerentrypoint.sh` performs sed-based env-var substitution into `base.conf-dist` at container start.

### 1.9 Logging
- **`ircd_log.c`**: Multi-level logging (`L_DEBUG` through `L_CRIT`). Log subsystems (`LS_SOCKET`, `LS_NETWORK`, `LS_CONFIG`, etc.). Writes to files or syslog.
- SNO (server notice) masks sent to operators via `sendto_opmask_butone`.

---

## 2. Core Data Structures

### `struct Client` (`include/client.h`)
- Unified structure for users, servers, and unregistered connections.
- Key fields: `cli_name` (nick/server name), `cli_fd` (file descriptor), `cli_flags` (state bitmask), `cli_handler` (dispatch index: UNREGISTERED/CLIENT/SERVER/OPER/SERVICE), `cli_connect` → `struct Connection`, `cli_user` → `struct User`, `cli_serv` → `struct Server`.
- Buffers: `con_passwd[PASSWDLEN+1]` (20 bytes), `con_buffer[BUFSIZE]` (512 bytes line buffer).

### `struct User` (`include/struct.h`)
- `username[USERLEN+1]` (11 bytes), `host[HOSTLEN+1]` (76), `realhost[HOSTLEN+1]`, `fakehost[HOSTLEN+1]`, `cloakip[HOSTLEN+1]`, `cloakhost[HOSTLEN+1]`, `sethost[HOSTLEN+USERLEN+2]`.
- `away` (heap-allocated, max `AWAYLEN=250`), `opername` (heap), `swhois[BUFSIZE+1]` (513 bytes).

### `struct Channel` (`include/channel.h`)
- `mode.key[KEYLEN+1]` (24), `mode.redir[CHANNELLEN+1]` (201), `mode.upass[KEYLEN+1]`, `mode.apass[KEYLEN+1]`.
- `chname[]` — flexible array at end of struct, sized exactly to channel name.
- Membership: double-linked list of `struct Membership`.

### `struct Server` (`include/struct.h`)
- `by[NICKLEN+1]`, `timestamp`, `up`, `down` (linked list of children), `last_error_msg`.

### `struct ConfItem` (`include/s_conf.h`)
- `passwd` (heap), `name`, `host`, `address` (`struct irc_sockaddr`), `flags`, privilege/class info.

### Privilege System
- `struct Privs` bitmask, checked via `HasPriv(client, PRIV_*)`.
- Propagated via `CMD_PRIVS` (server-to-server).

---

## 3. Message Flow: Client → Handler

```
TCP socket read (epoll ET_READ)
  → read_packet(cptr, 1)
    → os_recv_nonb() / ssl_recv()      [fills readbuf]
    → dbuf_put(&cli_recvQ, readbuf)     [receive queue]
    → dbuf_getmsg(&cli_recvQ, cli_buffer, BUFSIZE)  [extract one line ≤512]
    → client_dopacket(cptr, dolen)
      → parse_client(cptr, cli_buffer, endp)
        → strip @tags / :prefix
        → msg_tree_parse(cmd, &msg_tree) → struct Message*
        → shun check (if user is shunned and !MFLG_NOSHUN → discard)
        → lag accounting
        → parameter tokenisation (up to MAXPARA=15)
        → mptr->handlers[cli_handler(cptr)](cptr, from, i, para)
          → e.g. m_privmsg(), m_join(), m_mode() ...
```

For server connections, `server_dopacket()` skips the receive queue and calls `parse_server()` directly on each line, resolving numeric/named prefixes to `from`.

---

## 4. Elevated-Privilege Components

| Component | Privilege |
|-----------|-----------|
| `m_oper.c` / `do_oper()` | Sets `OPER_HANDLER`, grants all oper flags |
| `m_kill.c` | `PRIV_LOCAL_KILL` / `PRIV_KILL` |
| `m_gline.c`, `m_shun.c`, `m_zline.c` | `PRIV_GLINE`, `PRIV_SHUN`, `PRIV_ZLINE` |
| `m_opmode.c`, `m_clearmode.c` | `PRIV_OPMODE` |
| `mo_die.c`, `mo_restart.c` | `PRIV_DIE`, `PRIV_RESTART` |
| `m_sa*.c` (sajoin, sanick…) | `PRIV_NETADMIN` (`+N`) |
| `m_server.c` (`mr_server`) | Password-gated, hub/leaf-checked |
| `s_bsd.c` (`add_connection`) | Runs Zline/Gline check before full auth |
| `ircd_cloaking.c` | Called for every new connection's hostname |

---

## 5. Security-Critical State Variables

| Variable | Location | Risk |
|----------|----------|------|
| `cli_handler(cptr)` | `client.h` | Controls which handler table row is used; must not advance past SERVER/OPER without auth |
| `IsOper(cptr)` / `IsAdmin(cptr)` / `IsNetAdmin(cptr)` | Flags | Set in `do_oper()`, cleared on disconnect |
| `cli_passwd(cptr)` | `con_passwd[21]` | Plaintext until consumed in `mr_server` / `m_oper`; wiped with `memset` after use |
| `cli_auth(cptr)` | `AuthRequest*` | Tracks DNS/ident/iauth completion state |
| `IsIPChecked(cptr)` | Flag | Must not be set until after Zline/throttle check |
| `feature_str(FEAT_HOST_HIDING_KEY*)` | Runtime | Used directly in `strcpy` into 512-byte static buffer |
| `IsWebIRC(cptr)` | Flag | Prevents re-entry; once set, IP/host are spoofed |
