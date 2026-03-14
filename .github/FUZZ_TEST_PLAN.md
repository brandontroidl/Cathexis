# FUZZ_TEST_PLAN.md — Pass 8: Fuzzing Strategy
## Cathexis / Nefarious IRCd

---

## FZ-01 — Protocol Parser Fuzzer

**Target:** `parse_client()`, `parse_server()`

**Build harness:**
```c
// harness.c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Setup mock struct Client with all fields zeroed
    // Feed data as IRC message line to parse_client() or parse_server()
    // Catch crashes/hangs
}
```

**Tool:** libFuzzer with ASan+UBSan

**Seed corpus:**
```
PRIVMSG #test :hello
:nick!user@host PRIVMSG #test :hello
@tag1=val1;tag2=val2 PRIVMSG #test :message
@AAAA...A(511 bytes) PRIVMSG #test :x
: PRIVMSG
:user@host
UNKNOWNCMD a b c d e f g h i j k l m n o p  ← 16+ params
JOIN #chan,#chan2,#chan3
NICK \x00nick
NICK nick\r\nextra
```

---

## FZ-02 — Cloaking Key Overflow Fuzzer

**Target:** `hidehost_ipv4()`, `hidehost_ipv6()`, `hidehost_normalhost()`

**Approach:** Directly fuzz `feature_str(FEAT_HOST_HIDING_KEY1)` value length.

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Set KEY1 to a copy of data (null-terminated)
    // Call hidehost_ipv4(&test_ip);
    // Any size > 496 bytes triggers overflow
}
```

**Key fuzz inputs:**
- 495 bytes (boundary safe)
- 496 bytes (boundary safe)
- 497 bytes (overflow by 1)
- 512 bytes (overwrites res2[0])
- 1024 bytes (overwrites entire res2 + part of result)
- 2048 bytes (deep overflow)

---

## FZ-03 — Server Protocol Fuzzer (AFL++ Network Mode)

**Target:** `parse_server()` via `server_dopacket()`

**AFL++ setup:**
```bash
AFL_FUZZ_IN=./seeds/server
AFL_FUZZ_OUT=./findings/server
afl-fuzz -i $AFL_FUZZ_IN -o $AFL_FUZZ_OUT -- ./ircd_harness @@
```

**Malformed P10 inputs:**
```
# Oversized numeric prefix
AAAAAA NICK test 1 timestamp +i :realname
# Missing prefix
PRIVMSG #test :x
# Truncated message
:AB
# Unicode/high-byte in prefix
:\xff\xfe SERVER test.net 1 ts ts Jxx :desc
# Numeric prefix exceeding base64 range
ZZZZZ QUIT :bye
# Deeply nested server BURST with malformed modes
AB B #channel 1234567890 +bbbbbbb ban1 ban2 ban3 ban4 ban5 ban6 ban7 :AB
```

---

## FZ-04 — Channel Mode Parser Fuzzer

**Target:** `set_channel_mode()` / `modebuf_flush_int()`

**Seed corpus:**
```
MODE #chan +oooooooooooooooo nick1 nick2 nick3 nick4 nick5 nick6 nick7 nick8
MODE #chan +bbbbbbbbbbbbbbbb *!*@* *!*@*.* *!* ...
MODE #chan +l 99999999999
MODE #chan +k ""
MODE #chan +k AAAA...A(512 bytes)
MODE #chan +
MODE #chan ++++++++++++++++
```

---

## FZ-05 — Docker Entrypoint Config Injection Fuzzer

**Target:** `dockerentrypoint.sh` env var processing

**Approach:** Shell-level fuzzing with malicious env var values.

```bash
#!/bin/bash
for payload in \
    "1|injected_config" \
    $'1\nOper { name = "x"; }' \
    "1; Oper { name = y; password = x; host = *; class = Opers; }" \
    'test$(id)' \
    '`id`' \
    "test\"; cat /etc/passwd; echo \""; do
    IRCD_GENERAL_NUMERIC="$payload" ./dockerentrypoint.sh /bin/true
    cat /home/nefarious/ircd/base.conf
done
```

---

## FZ-06 — honggfuzz Network Fuzzer

```bash
honggfuzz \
  --input ./seeds \
  --output ./hongg_findings \
  --socket_fuzzer \
  -- ./ircd --config test.conf
```

Connect a mutated IRC client stream to port 6667; capture and replay crashes.

---

## FZ-07 — SASL / CAP Negotiation Fuzzer

**Target:** `m_authenticate.c`, `m_cap.c`

```
CAP LS 302
CAP REQ :sasl message-tags setname
CAP END
AUTHENTICATE PLAIN
AUTHENTICATE AAAA...A(1000 bytes)
AUTHENTICATE +
AUTHENTICATE \x00user\x00pass
CAP REQ :AAAA...A(400 bytes)
```
