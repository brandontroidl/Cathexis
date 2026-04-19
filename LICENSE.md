# License

Cathexis IRCd is distributed under the **GNU General Public License v3 or later** (GPL-3.0-or-later).

See `COPYING` for the full GPL v3 text, and `LICENSE` for the complete heritage chain and non-GPL component catalog.

## Copyright Heritage

### Layer 1 — Original IRC Daemon (1988–1991)

Copyright © 1988–1991 University of Oulu, Computing Center, Finland  
Author: Jarkko Oikarinen  
License: GPL v1 or later

### Layer 2 — ircu / IRCu2 (1990–2005)

Copyright © 1990–2005 Undernet Coder Committee  
Key contributors: Carlo Wood, Thomas Helvey, Kevin L. Mitchell, Perry Lorier, Michael Poole, Darren Reed, Andrea Cocito, Markku Savela, Joseph Bongaarts, hikari  
License: GPL v1 or later (most files), GPL v2 or later (files from 1998+)

### Layer 3 — Nefarious IRCu / Nefarious2 (2004–2015)

Copyright © 2004–2015 AfterNET IRC Network  
Authors: Matthew Beeching (Jobe), Alex Schumann (Rubin), Neil Spierling, and contributors  
License: GPL v2 or later; some files GPL v3 or later (Toni Garcia / IRC-Dev Development Team)

### Layer 4 — Cathexis IRCd (2026–present)

Copyright © 2026 Cathexis Development Team  
License: GPL v3 or later

## Non-GPL Components

All non-GPL code in this distribution uses permissive licenses compatible with GPL v3:

| Component | File(s) | License | Copyright |
|-----------|---------|---------|-----------|
| MD5 implementation | ircd_md5.c, ircd_md5.h | Public Domain | Colin Plumb, 1993 |
| DNS resolver library | ircd_reslib.c (portions) | BSD 4-Clause | UC Berkeley, 1985/1993 |
| DNS resolver library | ircd_reslib.c (portions) | DEC Permissive | Digital Equipment Corp, 1993 |
| DNS resolver library | ircd_reslib.c (portions) | ISC License | Internet Software Consortium, 1996–1999 |
| Install script | install-sh | MIT/X11 | Massachusetts Institute of Technology, 1991 |

**Special case:** `tests/iauth-test` is licensed under GPL v2 **only** (no "or later" clause). This file cannot be relicensed to GPL v3. It is a standalone test script not compiled into the daemon.

No Apache or LGPL licensed code exists in this codebase.

## GPL Version Compatibility

| Source | Original License | Permits v3? |
|--------|-----------------|-------------|
| IRC (1988) | GPL v1+ | Yes |
| ircu2 (1990) | GPL v1+ | Yes |
| ircu2 (1998+) | GPL v2+ | Yes |
| Nefarious2 | GPL v2+ | Yes |
| Cathexis | GPL v3+ | Native |
| ircd_md5 | Public Domain | No restrictions |
| ircd_reslib | BSD/DEC/ISC | Permissive, compatible |
| install-sh | MIT/X11 | Permissive, compatible |
| iauth-test | GPL v2 only | No (standalone test, not in daemon) |

The combined work is distributed under GPL v3 or later.

## License Files

| File | Contents |
|------|----------|
| `COPYING` | Full text of GNU General Public License v3 (648 lines) |
| `LICENSE` | Heritage chain, non-GPL catalog, compatibility table |
| `LICENSE.GPL-1` | Preserved original GPL v1 text from heritage codebase |
| `LICENSE.md` | This file — human-readable summary |
