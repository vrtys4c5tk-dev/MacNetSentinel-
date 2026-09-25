# 🛡️ MacNetSentinel

**MacNetSentinel** is a lightweight, background network and socket monitoring utility for macOS. It analyzes active IPv4/IPv6 connections in real-time, categorizes system processes vs. known third-party applications, and flags suspicious or unknown background network activity.

---

## ⚡ Features

- **Real-Time Socket Inspection:** Scans active `ESTABLISHED` network sockets via macOS native tools.
- **Process Categorization:** Distinguishes between default macOS system processes (`[SYSTEM]`), trusted user apps (`[KNOWN APP]`), and unverified background entities (`[UNKNOWN]`).
- **Clean Output:** Automatically strips hex-escaped process names (e.g., `Opera\x20` -> `Opera`).
- **Zero Heavy Dependencies:** Written entirely in standard Python without external third-party libraries.

---

## 🚀 Quick Start
===========================================================================
      MACNETSENTINEL - BACKGROUND NETWORK & SOCKET MONITOR
      License: Dual License | Copyright (c) 2026 MacNetSentinel
      Execution Time: 2026-09-25 18:50:00
===========================================================================

 SUMMARY:
  • Total Active External Sockets : 8
  • Unknown / Suspicious Connections : None detected (All traffic belongs to system/known apps).

 DETECTED SOCKET CONNECTIONS:
---------------------------------------------------------------------------
PROCESS            PID      USER         STATUS         CONNECTION (LOCAL -> REMOTE)
---------------------------------------------------------------------------
mDNSResponder      104      _mdnsresponder [SYSTEM  ]   192.168.1.50:5353->...
Spotify            661      semanurbicer   [KNOWN APP]  192.168.1.50:49913->34.158.1.133:4070
Code               1250     semanurbicer   [KNOWN APP]  192.168.1.50:50096->150.171.109.100:443
===========================================================================
Licensing & Commercial Terms
This project is distributed under a Dual-License model:

Non-Commercial / Academic / Personal Use: Free to use, evaluate, and study.

Commercial / Enterprise Use: Requires a commercial license.

For enterprise licensing or commercial integration inquiries, please contact:
📩 Email: semanur0619.bier@gmail.com
