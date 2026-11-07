# AIC8800 WiFi — macOS Userspace Driver + GUI

A **macOS userspace driver** for the AIC8800D80 USB WiFi chip: no kernel
extension, pure userspace libusb handling the full chain of
"SCSI mode switch → firmware download → WPA2 4-way handshake", plus a
one-click SwiftUI app.

Device stages: `1111:1111` (virtual CD-ROM) → `a69c:8d80` (Boot ROM) →
`a69c:8d81` (WiFi running).

## Status (tested on real hardware)

With an AIC8800D80 module and a WPA2-PSK(CCMP) AP, `aic8800-tool connect`
completes the full 4-way handshake (Msg1→2→3→4, firmware DATA_CFM `09` =
AP ACKed, GTK decrypted). Verified multiple times on 2026-11-07. The PTK
install CFM is not returned by the firmware (does not affect the handshake;
next step for the data path).

## Quick Start

```bash
# 1) Build the CLI tool (needs libusb-1.0.27, see build-tool.sh header)
bash scripts/build-tool.sh

# 2) Extract firmware (copyright AICSemi, not distributed with this repo)
bash scripts/fetch-firmware.sh /path/to/aic8800_linux_driver.tar.gz

# 3) Package the app (SwiftUI, built directly with swiftc, no Xcode project)
bash scripts/build-app.sh
open build/AIC8800WiFi.app
```

In the app: enter SSID + password → "一键连接" (one-click connect). When the
device is in CD-ROM stage the app shows the standard macOS authorization
dialog (mode switching needs root, via the standard macOS administrator
privilege escalation, no sudo piping).

## Quick Start (CLI)

```bash
# CD-ROM stage -> Boot ROM (needs root; or do it in one click in the app)
sudo bash scripts/mode-switch.sh

# Firmware upload + connect (no root needed; password via env var,
# never on the command line / ps)
AIC_SSID="<your-ssid>" AIC_PASS="<your-password>" bash scripts/connect.sh
```

## Repository Layout

```
app/                    SwiftUI app source
  AIC8800WiFiApp.swift    @main entry
  ContentView.swift       Main UI (status badge / input / handshake progress / log)
  DriverController.swift  Process management + output parsing state machine
  Resources/
    fw/                   Firmware (not in git, extract via scripts/fetch-firmware.sh)
    aic8800-tool          CLI binary (not in git, build via scripts/build-tool.sh)
scripts/
  build-tool.sh           Build the CLI tool from source (needs libusb-1.0.27)
  fetch-firmware.sh       Extract firmware from the vendor Linux driver package
  build-app.sh            Build & package the .app (swiftc + ad-hoc signing)
  mode-switch.sh          CD-ROM stage -> Boot ROM (root)
  connect.sh              No root: firmware upload + WPA2 connect
src/                     C sources (aic8800-tool.c / aic-modeswitch.c)
```

## Firmware & Licensing

- **Firmware binaries are NOT in this repository**: copyright AICSemi. The
  official Linux driver package (GPL-2.0) contains all required files;
  `scripts/fetch-firmware.sh` extracts them into `app/Resources/fw/`.
  Note: the driver package's GPL covers the driver source, **not** the
  firmware binaries themselves — those remain vendor-proprietary.
- **The CLI binary is NOT in this repository**: build it from `src/` with
  `scripts/build-tool.sh` (auditable).
- libusb is a dynamic-link dependency (LGPL-2.1); get its source from
  https://libusb.info/. This repo does not bundle libusb.
- Our own code is MIT (see LICENSE).

## Acknowledgements

- [gtxaspec/aic8800-wifi](https://github.com/gtxaspec/aic8800-wifi) (GPL-2.0) —
  primary reference for protocol and init sequence
- [olamellberg/AIC8800D80](https://github.com/olamellberg/AIC8800D80) (MIT) —
  SCSI mode-switch CDB reverse engineering
- EdoardoMantovani/aic8800-offensive-userspace-driver — **no license**; used
  only as a behavioral reference for message flows, no code copied
- [libusb](https://libusb.info/) (LGPL-2.1) — dynamically linked, not bundled

## Security Model

- Passwords travel via the `AIC_PASS` environment variable only — never on
  the command line (invisible to `ps`), never logged.
- Mode switching (CD-ROM → Boot ROM) requires root and uses the standard
  macOS administrator authorization dialog (`osascript ... with administrator
  privileges`); the privileged script takes no password arguments.
- The ad-hoc-signed app bundle is **not tamper-proof**: on a multi-user Mac,
  a local admin user could modify the bundle's scripts/binary and get code
  execution via the authorization prompt. Distribute with a Developer ID
  signature + notarization, and verify bundle integrity before privileged
  execution.

## Known Limitations

- STA mode + WPA2-PSK(CCMP) only; AP mode, WPA3, 5G association untested
- PTK install CFM not returned (GTK install works); encrypted data path pending
- Ad-hoc-signed app runs on this machine only; distribution needs
  Developer ID + notarytool
- Verified on one chip model (AIC8800D80 / u02 firmware); other models need
  adaptation

## Environment Variables (debugging)

| Variable | Purpose |
|---|---|
| `AIC_PASS` | Connect password (keeps it off the command line) |
| `AIC_STAMAC` | Force a STA MAC (default: read from efuse) |
| `AIC_SSID` | SSID (used by scripts) |
| `AIC_FW_DIR` | Firmware directory (default app/Resources/fw) |
| `AIC_NO_REINIT` | Skip full init (device already running) |
| `AIC_MSGDUMP` | Dump all message TX/RX |
| `AIC_EPDUMP` | Dump endpoint records (off by default — chatty firmware once filled a 25GB log) |
| `AIC_DEBUG_MAC` | Dump the raw GET_MAC_ADDR CFM |
| `AIC_KEYADD_TIMEOUT` | Key-install CFM wait in ms (default 500) |
| `AIC_NO_SCANU` / `AIC_PRECONNECT_SLEEP` | Scan / pre-connect behavior |

Full list in the source comments.
