# 📡 ESP32 WiFi Sniffer

**Setup Guide — Fontys ICT Group 1 | Daan, Mark & Mike**

---

## What This Does
The ESP32 runs in promiscuous WiFi mode, capturing **probe requests** sent by phones and laptops nearby. Every device that has WiFi on broadcasts these requests to find known networks. The ESP32 logs them and publishes to an MQTT broker, which the live dashboard reads in real time.

| What you see | What it means |
| :--- | :--- |
| **MAC address** | Unique hardware ID of the device (often randomised on modern phones) |
| **SSID** | Network name the device is looking for (*wildcard probe* = any network) |
| **RSSI** | Signal strength in dBm — stronger = closer |
| **Est. Distance** | Rough distance estimate using path-loss formula (indoor, ±50% accuracy) |

---

## What You Need

### Hardware
- ESP32-WROOM-32 development board
- USB data cable (not a charge-only cable)
- A phone or laptop to share a hotspot

### Software (one-time install)
- **VS Code** — [code.visualstudio.com](https://code.visualstudio.com)
- **PlatformIO extension** — install from VS Code Extensions (search *PlatformIO IDE*)

> ✅ **Note:** No MSYS2, no Python, no manual drivers needed. PlatformIO handles everything automatically.

---

## First-Time Setup

### Step 1 — Create the hotspot
The ESP32 is hardcoded to connect to this hotspot:

| Setting | Value |
| :--- | :--- |
| Network name (SSID) | `espsniffie` |
| Password | `wifisniffer` |
| Band | 2.4 GHz (not 5 GHz) |

On **Android**: Settings → Network → Hotspot. On **iPhone**: Settings → Personal Hotspot. Change the name and password to match exactly.

### Step 2 — Open the project in VS Code
Open VS Code → **File → Open Folder** → select the `esp32-sniffer` folder.
> ⚠️ **Warning:** The project path must not contain spaces. Place the folder at `C:\PlatformIO\esp32-sniffer\` or similar.

### Step 3 — First build (downloads toolchain)
Press `Ctrl+Alt+B` or click the **✓ checkmark** in the bottom toolbar.
The **first build takes 3–10 minutes** — PlatformIO downloads the ESP32 compiler and ESP-IDF automatically. Subsequent builds take about 10 seconds.
> ✅ You will see **[SUCCESS]** at the end of the terminal output when it's done.

### Step 4 — Flash to ESP32
1. Plug the ESP32 into your computer via USB.
2. Click the **→ arrow
