# Galactica — Free Fire iOS Mod

Unity-canvas, in-game mod menu for Free Fire iOS 1.132.1 (`com.dts.freefireth`).
Uses frida-gadget + frida-il2cpp-bridge. The patched IPA is built by GitHub Actions
and published as a release asset.

## Build

Trigger the workflow:

- GitHub UI → **Actions → Galactica Build → Run workflow** (branch `claude/serene-edison-xmfbql`)
- or via API — any `workflow_dispatch` payload works; defaults point at the original
  IPA and a known-good Frida gadget.

The workflow:

1. Pulls the original IPA from the `fforig` release of this repo.
2. Pulls `frida-gadget-16.5.9-ios-universal.dylib.gz` from the upstream release.
3. Runs `patch_ipa.py` which:
   - thins the gadget to **arm64e** (iPhone XS+ / A12+),
   - nulls out frida debug strings,
   - injects `LC_LOAD_DYLIB` into the main Mach-O,
   - drops `_CodeSignature` / `SC_Info` / `embedded.mobileprovision`,
   - re-zips.
4. Uploads the output as the `galactica` release asset.

## Install

- **TrollStore** — AirDrop or Files app → opens in TrollStore → Install.
- **Sideloadly** — drag IPA, Apple ID credentials, Start.
- **ESign / Scarlet** — enterprise cert.

## Usage

Launch the game. Tap the screen's **bottom-left corner once** to open Galactica.

Tabs: **AIMBOT · ESP · SETTINGS**.

- Aimbot — mode / FOV (0–367°) / smoothing / accuracy cap / no-indicator / predict shot
- ESP — box, name, HP bar, distance, bone lines, skeleton, team-check, max distance
- Settings — menu hue, ESP color cycle, opacity, anti-ban toggles, auto-headshot,
  instant-hit, **Guest Reset** (one-tap button, round indicator pulses)

Each feature auto-discovers the methods it needs at runtime and keeps growing the
hook set every 5 s so late-loaded classes get caught.

## Ban capture

Settings → Capture ban code → ON.
On a ban event, `/var/mobile/Containers/Data/Application/<GUID>/Documents/ban-trace.log`
collects:
- class/method that was hit
- arg types + stringified values
- native call stack

Retrieve via Filza (TrollStore) or Files app sharing.

## Files

- `ff.js` — the Galactica mod (Frida script, frida-il2cpp-bridge)
- `libnativeunity.config.json` — gadget runtime config
- `patch_ipa.py` — the patcher (thin / strip / inject / package)
- `.github/workflows/galactica.yml` — CI that assembles the IPA
