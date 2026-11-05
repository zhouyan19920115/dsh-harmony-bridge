# dsh-harmony-bridge

A **DeepSeek Harness plugin** that runs the bridge for the DSH Harmony phone app. Install it once:
DSH starts the bridge with itself, and the phone pairs over the LAN with 「自动发现」 — no desktop
package has to be copied to the computer anymore.

> Project: <https://github.com/zhouyan19920115/dsh-harmony>
> The HarmonyOS NEXT app lives in `harmony/`, the bridge sources in `bridge/`.

## Why

The old flow required the phone to hand a zip to the computer over Bluetooth/WeChat/星闪, unzip it and
double-click a launcher, on every new machine. With this plugin the computer only needs DSH + the plugin.

## What it does

- LAN discovery: `GET /_dsh/discover` so the phone finds this computer automatically;
- HTTP + WebSocket API for sessions, messages, prompts, queue, models, skills and `ask_user_question` answers;
- pairing token stored on disk; optional cloud relay; optional Huawei Push notifications.

## Install

1. DSH → Settings → Plugin Market → search `dsh-harmony-bridge` → install → restart DSH;
2. or locally: `cd plugins/dsh-harmony-bridge && npm pack`, then install the `.tgz` from the plugin manager;
3. or add this repository's market index (see `market/index.json`) to the plugin-market `indexes` config.

## Config

```yaml
- id: harmony-bridge
  name: dsh-harmony-bridge
  config:
    port: 8787
    host: 0.0.0.0
    autoStart: true
    verbose: false
    # relay: wss://your-relay.example.com/bridge
```

The bridge is spawned as a child process of DSH (`ELECTRON_RUN_AS_NODE=1`), so the user does not need a
separate Node.js installation, and it is stopped together with DSH.

## Phone side

The app's 「把桌面端发到电脑」 panel offers two options:

- **Option 1 — install the DSH plugin** (recommended): install DSH + this plugin, then use auto-discovery;
- **Option 2 — send the file**: for machines without DSH, send `dsh-harmony-desktop.zip` and run the launcher.

## License

MIT.
