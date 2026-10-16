# FloatControl

A small floating network monitor for Windows: an always-on-top widget showing
**ping**, **download** and **upload** speed live.

![icon](assets/floatcontrol.ico)

## Download

Get the ready-made exe from [`release/FloatControl-1.0.0.exe`](release/FloatControl-1.0.0.exe).
It's a single portable file, so there's nothing to install. Double-click it to start.

> Windows SmartScreen may warn about an unsigned app the first time.
> Click **More info → Run anyway**.

## Features

- Borderless floating widget, always on top, snaps to screen edges
- Ping with colour status (green < 60 ms, yellow < 150 ms, red), packet loss and jitter
- Uses the native Windows ICMP API, so there are no console pop-ups and no
  dependence on the system language
- Download/upload rates in **MB/s** or **Mbps**, a live graph, session totals and peaks
- Measures all adapters or one adapter you pick (loopback is excluded)
- Settings and position are remembered in `%APPDATA%\FloatControl\config.json`
- Optional **Start with Windows**
- Single instance, with its own AppUserModelID

### Controls

| Action | What it does |
| --- | --- |
| Drag | Move the widget |
| Double-click | Show or hide the details (totals, peaks, jitter) |
| Right-click | Opens the menu: ping host, interval, opacity, units, adapter, graph, always on top, lock position, start with Windows, reset totals, exit |

### Command line

```
FloatControl.exe [--host 1.1.1.1] [--interval 1] [--bits] [--iface "Wi-Fi"]
                 [--console [--per-iface]] [--reset] [--version]
```

`--console` prints the classic timestamped text output instead of opening the widget.

## App identity

| | |
| --- | --- |
| Product | FloatControl |
| Version | 1.0.0 |
| App GUID | `{271a2667-664e-4c37-b06b-b7a00486f8df}` |
| AppUserModelID | `CoolCupMan.FloatControl.NetMonitor.271a2667-664e-4c37-b06b-b7a00486f8df` |

These values are set in `floatcontrol.py` (`APP_VERSION`, `APP_GUID`) and are
written into the exe's version resource (*Properties → Details*). Keep the GUID
the same for every release and only bump `APP_VERSION`.

## Build from source

```
pip install -r requirements.txt pyinstaller
python build.py          # -> dist/FloatControl-<version>.exe
```

The GitHub Actions workflow in `.github/workflows/build.yml` builds the exe on
`windows-latest` for every push and uploads it as an artifact.
