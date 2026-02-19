# BreakPoint

BreakPoint is a **terminal-based Wi-Fi security auditing toolkit** for WPA/WPA2 environments. It provides an interactive menu workflow to:

- discover nearby access points,
- select and profile a target,
- capture and validate WPA handshakes,
- deauthenticate clients for testing,
- attempt dictionary-based password auditing,
- export reports and visual artifacts.

> ⚠️ **Legal & ethical notice**: Only use BreakPoint on networks and devices you **own** or have **explicit written permission** to test.

---

## What this tool does

BreakPoint combines packet capture/orchestration utilities, analysis helpers, and report generation into one CLI dashboard.

Core capabilities include:

1. **Scan nearby APs** (SSID, BSSID, channel, signal, encryption, vendor).
2. **Select target AP** manually or from scan results.
3. **Capture handshake** to `.cap` file.
4. **Send deauth frames** (for authorized resilience testing).
5. **Audit password** using a wordlist.
6. **List connected clients** observed on target BSSID.
7. **Show target profile** with metadata from latest scan.
8. **Generate exports/reports** (JSON, HTML, CSV, heatmap, topology graph).
9. **Discover probed networks** from client probe requests.

---

## Requirements

### 1) OS and privileges

- Linux environment with a wireless adapter that supports monitor mode (and ideally injection).
- Root privileges (or passwordless sudo for dependent tools).

You can quickly inspect local readiness with:

```bash
python env_setup.py
```

### 2) Python

- Python 3.10+ recommended.

### 3) Python packages

Install from `requirements.txt`:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 4) External system tools (typically required)

BreakPoint orchestrates common wireless tooling. Ensure these are available in your PATH if you plan to use all features:

- `airmon-ng`
- `airodump-ng`
- `aireplay-ng`
- `aircrack-ng`
- `iw` / `iwconfig`

On Debian/Ubuntu, these usually come from packages such as `aircrack-ng` and `wireless-tools`.

---

## Project layout

High-level files you will interact with most:

- `main_cli.py` – interactive dashboard entrypoint.
- `config.yaml` – interface, paths, and defaults.
- `captures/` – handshake captures.
- `reports/` – generated exports and visuals.
- `breakpoint.db` – local SQLite state.
- `.breakpoint_session.json` – saved session context.

---

## Configuration

BreakPoint loads settings from `config.yaml`.

Default configuration:

```yaml
interface: wlan0mon
paths:
  captures_dir: captures
  logs_file: breakpoint.log
  db_file: breakpoint.db
  session_file: .breakpoint_session.json
  reports_dir: reports
defaults:
  scan_timeout: 10
  capture_seconds: 25
  deauth_count: 16
```

### Common config edits

- Change `interface` to your adapter (for example `wlan0`, `wlan1mon`, etc.).
- Adjust default scan/capture/deauth values for your test workflow.
- Redirect output directories in `paths` if desired.

---

## Running BreakPoint

Start the dashboard:

```bash
python main_cli.py
```

On startup, BreakPoint:

- loads config,
- restores previous session (if available),
- checks injection support,
- attempts monitor mode management for your chosen interface.

Use `Ctrl+C` to request graceful shutdown; state is saved automatically.

---

## Interactive menu guide

### 1) Scan

- Prompts for scan timeout and optional encryption filter.
- Populates in-memory scan list and stores AP rows in SQLite.

Tip: run a scan before using **Target Profile** so metadata is available.

### 2) Select Target

- Select by scan index, or
- manually enter BSSID/channel/SSID.

### 3) Capture Handshake

- Prompts for output prefix and capture duration.
- Saves capture file and verifies handshake quality.
- Stores result in database as `verified` or `partial`.

### 4) Kick All Users (Deauth)

- Sends configurable deauth frame count to target network.

### 5) Audit Password

- Uses capture file + wordlist (default `/usr/share/wordlists/rockyou.txt`).
- Reports discovered password, if found.

### 6) Show Connected Clients

- Enumerates stations observed on selected BSSID.

### 7) Target Profile

- Displays SSID/BSSID/channel/band/encryption/vendor and beacon metadata.

### 8) Generate Report + Exports

Creates artifacts under `reports/`:

- `scan_export.json`
- `audit_report.html`
- `cracked.csv`
- `signal_heatmap.png`
- `topology.png`
- optional cleaned handshake capture (`handshake_clean.cap`) if input capture exists

### 9) Probed Networks

- Captures probe requests to show client MAC → requested SSID.

### 0) Feature Stub Status

- Runs placeholder integrations (online cracking submit, Telegram notify, vendor lookup stubs).

### q) Quit

- Saves session and exits.

---

## Typical workflow (recommended)

1. Start CLI.
2. **Scan** for APs.
3. **Select Target**.
4. (Optional) **Kick All Users** briefly to stimulate handshake traffic (authorized tests only).
5. **Capture Handshake**.
6. **Audit Password** with approved wordlist.
7. **Generate Report + Exports**.
8. Review `reports/` outputs and `breakpoint.db` records.

---

## Data and output files

BreakPoint can create/update:

- `breakpoint.log` – runtime logging.
- `breakpoint.db` – scan/handshake state.
- `.breakpoint_session.json` – last selected target and capture path.
- `captures/*` – capture artifacts.
- `reports/*` – export and visualization artifacts.

If you need a clean state:

```bash
rm -f breakpoint.db .breakpoint_session.json breakpoint.log
rm -rf captures reports
```

---

## Testing and quality checks

Run unit tests:

```bash
pytest
```

Optional lint:

```bash
flake8
```

---

## Troubleshooting

### No wireless interfaces found

- Confirm adapter is connected.
- Check driver support.
- Run `python env_setup.py` for detection details.

### Monitor mode fails

- Verify required external tools are installed.
- Confirm you have sufficient privileges.
- Ensure interface name is correct in prompt/config.

### Password audit fails immediately

- Validate capture path exists.
- Ensure handshake is complete/valid.
- Confirm wordlist path is readable.

### Empty client/probe results

- Increase sniff timeout.
- Stay on target channel.
- Confirm nearby traffic exists.

---

## Disclaimer

This project is for defensive security testing, education, and lab use. You are responsible for complying with all laws, policies, and authorization requirements.
