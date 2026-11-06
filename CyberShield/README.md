# CyberShield v4.2-ENT — Firewall Engine & Network Threat Prevention

Web app built for the UTS assignment. The dashboard layout matches the example
image exactly, skinned with a **Cyberpunk Edgerunners** theme (yellow `#fcee0a`,
cyan, magenta, black). All UI text is in English.

Created for: **Rafi Raihan Rijal — NIM 242502040029 — Class 3TI01**

## Folder contents

| File | Purpose |
|---|---|
| `index.html` | App structure (Dashboard, Firewall, Simulation, Log, Blacklist) |
| `css/style.css` | Cyberpunk Edgerunners theme |
| `js/app.js` | All logic: live chart, rule CRUD, simulation, connection test, log, blacklist |
| `database/cybershield.sql` | MySQL database file (3 tables: `firewall_rules`, `security_logs`, `blacklist_ips`) |
| `README.md` | This file |

> Demo data is stored in the browser's **localStorage** with the same table
> structure as the SQL above, so the app runs straight away without XAMPP / MySQL.
> If a PHP + MySQL version is required, the SQL file is ready to import.

## How to run — VS Code + Terminal / PowerShell

1. Open the `CyberShield` folder in VS Code.
2. Open the terminal in VS Code (`Ctrl + `` `) or PowerShell, then:

```powershell
cd CyberShield
python -m http.server 8000
```

3. Open your browser at: **http://localhost:8000**

### If Python is not installed, use one of these:

```powershell
# Node.js
npx --yes serve .

# PHP (if XAMPP / PHP is already installed)
php -S localhost:8000
```

### Easiest way (no terminal):
Right-click `index.html` → **Open with Live Server** (VS Code extension),
or double-click `index.html` — it still works, but the http server above is recommended.

## How to test (for the report & 3–5 minute demo video)

1. **Dashboard** — Total Packets / Connections / Threats rise every second,
   the chart moves, and the UTC clock runs.
2. **Firewall Rules** — seed data: Allow HTTP 80, HTTPS 443, DNS 53,
   Block Telnet 23, and Allow SSH Admin (LAN) 192.168.1.0/24 which is inactive.
   Click `＋ Add Rule`, toggle a switch on/off, delete a rule.
   Evaluation order: Blacklist → BLOCK → ALLOW → default deny.
3. **Traffic & Attack Simulation** — the traffic generator runs automatically
   (`Pause Traffic` button, Slow/Normal/Fast speed). Click `Port Scan`,
   `Brute Force SSH`, `DDoS / SYN Flood`, `SQL Injection`, `Malware C2 Beacon`,
   `RDP/SMB Attack` — all are recorded as BLOCKED. Check the right column
   "Live Connection Status" (524 allowed / 512 blocked at start, then rising).
4. **Manual Connection Test** — try `203.0.113.10:443` → should be **ALLOWED**,
   try `45.227.45.10:22` → should be **BLOCKED** (default deny, no ALLOW rule).
5. **Security Log** — time format `YYYY-MM-DD HH:MM:SS`, max. 500 latest,
   filter All/BLOCKED/ALLOWED, search IP/port/activity, Export CSV, Delete Log,
   `+ Blacklist` button on every blocked row.
6. **Blacklist IP** — seed data is 3 IPs (TOR exit, SSH brute force, malware C2 server).
   Add an IP/CIDR + reason, delete an IP. A blacklisted IP is always blocked
   in the connection test, whatever the rules say.
7. **Power button** — `Disable Firewall` at the top right: all connections are allowed,
   the threat label changes to CRITICAL. Click again to enable it.

## Submission (as per the assignment)

Submit to Google Drive at the link in the assignment, in a folder named:

```
Rafi Raihan Rijal_242502040029
```

Folder contents: source code (this folder), `database/cybershield.sql`,
short report, screenshots of the dashboard + main features, and a 3–5 minute demo video.
