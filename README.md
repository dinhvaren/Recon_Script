# Recon Automation Script → Attack Surface

A **Bash automation script** for the **Reconnaissance phase** of web penetration testing.

The goal is **asset discovery + normalization** to generate a clean, reusable **Attack Surface dataset** for scanners and manual validation.

> No exploitation is performed.  
> Nuclei scanning is **optional** and only runs when explicitly enabled.

## Recon Workflow

This is the high-level pipeline implemented by the script:

![Recon Workflow](Workflow/Workflow.png)

## Features

- Passive subdomain discovery (**subfinder**)
- Optional DNS brute-force (**dnsx**, controlled by `BRUTE=1`)
- DNS resolution + IP extraction (**dnsx**)
- Live probing on common web ports (**httpx**) → `live_urls.txt`
- Host normalization → `hosts.txt`
- Reverse PTR lookup (best-effort) → `reverse_ptr.txt`
- ASN discovery (**amass** or fallback **whois**) → `asn.txt`
- IP/CIDR aggregation → `ips.txt`
- Tech fingerprinting (optional **whatweb**) → `tech_stack.txt`
- Port scanning (**nmap --top-ports**) → `ports.txt`
- VHost discovery via Host header fuzz (**ffuf**) → `vhosts.txt`
- Archived URLs (**waybackurls** or **gau**) → `wayback_urls.txt`
- Crawling (**katana**) → `katana_urls.txt`
- Path enumeration (**ffuf**) → `paths.txt`
- Parameter discovery (URL parsing + optional **arjun**) → `params.txt`
- API endpoint heuristics → `api.txt`
- Optional vulnerability scan (**nuclei**) → JSONL + readable summary
- **(Optional) Screenshots with gowitness** when `GOWITNESS=1` (if integrated in your script)

## Quick Start

### 1) System requirements

```bash
sudo apt update
sudo apt install -y nmap ffuf seclists jq whois dnsutils unzip
```

> `dnsutils` provides `dig`.

### 2) Install ProjectDiscovery tools (Go)

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Make sure Go bin is in PATH:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

### 3) Optional tools

**Arjun (parameter discovery):**

```bash
pipx install arjun || pip install --user arjun
```

**WhatWeb (tech fingerprinting):**

```bash
sudo apt install -y whatweb
```

**Waybackurls (archived URLs):**

```bash
go install -v github.com/tomnomnom/waybackurls@latest
```

**gau (archived URLs alternative):**

```bash
go install -v github.com/lc/gau/v2/cmd/gau@latest
```

**Amass (ASN/IP intel, optional):**

```bash
sudo apt install -y amass
```

**Gowitness (screenshots, optional):**

```bash
go install -v github.com/sensepost/gowitness@latest
```

## Usage

### Script entry

```bash
./recon_automation.sh <domain> [outdir] [top_ports]
```

Arguments:

* `<domain>`: target domain (**required**)
* `[outdir]`: output directory (**default:** `recon_<domain>`)
* `[top_ports]`: Nmap top ports scope (**default:** `2000`)

Examples:

```bash
./recon_automation.sh example.com
./recon_automation.sh example.com recon_run1 1000
./recon_automation.sh example.com recon_run2 5000
```

## Environment Flags

### DNS brute-force (optional)

```bash
BRUTE=1 ./recon_automation.sh example.com
BRUTE=1 BRUTE_BIG=1 ./recon_automation.sh example.com
```

* `BRUTE=1`: enable DNS brute-force (requires `dnsx`)
* `BRUTE_BIG=1`: use larger subdomain wordlist

### Extended crawling (optional)

```bash
EXTEND=1 ./recon_automation.sh example.com
```

Enables deeper crawling options in `katana`.

### Nuclei vulnerability scan (optional)

Enable:

```bash
NUCLEI=1 ./recon_automation.sh example.com
```

Advanced usage:

```bash
NUCLEI=1 NUC_RATE=80 NUC_CONC=50 ./recon_automation.sh example.com
NUCLEI=1 NUC_SEV=critical,high,medium ./recon_automation.sh example.com
NUCLEI=1 NUC_TPL=nuclei-templates ./recon_automation.sh example.com
NUCLEI=1 NUC_TAGS=cve,misconfig ./recon_automation.sh example.com
```

Variables:

* `NUC_TPL` – templates path (**default:** `nuclei-templates`)
* `NUC_SEV` – severities (**default:** `critical,high,medium`)
* `NUC_RATE` – rate limit (**default:** `50`)
* `NUC_CONC` – concurrency (**default:** `25`)
* `NUC_TAGS` – include tags (**optional**)
* `NUC_EXCLUDE_TAGS` – excluded tags (**default:** `dos,fuzz`)

### Screenshots with Gowitness (optional)

> Only applicable if your script includes the gowitness stage.

```bash
GOWITNESS=1 ./recon_automation.sh example.com
```

Common tunables:

```bash
GOWITNESS=1 GW_FORMAT=png GW_FULLPAGE=1 GW_DELAY=5 GW_TIMEOUT=30 GW_THREADS=6 ./recon_automation.sh example.com
```

* `GW_FORMAT` – `png` or `jpeg` (**default:** `png`)
* `GW_FULLPAGE` – full page screenshots (**default:** `1`)
* `GW_DELAY` – wait before screenshot (SPA/JS-heavy sites) (**default:** `5`)
* `GW_TIMEOUT` – timeout seconds (**default:** `30`)
* `GW_THREADS` – concurrency (**default:** `6`)

## Output Structure

```text
recon_target/
├── DNS_Recon/
├── enumeration/
├── tech/
├── urls/
├── js/
├── vuln/
├── attack_surface/
├── logs/
└── tmp/
```

### Main deliverable: Attack Surface dataset

```text
attack_surface/
├── hosts.txt
├── ips.txt
├── ports.txt
├── vhosts.txt
├── urls.txt
├── paths.txt
├── params.txt
├── api.txt
└── summary.md
```

If gowitness is enabled:

```text
attack_surface/screenshots_gowitness/
├── screenshots/
├── gowitness.sqlite3
└── gowitness.jsonl
```

## Stages (What the script does)

### 1) DNS Recon

* Passive subdomain enumeration (`subfinder`)
* Optional DNS brute-force (`dnsx`)
* DNS resolution (`dnsx`)
* Live probing on common web ports (`httpx`)
* Host normalization (`hosts.txt`)
* Reverse PTR lookup (best-effort)
* ASN discovery (`amass` or `whois`)
* IP range aggregation (`ips.txt`)

### 2) Technology Discovery

* Tech fingerprinting on top live URLs (`whatweb`)

### 3) Enumeration

* Port scanning using `nmap --top-ports`
* Open port extraction (`host:port`)
* Virtual host discovery via Host header fuzzing (`ffuf`)

### 4) URLs & API Discovery

* Archived URLs (`waybackurls` or `gau`)
* Crawling (`katana`)
* Path enumeration (`ffuf`)
* Parameter discovery (URL parsing + optional `arjun`)
* JavaScript parameter hints
* API endpoint heuristics

### 5) Optional Nuclei Scan

If enabled:

* Updates templates (best-effort)
* Runs Nuclei against live URLs
* Outputs JSONL + readable text/summary

## Requirements

### Required tools

* `subfinder`
* `httpx`
* `nmap`
* `ffuf`

### Required wordlists

SecLists under:

* `/usr/share/seclists`

Install:

```bash
sudo apt install -y seclists
```

### Optional tools (auto-detected)

* `dnsx`
* `waybackurls` / `gau`
* `katana`
* `arjun`
* `whatweb`
* `jq`
* `amass`
* `whois`
* `dig`
* `nuclei`
* `gowitness` (if enabled)

## Wordlists Used (SecLists)

| Purpose               | Wordlist                                              |
| --------------------- | ----------------------------------------------------- |
| Subdomain enum        | `Discovery/DNS/subdomains-top1million-20000.txt`      |
| Subdomain brute (big) | `Discovery/DNS/subdomains-top1million-110000.txt`     |
| VHost fuzz            | `Discovery/DNS/deepmagic.com-prefixes-top500.txt`     |
| Directory brute       | `Discovery/Web-Content/directory-list-2.3-medium.txt` |
| Common paths          | `Discovery/Web-Content/common.txt`                    |

## Notes & Safety

* Use only on targets you own or have explicit authorization to test.
* Enable `BRUTE`, `EXTEND`, `NUCLEI`, `GOWITNESS` only when permitted.
* The script prioritizes **signal quality** and **reusable datasets** over aggressive scanning.

## License / Disclaimer

This project is intended for educational and authorized security testing only.
You are responsible for complying with applicable laws and rules of engagement.