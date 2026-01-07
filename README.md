# Recon Automation Script → Attack Surface

This project provides a **Bash automation script** for the **Reconnaissance phase** of web penetration testing.

The script focuses on **asset discovery and normalization**, producing a clean **Attack Surface dataset** that can be reused for scanners and manual validation workflows.

> No exploitation is performed.  
> Nuclei scanning is **optional** and only runs when explicitly enabled.

## Recon Workflow

The following diagram illustrates the reconnaissance workflow implemented by this script.

![Recon Workflow](Workflow/Workflow.png)

## Quick Start

### Install requirements

```bash
sudo apt update
sudo apt install -y nmap ffuf seclists jq whois dnsutils
```

Install ProjectDiscovery tools (example using `go install`):

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Optional tools:

```bash
pipx install arjun || pip install --user arjun
```

## Usage

### Script entry

```bash
./recon_automation.sh <domain> [outdir] [top_ports]
```

Arguments:

* `<domain>`: target domain (required)
* `[outdir]`: output directory (default: `recon_<domain>`)
* `[top_ports]`: Nmap top ports scope (default: `2000`)

Examples:

```bash
./recon_automation.sh example.com
./recon_automation.sh example.com recon_run1 1000
./recon_automation.sh example.com recon_run2 5000
```

## Environment Flags

### DNS brute-force

```bash
BRUTE=1 ./recon_automation.sh example.com
BRUTE=1 BRUTE_BIG=1 ./recon_automation.sh example.com
```

* `BRUTE=1`: enable DNS brute-force (requires `dnsx`)
* `BRUTE_BIG=1`: use larger subdomain wordlist

### Extended crawling

```bash
EXTEND=1 ./recon_automation.sh example.com
```

Enables deeper crawling with `katana`.

### Nuclei vulnerability scan (optional)

The script supports running Nuclei using:

```bash
nuclei -t nuclei-templates -severity critical,high,medium
```

Enable Nuclei:

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

Nuclei environment variables:

* `NUC_TPL` – templates path (default: `nuclei-templates`)
* `NUC_SEV` – severities (default: `critical,high,medium`)
* `NUC_RATE` – rate limit (default: `50`)
* `NUC_CONC` – concurrency (default: `25`)
* `NUC_TAGS` – include tags (optional)
* `NUC_EXCLUDE_TAGS` – excluded tags (default: `dos,fuzz`)

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

Main deliverable:

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

## Recon Workflow

The script implements the following stages:

### 1) DNS Recon

* Passive subdomain enumeration (`subfinder`)
* Optional DNS brute-force (`dnsx`)
* DNS resolution using `dnsx`
* Live host probing on common web ports (`httpx`)
* Host normalization (`hosts.txt`)
* Reverse PTR lookup (best-effort)
* ASN discovery (`amass` or `whois`)
* IP range aggregation (`ips.txt`)

### 2) Technology Discovery

* Technology fingerprinting on top live URLs (`whatweb`)

### 3) Enumeration

* Port scanning using `nmap --top-ports`
* Open port extraction (`host:port`)
* Virtual host discovery via Host header fuzzing (`ffuf`)

### 4) URLs & API Discovery

* Archived URLs (`waybackurls` or `gau`)
* Crawling with `katana`
* Path enumeration (`ffuf`)
* Parameter discovery (URL parsing + optional `arjun`)
* JavaScript parameter hints
* API endpoint heuristics

### 5) Optional Nuclei Scan

If enabled:

* Updates templates (best-effort)
* Runs Nuclei against live URLs
* Outputs JSONL + readable text report

## Requirements

### Required tools

* `subfinder`
* `httpx`
* `nmap`
* `ffuf`

### Required wordlists

* `seclists` installed at `/usr/share/seclists`

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
* Enable `BRUTE`, `EXTEND`, and `NUCLEI` only when permitted.
* The script prioritizes **signal quality** and **reusable datasets** over aggressive scanning.

## License / Disclaimer

This project is intended for educational and authorized security testing only.
You are responsible for complying with applicable laws and rules of engagement.