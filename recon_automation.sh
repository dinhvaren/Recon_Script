#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-}"
# normalize if user passes URL
TARGET="${TARGET#http://}"
TARGET="${TARGET#https://}"
TARGET="${TARGET%%/*}"

# sanitize target for folder name (avoid / : ? etc.)
SAFE_TARGET="$(echo "${TARGET:-target}" | sed 's#[^a-zA-Z0-9._-]#_#g')"
OUTBASE="${2:-recon_${SAFE_TARGET}}"
TOPPORTS="${3:-2000}"

if [[ -z "${TARGET}" ]]; then
  echo "Usage: $0 <domain> [outdir] [top_ports]"
  echo "Env:"
  echo "  BRUTE=1              Enable dns brute (requires dnsx)"
  echo "  BRUTE_BIG=1          Use bigger subdomain wordlist for brute"
  echo "  EXTEND=1             Enable heavier URL/JS crawling (katana depth/inputs)"
  echo "  NUCLEI=1             Enable nuclei vuln scan (requires nuclei)"
  echo "  NUC_TPL=nuclei-templates   nuclei templates path/name (default: nuclei-templates)"
  echo "  NUC_RATE=50          nuclei rate limit (req/sec)"
  echo "  NUC_CONC=25          nuclei concurrency"
  echo "  NUC_SEV=critical,high,medium   nuclei severities (default: critical,high,medium)"
  echo "  NUC_TAGS=            nuclei tags filter (optional, e.g. cve,misconfig)"
  echo "  NUC_EXCLUDE_TAGS=dos,fuzz      nuclei exclude-tags (optional)"
  echo
  echo "  GOWITNESS=1          Enable gowitness screenshots (requires gowitness)"
  echo "  GW_TIMEOUT=30        gowitness timeout seconds"
  echo "  GW_DELAY=5           gowitness delay before screenshot"
  echo "  GW_THREADS=6         gowitness concurrency"
  echo "  GW_FULLPAGE=1        full-page screenshots (1=on, 0=off)"
  echo "  GW_FORMAT=png        screenshot format: png|jpeg"
  echo
  exit 1
fi

# Wordlists (SecLists)
SECLISTS="/usr/share/seclists"

# Default: fast + solid
SUB_WORDLIST="${SECLISTS}/Discovery/DNS/subdomains-top1million-20000.txt"
SUB_WORDLIST_BIG="${SECLISTS}/Discovery/DNS/subdomains-top1million-110000.txt"

# VHost: prefixes usually better signal than full subdomain list
VHOST_WORDLIST="${SECLISTS}/Discovery/DNS/deepmagic.com-prefixes-top500.txt"

# Dir brute: medium + common
DIR_WORDLIST="${SECLISTS}/Discovery/Web-Content/directory-list-2.3-medium.txt"
COMMON_WORDLIST="${SECLISTS}/Discovery/Web-Content/common.txt"

for wl in "$SUB_WORDLIST" "$VHOST_WORDLIST" "$DIR_WORDLIST" "$COMMON_WORDLIST"; do
  if [[ ! -f "$wl" ]]; then
    echo "[!] Missing wordlist: $wl"
    echo "    Install: sudo apt install seclists"
    exit 1
  fi
done

# Output structure
OUT="${OUTBASE}"
mkdir -p "$OUT"/{DNS_Recon,enumeration,tech,urls,js,vuln,attack_surface,logs,tmp}

LOG="$OUT/logs/run.log"
touch "$LOG"
log() { echo "[$(date +'%F %T')] $*" | tee -a "$LOG" ; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[!] Missing command: $1" | tee -a "$LOG"
    return 1
  }
}

# Tools check
log "Checking tools..."
need_cmd subfinder || exit 1
need_cmd httpx || exit 1
need_cmd nmap || exit 1
need_cmd ffuf || exit 1

# Optional tools
HAS_DNSX=0; command -v dnsx >/dev/null 2>&1 && HAS_DNSX=1
HAS_WAYBACKURLS=0; command -v waybackurls >/dev/null 2>&1 && HAS_WAYBACKURLS=1
HAS_GAU=0; command -v gau >/dev/null 2>&1 && HAS_GAU=1
HAS_ARJUN=0; command -v arjun >/dev/null 2>&1 && HAS_ARJUN=1
HAS_KATANA=0; command -v katana >/dev/null 2>&1 && HAS_KATANA=1
HAS_WHATWEB=0; command -v whatweb >/dev/null 2>&1 && HAS_WHATWEB=1
HAS_JQ=0; command -v jq >/dev/null 2>&1 && HAS_JQ=1
HAS_AMASS=0; command -v amass >/dev/null 2>&1 && HAS_AMASS=1
HAS_WHOIS=0; command -v whois >/dev/null 2>&1 && HAS_WHOIS=1
HAS_DIG=0; command -v dig >/dev/null 2>&1 && HAS_DIG=1
HAS_NUCLEI=0; command -v nuclei >/dev/null 2>&1 && HAS_NUCLEI=1
HAS_GOWITNESS=0; command -v gowitness >/dev/null 2>&1 && HAS_GOWITNESS=1

echo "$TARGET" > "$OUT/target.txt"

# Tunables
THREADS_HTTPX=80
THREADS_FFUF=80
TIMEOUT=10

# 01) DNS Recon
log "DNS Recon"

SUBS="$OUT/DNS_Recon/subdomains.txt"
RESOLVED_MAP="$OUT/DNS_Recon/resolved_map.txt"     # host + response (dnsx -re)
RESOLVED_IPS="$OUT/DNS_Recon/resolved_ips.txt"     # ips only (dnsx -ro)
LIVE_FULL="$OUT/DNS_Recon/live_httpx_full.txt"     # keep title/status/tech
LIVE="$OUT/DNS_Recon/live_urls.txt"                # urls only (for pipelines)

# Reverse PTR, ASN/IP, IP attack surface
REV_PTR="$OUT/DNS_Recon/reverse_ptr.txt"
ASN_TXT="$OUT/DNS_Recon/asn.txt"
ASN_IPS_TXT="$OUT/DNS_Recon/asn_ips.txt"
IPS_TXT="$OUT/attack_surface/ips.txt"

if [[ ! -s "$SUBS" ]]; then
  log "Subdomain enum (passive): subfinder -d $TARGET"
  subfinder -d "$TARGET" -silent | sort -u > "$SUBS"
  log "Subdomains(passive): $(wc -l < "$SUBS")"
else
  log "Skip subfinder (exists): $SUBS"
fi

# ALWAYS include root/apex domain (subfinder may not include it)
if ! grep -qxF "$TARGET" "$SUBS" 2>/dev/null; then
  echo "$TARGET" >> "$SUBS"
  sort -u "$SUBS" -o "$SUBS"
  log "Added root domain into subdomains list: $TARGET"
fi

# Optional brute DNS (only if dnsx exists and BRUTE=1)
if [[ "${BRUTE:-0}" == "1" ]]; then
  if [[ $HAS_DNSX -eq 1 ]]; then
    WL="$SUB_WORDLIST"
    [[ "${BRUTE_BIG:-0}" == "1" ]] && WL="$SUB_WORDLIST_BIG"

    log "Subdomain brute (dnsx) with: $(basename "$WL")"
    cat "$WL" | awk -v d="$TARGET" '{print $0"."d}' \
      | dnsx -silent -a -ro 2>/dev/null \
      | sort -u > "$OUT/DNS_Recon/subdomains_brute.txt" || true

    cat "$SUBS" "$OUT/DNS_Recon/subdomains_brute.txt" 2>/dev/null | sort -u > "$OUT/tmp/subs_all.tmp"
    mv "$OUT/tmp/subs_all.tmp" "$SUBS"
    log "Subdomains(total): $(wc -l < "$SUBS")"
  else
    log "BRUTE=1 but dnsx not found -> skip brute"
  fi
fi

# Resolve (dnsx: use -re/-ro; retry with public resolvers if 0)
if [[ ! -s "$RESOLVED_IPS" ]]; then
  : > "$RESOLVED_MAP"
  : > "$RESOLVED_IPS"

  if [[ $HAS_DNSX -eq 1 ]]; then
    log "Resolve: dnsx (map + ips)"

    # First try (default resolvers)
    dnsx -silent -a -re -l "$SUBS" 2>/dev/null | sort -u > "$RESOLVED_MAP" || true
    dnsx -silent -a -ro -l "$SUBS" 2>/dev/null | sort -u > "$RESOLVED_IPS" || true

    # If still empty, retry with public resolvers
    if [[ ! -s "$RESOLVED_IPS" ]]; then
      log "dnsx returned 0 IPs -> retry with public resolvers"
      RESOLVERS="$OUT/tmp/resolvers.txt"
      cat > "$RESOLVERS" << 'EOF'
1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
9.9.9.9
EOF
      dnsx -silent -a -re -l "$SUBS" -r "$RESOLVERS" 2>/dev/null | sort -u > "$RESOLVED_MAP" || true
      dnsx -silent -a -ro -l "$SUBS" -r "$RESOLVERS" 2>/dev/null | sort -u > "$RESOLVED_IPS" || true
    fi
  else
    log "dnsx not found -> cannot resolve IPs (RESOLVED_IPS will be empty)"
    : > "$RESOLVED_MAP"
    : > "$RESOLVED_IPS"
  fi

  log "Resolved IPs: $(wc -l < "$RESOLVED_IPS" 2>/dev/null || echo 0)"
else
  log "Skip resolve (exists): $RESOLVED_IPS"
fi

# Live check (include common web ports)
if [[ ! -s "$LIVE" ]]; then
  log "Live check: httpx (common web ports)"
  cat "$SUBS" | httpx -silent -threads "$THREADS_HTTPX" -timeout "$TIMEOUT" \
    -ports 80,81,443,3000,5000,8000,8080,8443,9000 \
    -follow-redirects -title -status-code -tech-detect \
    -o "$LIVE_FULL" || true

  awk '{print $1}' "$LIVE_FULL" 2>/dev/null | sort -u > "$LIVE" || true
  [[ -s "$LIVE" ]] || : > "$LIVE"
  log "Live URLs: $(wc -l < "$LIVE" 2>/dev/null || echo 0)"
else
  log "Skip httpx (exists): $LIVE"
fi

# 01b) Screenshots (gowitness) - optional
log "Screenshots (optional: GOWITNESS=1)"

GW_DIR="$OUT/attack_surface/screenshots_gowitness"
GW_SS_DIR="$GW_DIR/screenshots"
GW_DB="$GW_DIR/gowitness.sqlite3"
GW_JSONL="$GW_DIR/gowitness.jsonl"
mkdir -p "$GW_SS_DIR"

GW_TIMEOUT="${GW_TIMEOUT:-30}"
GW_DELAY="${GW_DELAY:-5}"
GW_THREADS="${GW_THREADS:-6}"
GW_FORMAT="${GW_FORMAT:-png}"
GW_FULLPAGE="${GW_FULLPAGE:-1}"

if [[ "${GOWITNESS:-0}" == "1" ]]; then
  if [[ $HAS_GOWITNESS -eq 1 && -s "$LIVE" ]]; then
    log "Run gowitness screenshots -> $GW_SS_DIR"

    GW_ARGS=(
      scan file -f "$LIVE"
      --timeout "$GW_TIMEOUT"
      --delay "$GW_DELAY"
      --threads "$GW_THREADS"
      --screenshot-path "$GW_SS_DIR"
      --screenshot-format "$GW_FORMAT"
      --write-db
      --write-db-uri "sqlite://$GW_DB"
      --write-jsonl
      --write-jsonl-file "$GW_JSONL"
    )

    if [[ "$GW_FULLPAGE" == "1" ]]; then
      GW_ARGS+=(--screenshot-fullpage)
    fi

    gowitness "${GW_ARGS[@]}" || true

    SS_COUNT="$(find "$GW_SS_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')"
    log "Gowitness done. Screenshots: ${SS_COUNT}"
    log "Gowitness DB: $GW_DB"
    log "Gowitness JSONL: $GW_JSONL"
  else
    log "GOWITNESS=1 but gowitness not found or LIVE empty -> skip"
  fi
else
  log "GOWITNESS=0 -> skip gowitness screenshots"
fi

# hosts.txt (IMPORTANT: host only, no :port)
HOSTS_TXT="$OUT/attack_surface/hosts.txt"
if [[ ! -s "$HOSTS_TXT" ]]; then
  log "Build hosts.txt from live URLs"
  sed -E 's#^https?://##' "$LIVE" 2>/dev/null \
    | awk -F/ '{print $1}' \
    | cut -d: -f1 \
    | awk 'NF' \
    | sort -u > "$HOSTS_TXT" || true
  [[ -s "$HOSTS_TXT" ]] || : > "$HOSTS_TXT"
  log "Hosts: $(wc -l < "$HOSTS_TXT" 2>/dev/null || echo 0)"
fi

# Reverse PTR from resolved IPs
if [[ ! -s "$REV_PTR" ]]; then
  : > "$REV_PTR"
  if [[ $HAS_DIG -eq 1 && -s "$RESOLVED_IPS" ]]; then
    log "Reverse PTR lookup from resolved IPs (best-effort)"
    sort -u "$RESOLVED_IPS" | while read -r ip; do
      [[ -z "$ip" ]] && continue
      ptr="$(dig +short -x "$ip" 2>/dev/null | head -n1 || true)"
      [[ -n "$ptr" ]] && echo "$ip -> $ptr"
    done >> "$REV_PTR" || true
  else
    log "dig not found or no resolved IPs -> skip reverse PTR"
  fi
fi

# ASN / IP Range Recon (optional)
if [[ ! -s "$ASN_TXT" ]]; then
  : > "$ASN_TXT"
  if [[ $HAS_AMASS -eq 1 ]]; then
    log "ASN recon: amass intel -d $TARGET (extract ASNs)"
    amass intel -d "$TARGET" 2>/dev/null \
      | grep -oE 'AS[0-9]+' | sort -u >> "$ASN_TXT" || true
  elif [[ $HAS_WHOIS -eq 1 ]]; then
    log "ASN recon: whois (best-effort, may be incomplete)"
    whois "$TARGET" 2>/dev/null | grep -oiE 'AS[0-9]+' | sort -u >> "$ASN_TXT" || true
  else
    log "No amass/whois -> skip ASN recon"
  fi
  sort -u "$ASN_TXT" -o "$ASN_TXT" || true
fi

if [[ ! -s "$ASN_IPS_TXT" ]]; then
  : > "$ASN_IPS_TXT"
  if [[ -s "$ASN_TXT" && $HAS_AMASS -eq 1 ]]; then
    log "ASN -> IPs: amass intel -asn (best-effort)"
    while read -r asn; do
      [[ -z "$asn" ]] && continue
      amass intel -asn "${asn#AS}" 2>/dev/null \
        | awk '{print $1}' \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$' || true
    done < "$ASN_TXT" | sort -u > "$ASN_IPS_TXT" || true
  else
    : > "$ASN_IPS_TXT"
  fi
fi

# Build attack_surface/ips.txt = resolved IPs + ASN IPs (if any)
if [[ ! -s "$IPS_TXT" ]]; then
  log "Build ips.txt (resolved IPs + ASN IPs)"
  {
    cat "$RESOLVED_IPS" 2>/dev/null || true
    cat "$ASN_IPS_TXT" 2>/dev/null || true
  } | awk 'NF' | sort -u > "$IPS_TXT" || true
  [[ -s "$IPS_TXT" ]] || : > "$IPS_TXT"
  log "IPs/CIDRs: $(wc -l < "$IPS_TXT" 2>/dev/null || echo 0)"
fi

# Technology Discovery
log "Technology Discovery"
TECH_TXT="$OUT/tech/tech_stack.txt"

if [[ ! -s "$TECH_TXT" ]]; then
  : > "$TECH_TXT"
  if [[ $HAS_WHATWEB -eq 1 && -s "$LIVE" ]]; then
    log "whatweb on top 30 live URLs"
    head -n 30 "$LIVE" | while read -r url; do
      echo "### $url" >> "$TECH_TXT"
      whatweb --no-errors --color=never "$url" 2>/dev/null >> "$TECH_TXT" || true
      echo >> "$TECH_TXT"
    done
  else
    log "whatweb not found or LIVE empty -> tech file will be minimal"
    echo "whatweb not available or no live URLs." >> "$TECH_TXT"
  fi
fi

# 02) Enumeration: Ports + VHost
log "Enumeration"

PORTS_RAW="$OUT/enumeration/nmap_raw.txt"
PORTS_TXT="$OUT/attack_surface/ports.txt"
VHOSTS_TXT="$OUT/attack_surface/vhosts.txt"

if [[ ! -s "$PORTS_RAW" ]]; then
  if [[ -s "$HOSTS_TXT" ]]; then
    log "Nmap scan (top $TOPPORTS ports) on hosts.txt"
    nmap -sS -sV -Pn --top-ports "$TOPPORTS" -T4 -iL "$HOSTS_TXT" -oN "$PORTS_RAW" || true
  else
    log "hosts.txt empty -> skip nmap"
    : > "$PORTS_RAW"
  fi
else
  log "Skip nmap (exists): $PORTS_RAW"
fi

if [[ ! -s "$PORTS_TXT" ]]; then
  log "Parse nmap -> ports.txt (host:port)"
  awk '
    /^Nmap scan report for /{
      host_line=$0
      host=$NF
      gsub(/[()]/,"",host)
    }
    /^[0-9]+\/tcp[[:space:]]+open/{
      split($1,a,"/")
      port=a[1]
      if(host!="" && port!=""){ print host ":" port }
    }' "$PORTS_RAW" | sort -u > "$PORTS_TXT" || true
  [[ -s "$PORTS_TXT" ]] || : > "$PORTS_TXT"
  log "Open ports: $(wc -l < "$PORTS_TXT" 2>/dev/null || echo 0)"
fi

# Base URL for fuzz (FIX: more robust than grep)
BASE_URL="$OUT/tmp/base_url.txt"
if [[ ! -s "$BASE_URL" ]]; then
  awk 'NF{print $1}' "$LIVE" 2>/dev/null \
    | grep -E '^https?://' \
    | head -n1 > "$BASE_URL" || true
fi

# VHost enum (Host header fuzz)
if [[ ! -s "$VHOSTS_TXT" ]]; then
  if [[ -s "$BASE_URL" ]]; then
    BASE="$(cat "$BASE_URL")"
    log "VHost enum with ffuf (Host header) against: $BASE"
    FFUF_JSON="$OUT/enumeration/vhost_ffuf.json"

    ffuf -u "$BASE" \
      -H "Host: FUZZ.${TARGET}" \
      -w "$VHOST_WORDLIST" \
      -t "$THREADS_FFUF" \
      -timeout "$TIMEOUT" \
      -ac \
      -of json -o "$FFUF_JSON" >/dev/null 2>&1 || true

    if [[ -s "$FFUF_JSON" ]]; then
      if [[ $HAS_JQ -eq 1 ]]; then
        jq -r '.results[].input.FUZZ' "$FFUF_JSON" 2>/dev/null \
          | sed "s#$#.${TARGET}#" | sort -u > "$VHOSTS_TXT" || true
      else
        grep -oE '"FUZZ":"[^"]+"' "$FFUF_JSON" \
          | sed -E 's/.*"FUZZ":"([^"]+)".*/\1/' \
          | sed "s#$#.${TARGET}#" | sort -u > "$VHOSTS_TXT" || true
      fi
    fi

    [[ -s "$VHOSTS_TXT" ]] || : > "$VHOSTS_TXT"
    log "VHosts found: $(wc -l < "$VHOSTS_TXT" 2>/dev/null || echo 0)"
  else
    log "No base URL available (LIVE empty). Creating empty vhosts.txt"
    : > "$VHOSTS_TXT"
  fi
else
  log "Skip vhost enum (exists): $VHOSTS_TXT"
fi

# 03) URLs / API Discovery
log "URLs / API Discovery"

WAYBACK="$OUT/urls/wayback_urls.txt"
KATANA_URLS="$OUT/urls/katana_urls.txt"
PATHS="$OUT/urls/paths.txt"
PARAMS="$OUT/urls/params.txt"
API="$OUT/urls/api_endpoints.txt"

URLS_TXT="$OUT/attack_surface/urls.txt"
PATHS_TXT="$OUT/attack_surface/paths.txt"
PARAMS_TXT="$OUT/attack_surface/params.txt"
API_TXT="$OUT/attack_surface/api.txt"

# Archived URLs: waybackurls OR gau
if [[ ! -s "$WAYBACK" ]]; then
  if [[ $HAS_WAYBACKURLS -eq 1 ]]; then
    log "Archived URLs: waybackurls"
    cat "$SUBS" | waybackurls | sort -u > "$WAYBACK" || true
  elif [[ $HAS_GAU -eq 1 ]]; then
    log "Archived URLs: gau"
    cat "$SUBS" | gau --threads 20 | sort -u > "$WAYBACK" || true
  else
    log "No waybackurls/gau found -> create empty"
    : > "$WAYBACK"
  fi
else
  log "Skip archived URLs (exists): $WAYBACK"
fi

# Katana crawl (URLs/JS endpoints)
if [[ ! -s "$KATANA_URLS" ]]; then
  : > "$KATANA_URLS"

  if [[ $HAS_KATANA -eq 1 && -s "$LIVE" ]]; then
    log "Katana crawl (top 50 live URLs)"
    head -n 50 "$LIVE" > "$OUT/tmp/live_50.txt"

    # FIX: more reliable detect for -depth token
    KATANA_DEPTH_FLAG="-d"
    if katana -h 2>&1 | grep -Eq '(^|[[:space:]])-depth([[:space:]]|,|$)'; then
      KATANA_DEPTH_FLAG="-depth"
    fi

    if [[ "${EXTEND:-0}" == "1" ]]; then
      katana -silent -list "$OUT/tmp/live_50.txt" -jc -kf all "$KATANA_DEPTH_FLAG" 3 -ps -o "$KATANA_URLS" || true
    else
      katana -silent -list "$OUT/tmp/live_50.txt" -jc -kf all "$KATANA_DEPTH_FLAG" 2 -o "$KATANA_URLS" || true
    fi

    [[ -s "$KATANA_URLS" ]] && sort -u "$KATANA_URLS" -o "$KATANA_URLS" || true
    rm -f "$OUT/tmp/live_50.txt" || true
  fi
fi

# Build urls.txt (live + archived + katana)
if [[ ! -s "$URLS_TXT" ]]; then
  log "Build urls.txt (LIVE + archived + katana)"
  cat "$LIVE" "$WAYBACK" "$KATANA_URLS" 2>/dev/null \
    | awk 'NF' \
    | sed -E 's/#.*$//' \
    | sort -u > "$URLS_TXT" || true
  [[ -s "$URLS_TXT" ]] || : > "$URLS_TXT"
  log "Total URLs: $(wc -l < "$URLS_TXT" 2>/dev/null || echo 0)"
fi

# Path enum
if [[ ! -s "$PATHS" ]]; then
  if [[ -s "$BASE_URL" ]]; then
    BASE="$(cat "$BASE_URL")"
    log "Path enum: ffuf (common + medium) on $BASE"

    : > "$PATHS"

    ffuf -u "${BASE%/}/FUZZ" \
      -w "$COMMON_WORDLIST" \
      -t "$THREADS_FFUF" -timeout "$TIMEOUT" \
      -ac \
      -of json -o "$OUT/urls/paths_common.json" >/dev/null 2>&1 || true

    ffuf -u "${BASE%/}/FUZZ" \
      -w "$DIR_WORDLIST" \
      -t "$THREADS_FFUF" -timeout "$TIMEOUT" \
      -ac \
      -of json -o "$OUT/urls/paths_medium.json" >/dev/null 2>&1 || true

    for j in "$OUT/urls/paths_common.json" "$OUT/urls/paths_medium.json"; do
      [[ -s "$j" ]] || continue
      if [[ $HAS_JQ -eq 1 ]]; then
        jq -r '.results[].url' "$j" 2>/dev/null >> "$PATHS" || true
      else
        grep -oE '"url":"[^"]+"' "$j" | sed -E 's/.*"url":"([^"]+)".*/\1/' >> "$PATHS" || true
      fi
    done

    sort -u "$PATHS" -o "$PATHS" || true
    [[ -s "$PATHS" ]] || : > "$PATHS"
  else
    : > "$PATHS"
  fi
else
  log "Skip path enum (exists): $PATHS"
fi

# Params: extract from URLs + optional arjun
if [[ ! -s "$PARAMS" ]]; then
  log "Parameter discovery: extract '?' from urls.txt (+ optional arjun)"
  : > "$PARAMS"

  grep -F "?" "$URLS_TXT" 2>/dev/null | sort -u >> "$PARAMS" || true

  if [[ $HAS_ARJUN -eq 1 && -s "$LIVE" ]]; then
    log "Arjun (top 50 live URLs) --passive"
    head -n 50 "$LIVE" > "$OUT/tmp/live_50.txt"
    arjun -i "$OUT/tmp/live_50.txt" -m GET --passive -oT "$OUT/tmp/arjun_params.tmp" >/dev/null 2>&1 || true
    cat "$OUT/tmp/arjun_params.tmp" 2>/dev/null >> "$PARAMS" || true
    rm -f "$OUT/tmp/live_50.txt" "$OUT/tmp/arjun_params.tmp" || true
  fi

  sort -u "$PARAMS" -o "$PARAMS" || true
  [[ -s "$PARAMS" ]] || : > "$PARAMS"
  log "Params URLs: $(wc -l < "$PARAMS" 2>/dev/null || echo 0)"
else
  log "Skip params (exists): $PARAMS"
fi

# JS hints: param keys from katana URLs (optional artifact)
JS_PARAMS_HINT="$OUT/js/params_from_js.txt"
if [[ ! -s "$JS_PARAMS_HINT" ]]; then
  grep -Eo '[\?&][a-zA-Z0-9_]{1,30}=' "$KATANA_URLS" 2>/dev/null \
    | sed -E 's/^[\?&]//' | sed -E 's/=$//' | sort -u > "$JS_PARAMS_HINT" || true
  [[ -s "$JS_PARAMS_HINT" ]] || : > "$JS_PARAMS_HINT"
fi

# API candidates heuristic (expanded)
if [[ ! -s "$API" ]]; then
  log "API candidates: grep common patterns from urls.txt"
  grep -Ei '/api/|/ajax|/graphql|/swagger|openapi|/v[0-9]+/|/rest/|/wp-json/|/v3/api-docs|/swagger-ui|/checkout|/cart/|/auth|/login|/order|/payment' "$URLS_TXT" 2>/dev/null \
    | sort -u > "$API" || true
  [[ -s "$API" ]] || : > "$API"
  log "API candidates: $(wc -l < "$API" 2>/dev/null || echo 0)"
else
  log "Skip API candidates (exists): $API"
fi

# Copy to attack_surface
cat "$PATHS" 2>/dev/null | sort -u > "$PATHS_TXT" || : > "$PATHS_TXT"
cat "$PARAMS" 2>/dev/null | sort -u > "$PARAMS_TXT" || : > "$PARAMS_TXT"
cat "$API"    2>/dev/null | sort -u > "$API_TXT"    || : > "$API_TXT"

# 04) Vulnerability Scan (Nuclei)
log "Vulnerability Scan (optional: NUCLEI=1)"

NUC_DIR="$OUT/vuln"
mkdir -p "$NUC_DIR"

NUC_OUT_TXT="$NUC_DIR/nuclei_findings.txt"
NUC_OUT_JSON="$NUC_DIR/nuclei_findings.jsonl"
NUC_SUMMARY="$NUC_DIR/nuclei_summary.txt"

# ensure files exist even when NUCLEI=0 (avoid summary crash)
: > "$NUC_OUT_TXT" || true
: > "$NUC_OUT_JSON" || true
: > "$NUC_SUMMARY" || true

NUC_RATE="${NUC_RATE:-50}"
NUC_CONC="${NUC_CONC:-25}"

# Default theo yêu cầu của bạn
NUC_SEV="${NUC_SEV:-critical,high,medium}"
NUC_TPL="${NUC_TPL:-nuclei-templates}"

NUC_TAGS="${NUC_TAGS:-}"
NUC_EXCLUDE_TAGS="${NUC_EXCLUDE_TAGS:-dos,fuzz}"

# detect correct exclude-tags flag (varies by nuclei versions)
NUC_EXCLUDE_FLAG="-etags"
if [[ $HAS_NUCLEI -eq 1 ]]; then
  if nuclei -h 2>&1 | grep -q -- '-exclude-tags'; then
    NUC_EXCLUDE_FLAG="-exclude-tags"
  fi
fi

if [[ "${NUCLEI:-0}" == "1" ]]; then
  if [[ $HAS_NUCLEI -eq 1 && -s "$LIVE" ]]; then
    log "Run nuclei: -t $NUC_TPL -severity $NUC_SEV (rate=$NUC_RATE conc=$NUC_CONC)"

    nuclei -update-templates >/dev/null 2>&1 || true

    : > "$NUC_OUT_TXT"
    : > "$NUC_OUT_JSON"

    NUC_ARGS=(
      -silent
      -l "$LIVE"
      -t "$NUC_TPL"
      -severity "$NUC_SEV"
      -rl "$NUC_RATE"
      -c "$NUC_CONC"
      -retries 1
      -timeout "$TIMEOUT"
      "$NUC_EXCLUDE_FLAG" "$NUC_EXCLUDE_TAGS"
      -jsonl -o "$NUC_OUT_JSON"
    )

    if [[ -n "$NUC_TAGS" ]]; then
      NUC_ARGS+=(-tags "$NUC_TAGS")
    fi

    nuclei "${NUC_ARGS[@]}" || true

    if [[ -s "$NUC_OUT_JSON" ]]; then
      if [[ $HAS_JQ -eq 1 ]]; then
        jq -r '"\(.severity)\t\(.templateID)\t\(.matched)"' "$NUC_OUT_JSON" 2>/dev/null \
          | sort -u > "$NUC_OUT_TXT" || true
      else
        cp "$NUC_OUT_JSON" "$NUC_OUT_TXT" || true
      fi
    fi

    {
      echo "Nuclei summary"
      echo "Target: $TARGET"
      echo "Input: $LIVE"
      echo "Templates: $NUC_TPL"
      echo "Severity: $NUC_SEV"
      echo "JSONL: $NUC_OUT_JSON"
      echo "TXT:  $NUC_OUT_TXT"
      echo
      if [[ -s "$NUC_OUT_JSON" && $HAS_JQ -eq 1 ]]; then
        echo "Counts by severity:"
        jq -r '.severity' "$NUC_OUT_JSON" 2>/dev/null | sort | uniq -c | sort -nr || true
      else
        echo "Counts: (jq not found or no findings)"
        echo "Lines(JSONL): $(wc -l < "$NUC_OUT_JSON" 2>/dev/null || echo 0)"
      fi
    } > "$NUC_SUMMARY" || true

    log "Nuclei done. Findings: $(wc -l < "$NUC_OUT_TXT" 2>/dev/null || echo 0)"
  else
    log "NUCLEI=1 but nuclei not found or LIVE empty -> skip nuclei scan"
  fi
else
  log "NUCLEI=0 -> skip nuclei scan"
fi

# Summary
SUMMARY="$OUT/attack_surface/summary.md"
log "Write summary: $SUMMARY"

GW_SS_COUNT="0"
if [[ -d "$GW_SS_DIR" ]]; then
  GW_SS_COUNT="$(find "$GW_SS_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')" || GW_SS_COUNT="0"
fi

{
  echo "# Recon -> Attack Surface Summary"
  echo
  echo "- Target: $TARGET"
  echo "- Output: $OUT"
  echo "- BRUTE:  ${BRUTE:-0} (dnsx required)"
  echo "- EXTEND: ${EXTEND:-0} (katana heavier crawl)"
  echo "- NUCLEI: ${NUCLEI:-0} (nuclei vuln scan)"
  echo "- GOWITNESS: ${GOWITNESS:-0} (screenshots)"
  echo
  echo "## Counts"
  echo "- Subdomains: $(wc -l < "$SUBS" 2>/dev/null || echo 0)"
  echo "- Resolved IPs: $(wc -l < "$RESOLVED_IPS" 2>/dev/null || echo 0)"
  echo "- Live URLs:  $(wc -l < "$LIVE" 2>/dev/null || echo 0)"
  echo "- Hosts:      $(wc -l < "$HOSTS_TXT" 2>/dev/null || echo 0)"
  echo "- IPs/CIDRs:  $(wc -l < "$IPS_TXT" 2>/dev/null || echo 0)"
  echo "- Ports:      $(wc -l < "$PORTS_TXT" 2>/dev/null || echo 0)"
  echo "- VHosts:     $(wc -l < "$VHOSTS_TXT" 2>/dev/null || echo 0)"
  echo "- URLs:       $(wc -l < "$URLS_TXT" 2>/dev/null || echo 0)"
  echo "- Paths:      $(wc -l < "$PATHS_TXT" 2>/dev/null || echo 0)"
  echo "- Params:     $(wc -l < "$PARAMS_TXT" 2>/dev/null || echo 0)"
  echo "- API cand.:  $(wc -l < "$API_TXT" 2>/dev/null || echo 0)"
  echo "- Nuclei findings: $(wc -l < "$NUC_OUT_TXT" 2>/dev/null || echo 0)"
  echo "- Gowitness screenshots: ${GW_SS_COUNT}"
  echo
  echo "## Files"
  echo "- subdomains.txt:       DNS_Recon/subdomains.txt"
  echo "- resolved_map.txt:     DNS_Recon/resolved_map.txt"
  echo "- resolved_ips.txt:     DNS_Recon/resolved_ips.txt"
  echo "- live_httpx_full.txt:  DNS_Recon/live_httpx_full.txt"
  echo "- live_urls.txt:        DNS_Recon/live_urls.txt"
  echo "- hosts.txt:            attack_surface/hosts.txt"
  echo "- ips.txt:              attack_surface/ips.txt"
  echo "- ports.txt:            attack_surface/ports.txt"
  echo "- vhosts.txt:           attack_surface/vhosts.txt"
  echo "- urls.txt:             attack_surface/urls.txt"
  echo "- paths.txt:            attack_surface/paths.txt"
  echo "- params.txt:           attack_surface/params.txt"
  echo "- api.txt:              attack_surface/api.txt"
  echo "- tech_stack.txt:       tech/tech_stack.txt"
  echo "- reverse_ptr.txt:      DNS_Recon/reverse_ptr.txt"
  echo "- asn.txt:              DNS_Recon/asn.txt"
  echo "- asn_ips.txt:          DNS_Recon/asn_ips.txt"
  echo "- js_params_hint:       js/params_from_js.txt"
  echo "- nuclei_findings.txt:  vuln/nuclei_findings.txt"
  echo "- nuclei_findings.jsonl:vuln/nuclei_findings.jsonl"
  echo "- nuclei_summary.txt:   vuln/nuclei_summary.txt"
  echo "- gowitness screenshots: attack_surface/screenshots_gowitness/screenshots/"
  echo "- gowitness db:          attack_surface/screenshots_gowitness/gowitness.sqlite3"
  echo "- gowitness jsonl:       attack_surface/screenshots_gowitness/gowitness.jsonl"
} > "$SUMMARY"

log "DONE Attack surface is ready at: $OUT/attack_surface"
