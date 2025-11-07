#!/usr/bin/env bash
# check-c2-linux.sh
# Scan files/dirs for potential C2 indicators 
# Usage: ./check-c2-linux.sh /path/to/file_or_directory

set -euo pipefail

TARGET=${1:-}
if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <file-or-directory>"
  exit 2
fi

# Regex fragments
IP_RE='([0-9]{1,3}\.){3}[0-9]{1,3}'
URL_RE='https?://[^[:space:]\"'\''<>]+'   # HTTP/HTTPS URLs
DOMAIN_RE='[A-Za-z0-9._-]+\.[A-Za-z]{2,}' # simple domain heuristics
CMD_RE='(curl|wget|nc|ncat|telnet|bash -i|/dev/tcp|socat|powershell|Invoke-WebRequest)'

# find files (text-ish) and scan
find "$TARGET" -type f -readable 2>/dev/null | while IFS= read -r file; do
  # skip binary files (quick heuristic)
  if head -c 8000 "$file" | grep -qP '\x00'; then
    continue
  fi

  # extract raw matche
  ips=$(grep -Eo "$IP_RE" "$file" | sort -u || true)
  urls=$(grep -Eo "$URL_RE" "$file" | sort -u || true)
  domains=$(grep -Eo "$DOMAIN_RE" "$file" | sort -u || true)
  cmds=$(grep -Eio "$CMD_RE" "$file" | sort -u || true)

  # vvalidate ips  and classify private/public
  valid_ips=""
  if [[ -n "$ips" ]]; then
    while IFS= read -r ip; do
      IFS='.' read -r a b c d <<<"$ip"
      if ((a<=255 && b<=255 && c<=255 && d<=255)); then
        # classify
        if (( a==10 )) || ( ((a==172)) && (b>=16 && b<=31) ) || ( ((a==192)) && (b==168) ) || ( ((a==127)) ) || ( ((a==169)) && (b==254) ); then
          echo "PRIVATE IP in $file : $ip"
        else
          echo "PUBLIC  IP in $file : $ip"
        fi
      fi
    done <<<"$ips"
  fi

  if [[ -n "$urls" ]]; then
    while IFS= read -r u; do echo "URL found in $file : $u"; done <<<"$urls"
  fi

  if [[ -n "$domains" ]]; then
    while IFS= read -r d; do echo "Domain found in $file : $d"; done <<<"$domains"
  fi

  if [[ -n "$cmds" ]]; then
    while IFS= read -r c; do echo "Network/c2-like command in $file : $c"; done <<<"$cmds"
  fi
done

