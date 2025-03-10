#!/bin/bash

# csv

DOMAIN=""
LOG_FILE="Results.csv"
USE_PROXY=false
SCAN_MODE="active"

# CHECK FOR DEPENDENCIES
for cmd in assetfinder nmap awk getent column; do
if [[ "$SCAN_MODE" == "passive" && "$cmd" == "nmap" ]]; then
continue
fi
if ! command -v "$cmd" &>/dev/null; then
printf "Error: %s not found.\n" "$cmd" >&2
exit 1
fi
done

# CHECK ARGS
 
while getopts "d:p:m:" opt; do
[[ $opt == "d" ]] && DOMAIN="$OPTARG"
[[ $opt == "p" ]] && USE_PROXY=true
[[ $opt == "m" ]] && SCAN_MODE="$OPTARG"
done

[[ -z "$DOMAIN" ]] && { printf "Use: %s -d <domain> [-p] [-m active|passive]\n" "$0" >&2; exit 1; }

if [[ "$SCAN_MODE" != "active" && "$SCAN_MODE" != "passive" ]]; then
printf "Wrong scan mode. Use 'active' or 'passive'.\n" >&2
exit 1
fi

# SUBDOMAIN ENUMERATION

printf "[*] Domain enumeration: %s\n" "$DOMAIN"


if ! assetfinder --subs-only "$DOMAIN" > subdomains.txt; then
    printf "\n Something went wrong with assetfinder  ʕノ•ᴥ•ʔノ ︵ ┻━┻ \n" >&2
    exit 1
fi


# REMOVE DUPLICATE SUBDOMAINS

sort -u subdomains.txt -o subdomains.txt

# PASSIVE MODE, NO NMAP

if [[ "$SCAN_MODE" == "passive" ]]; then
printf "[*] Passive mode, no nmap scan.\n"
printf "Host ; Stato\n" > "$LOG_FILE"
while read -r sub; do
[[ -z "$sub" ]] && continue
printf "%-30s ; %s\n" "$sub" "FOUND" >> "$LOG_FILE"
done < subdomains.txt
column -t -s ";" "$LOG_FILE" > tmpfile && mv tmpfile "$LOG_FILE"
printf "[*] Enumeration completed, results in %s\n" "$LOG_FILE"
exit 0
fi

# ACTIVE MODE
 
printf "[*] Scan start...\n" > "$LOG_FILE"
printf "Host ; IP ; State ; Ports\n" >> "$LOG_FILE"

while read -r sub; do
[[ -z "$sub" ]] && continue
printf "[*] Scanning %s...\n" "$sub"

# TRIES TO RESOLVE SUBDOMAINS IN IPs
ip=$(getent hosts "$sub" | awk '{print $1}')
if [[ -z "$ip" ]]; then
printf "%-30s ; %-15s ; %-5s ; %s\n" "$sub" "-" "DOWN" "No open ports" >> "$LOG_FILE"
continue
fi

# OPTIMIZED NMAP COMMAND
CMD=("nmap" "-sS" "-T3" "-Pn" "-A" "--top-ports" "1000" "--min-parallelism" "20" "-oG" "-")
$USE_PROXY && CMD=("proxychains" "${CMD[@]}")

if ! RESULT=$("${CMD[@]}" "$sub" | awk -v ip="$ip" '
/Host: / {host=$2;}
/Ports:/ {
ports="";
split($0, arr, ",");
for (i in arr) {
if (match(arr[i], /([0-9]+)\/open/)) {
ports = ports ? ports "," substr(arr[i], RSTART, RLENGTH-5) : substr(arr[i], RSTART, RLENGTH-5);
}
}
}
END {
if (host) {
printf "%-30s ; %-15s ; %-5s ; %s\n", host, ip, "UP", (ports ? ports : "No open ports")
} else {
printf "%-30s ; %-15s ; %-5s ; %s\n", host, ip, "DOWN", "No open ports"
}
}
'); then
printf "Error scanning %s\n" "$sub" >&2
continue
fi



[[ -n "$RESULT" ]] && printf "%s\n" "$RESULT" >> "$LOG_FILE"
 
done < subdomains.txt

# FORMAT CSV OUTPUT
column -t -s ";" "$LOG_FILE" > tmpfile && mv tmpfile "$LOG_FILE"

printf "Scan completed, results in %s\n" "$LOG_FILE"
