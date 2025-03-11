DOMAIN=""
LOG_FILE="Results.csv"
USE_PROXY=false
SCAN_MODE="active"
OUTPUT_FORMAT="csv"

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
while getopts "d:p:m:o:" opt; do
    case $opt in
        d) DOMAIN="$OPTARG" ;;
        p) USE_PROXY=true ;;
        m) SCAN_MODE="$OPTARG" ;;
        o) OUTPUT_FORMAT="$OPTARG" ;;
        *) printf "Invalid option\n" >&2; exit 1 ;;
    esac
done

[[ -z "$DOMAIN" ]] && { printf "Use: %s -d <domain> [-p] [-m active|passive] [-o csv|json]\n" "$0" >&2; exit 1; }

if [[ "$SCAN_MODE" != "active" && "$SCAN_MODE" != "passive" ]]; then
    printf "Wrong scan mode. Use 'active' or 'passive'.\n" >&2
    exit 1
fi

# LOG FILE FORMAT
if [[ "$OUTPUT_FORMAT" == "json" ]]; then
    LOG_FILE="Results.json"
    echo "[" > "$LOG_FILE" # Json open
else
    LOG_FILE="results.csv"
fi

printf "[*] Domain enumeration: %s\n" "$DOMAIN"

if ! assetfinder --subs-only "$DOMAIN" > subdomains.txt; then
    printf "\n Something went wrong with assetfinder ʕノ•ᴥ•ʔノ ︵ ┻━┻ \n" >&2
    exit 1
fi
# SORT DUPLICATES
sort -u subdomains.txt -o subdomains.txt

FIRST_ENTRY=true

if [[ "$SCAN_MODE" == "passive" ]]; then
    printf "[*] Passive mode, no nmap scan.\n"

    if [[ "$OUTPUT_FORMAT" == "csv" ]]; then
        printf "Host ; Stato\n" > "$LOG_FILE"
    fi

    while read -r sub; do
        [[ -z "$sub" ]] && continue

        if [[ "$OUTPUT_FORMAT" == "json" ]]; then
            [[ "$FIRST_ENTRY" == false ]] && echo "," >> "$LOG_FILE"
            echo "{\"host\": \"$sub\", \"status\": \"FOUND\"}" >> "$LOG_FILE"
            FIRST_ENTRY=false
        else
            printf "%-30s ; %s\n" "$sub" "FOUND" >> "$LOG_FILE"
        fi
    done < subdomains.txt
else
    printf "[*] Scanning...\n"

    if [[ "$OUTPUT_FORMAT" == "csv" ]]; then
        printf "Host ; IP ; State ; Ports\n" > "$LOG_FILE"
    fi

    while read -r sub; do
        [[ -z "$sub" ]] && continue
        printf "[*] Scanning %s...\n" "$sub"

        ip=$(getent hosts "$sub" | awk '{print $1}')
        if [[ -z "$ip" ]]; then
            if [[ "$OUTPUT_FORMAT" == "json" ]]; then
                [[ "$FIRST_ENTRY" == false ]] && echo "," >> "$LOG_FILE"
                echo "{\"host\": \"$sub\", \"ip\": null, \"state\": \"DOWN\", \"ports\": []}" >> "$LOG_FILE"
                FIRST_ENTRY=false
            else
                printf "%-30s ; %-15s ; %-5s ; %s\n" "$sub" "-" "DOWN" "No open ports" >> "$LOG_FILE"
            fi
            continue
        fi
          
        CMD=("nmap" "-sS" "-sV" "-T3" "-Pn" "-A" "--top-ports" "1000" "--min-parallelism" "20" "-oG" "-")
        $USE_PROXY && CMD=("proxychains" "${CMD[@]}")

        if ! RESULT=$("${CMD[@]}" "$sub" | awk -v ip="$ip" '
            /Host: / {host=$2;}
            /Ports:/ {
                ports="";
                split($0, arr, ",");
                for (i in arr) {
                    if (match(arr[i], /([0-9]+)\/open/)) {
                        port=substr(arr[i], RSTART, RLENGTH-5);
                        # Estrai il servizio e la versione
                        service="";
                        if (match(arr[i], /([0-9]+)\/open\/\S+\/(.+)/, matches)) {
                            service=matches[2];
                        }
                        ports = ports ? ports "," port ":" service : port ":" service;
                    }
                }
            }
            END {
                if (host) {
                    printf "%s;%s;UP;%s\n", host, ip, (ports ? ports : "No open ports")
                } else {
                    printf "%s;%s;DOWN;No open ports\n", host, ip
                }
            }
        '); then
            printf "Error scanning %s\n" "$sub" >&2
            continue
        fi

        if [[ -n "$RESULT" ]]; then
            IFS=';' read -r h ip state ports <<< "$RESULT"
            if [[ "$OUTPUT_FORMAT" == "json" ]]; then
                [[ "$FIRST_ENTRY" == false ]] && echo "," >> "$LOG_FILE"

                ports_json="["
                if [[ -n "$ports" && "$ports" != "No open ports" ]]; then
                    IFS=',' read -ra port_array <<< "$ports"
                    for i in "${!port_array[@]}"; do
                        port_service="${port_array[i]}";
                        IFS=':' read -r port service <<< "$port_service";
                        ports_json+="\n    {";
                        ports_json+="\n      \"port\":\"$port\",";
                        ports_json+="\n      \"service\":\"$service\"";
                        ports_json+="\n    }";
                        if [[ $i -lt $(( ${#port_array[@]} - 1 )) ]]; then
                            ports_json+=",";
                        fi
                    done
                    ports_json+="\n  "
                fi
                ports_json+="]"
                # Json indentation
                echo "{
  \"host\": \"$h\",
  \"ip\": \"$ip\",
  \"state\": \"$state\",
  \"ports\": $ports_json
}" >> "$LOG_FILE"
                FIRST_ENTRY=false
            else
                printf "%-30s ; %-15s ; %-5s ; %s\n" "$h" "$ip" "$state" "$ports" >> "$LOG_FILE"
            fi
        fi
    done < subdomains.txt
fi

# close json
if [[ "$OUTPUT_FORMAT" == "json" ]]; then
    echo "]" >> "$LOG_FILE"
fi

# FORMAT OUTPUT
if [[ "$OUTPUT_FORMAT" == "csv" ]]; then
    column -t -s ";" "$LOG_FILE" > tmpfile && mv tmpfile "$LOG_FILE"
fi

printf "Scan completed, results in %s\n" "$LOG_FILE"
