#!/bin/bash
source /etc/profile.d/rvm.sh

TARGET=""
PORTS="all"
SCAN_ID=""
KAFKA="kafka.service:9092"
ENRICH="{}"

echo "[DEBUG] KAFKA=$KAFKA"
echo "[DEBUG] ENRICH=$ENRICH"


function usage() {
  echo "$0 [-t <target> -p <ports> -s <scan id> -e <enrichment> -k <kafka address>][-h(help) -d(debug)]"
}

IFS=$'\n\t'

while getopts "t:p:s:e:k:hd" name; do
  case $name in
    t) TARGET=$OPTARG ;;
    p) PORTS=$OPTARG ;;
    s) SCAN_ID=$OPTARG ;;
    e) ENRICH=$OPTARG ;;
    k) KAFKA=$OPTARG ;;
    h) usage ;;
    d) DEBUG="-d" ;;
  esac
done

if [ -z "$KAFKA" ]; then
  KAFKA="kafka.service:9092"
fi

if [ "x$TARGET" == "x" ]; then
    usage
    exit
fi

if [ "x$PORTS" == "x" ]; then
    PORTS="all"
fi

if [ "x$SCAN_ID" == "x" ]; then
    usage
    exit
fi

SCRIPT_RUBY_PATH="/opt/rb/bin/rb_host_discovery.rb"

# If we are in redborder-ng ..
if [[ -f "/usr/lib/redborder/scripts/rb_host_discovery.rb" ]]; then
  SCRIPT_RUBY_PATH="/usr/lib/redborder/scripts/rb_host_discovery.rb"
fi


ruby $SCRIPT_RUBY_PATH -t "$TARGET" -p "$PORTS" -s "$SCAN_ID" -e "$ENRICH" -k "$KAFKA" $DEBUG
