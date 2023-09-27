#!/bin/bash

source /etc/profile.d/rvm.sh

TARGET=""
PORTS="all"
SCAN_ID=""
BATCH_RATE="0.1"
KAFKA="127.0.0.1:9092"
ENRICH="{}"

function usage() {
  echo "$0 [-t <target> -p <ports> -s <scan id> -e <enrichment> -br <batch rate> -k <kafka address>][-h(help) -d(debug)]"
}

IFS=$'\n\t'

while getopts "t:p:s:e:br:k:hd" name; do
  case $name in
    t) TARGET=$OPTARG ;;
    p) PORTS=$OPTARG ;;
    s) SCAN_ID=$OPTARG ;;
    e) ENRICH=$OPTARG ;;
    br) BATCH_RATE=$OPTARG ;;
    k) KAFKA=$OPTARG ;;
    h) usage ;;
    d) DEBUG="-d" ;;
  esac
done

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

SCRIPT_RUBY_PATH="/opt/rb/bin/rb_scan_vulnerabilities.rb"

# If we are in redborder-ng ..
if [[ -f "/usr/lib/redborder/scripts/rb_scan_vulnerabilities.rb" ]]; then
  SCRIPT_RUBY_PATH="/usr/lib/redborder/scripts/rb_scan_vulnerabilities.rb"
fi

ruby $SCRIPT_RUBY_PATH -t $TARGET -p $PORTS -s $SCAN_ID -e $ENRICH -b $BATCH_RATE -k $KAFKA $DEBUG
