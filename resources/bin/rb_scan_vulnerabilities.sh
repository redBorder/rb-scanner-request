#!/bin/bash

source /etc/profile.d/rvm.sh

TARGET=""
PORTS="all"
SCAN_ID=""

function usage() {
  echo "$0 [-t <target> -p <ports> -s <scan id> -e <enrichment>][-h]"
}

IFS=$'\n\t'

while getopts "t:p:s:e:h" name; do
  case $name in
    t) TARGET=$OPTARG ;;
    p) PORTS=$OPTARG ;;
    s) SCAN_ID=$OPTARG ;;
    e) ENRICH=$OPTARG ;;
    h) usage ;;
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

if [ "x$PORTS" == "x" ]; then
    ENRICH="{}"
fi


SCRIPT_RUBY_PATH="/opt/rb/bin/rb_scan_vulnerabilities.rb"

# If we are in redborder-ng ..
if [[ -f "/usr/lib/redborder/scripts/rb_scan_vulnerabilities.rb" ]]; then
  SCRIPT_RUBY_PATH="/usr/lib/redborder/scripts/rb_scan_vulnerabilities.rb"
fi

ruby $SCRIPT_RUBY_PATH $TARGET $PORTS $SCAN_ID $ENRICH
