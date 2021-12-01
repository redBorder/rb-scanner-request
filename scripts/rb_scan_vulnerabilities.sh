#!/bin/bash

source /etc/profile/

TARGET=""
PORTS="all"
SCAN_ID=""

function usage() {
  echo "$0 [-t <target> -p <ports> -s <scan id>][-h]"
}

while getopts "t:p:s:h" name; do
  case $name in
    t) TARGET=$OPTARG ;;
    p) PORTS=$OPTARG ;;
    s) SCAN_ID=$OPTARG ;;
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

ruby /usr/lib/redborder/scripts/rb_scan_vulnerabilities.rb $TARGET $PORTS $SCAN_ID
