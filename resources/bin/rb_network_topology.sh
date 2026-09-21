#!/bin/bash
set -e
if [[ -f /etc/profile.d/rvm.sh ]]; then
  source /etc/profile.d/rvm.sh
fi
exec ruby /usr/lib/redborder/scripts/rb_network_topology.rb "$@"
