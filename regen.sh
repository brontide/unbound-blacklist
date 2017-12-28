#!/bin/sh

# Fetch list
wget -qO- https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | \
grep "^0\.0\.0\.0" | awk '{print $2}' | grep -v 0.0.0.0 | xargs -n1 -I{}  echo local-zone: {} refuse > ads.conf

