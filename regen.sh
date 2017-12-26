#!/bin/sh

# Fetch list
wget -qO- https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | \
grep "^0\.0\.0\.0" hosts | awk '{print "local-zone:", $2 , " refuse"}' > ads.conf

