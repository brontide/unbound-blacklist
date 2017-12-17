#!/bin/sh

# Fetch list
wget https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
# Convert to unbound format
grep "^0\.0\.0\.0" hosts | awk '{print "local-zone:", $2 , " refuse"}' > ads.conf

