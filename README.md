# Blacklist enforcing, recursive DNS resolver

This project pairs unbound with a small python plugin that will block DNS resolution
for hosts in a traditional hostfile blacklist.

```
# Download StevenBlack hostlist
make download
# Build docker image
make build
# Bring up -d image
make up
```

The docker has a healthcheck so it should be immediatly visible if there are any issues

### Notes

This is based on fedora because it was one of the few that properly supported the python
modules without giving me too mcuh grief

This project would not be possible without 
[https://github.com/cbuijs/unbound-dns-firewall]
