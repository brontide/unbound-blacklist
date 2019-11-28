# Blacklist enforcing, recursive DNS resolver

This project pairs unbound with a small python plugin that will block DNS resolution
for hosts in a traditional hostfile blacklist.  Now supports blocking of CNAME replies
which match a blacklist item.


First, update the docker-compose.yml for your IP you want to listen on.

```yaml
version: "3.4"

services:
  unbound:
    build: .
    restart: always
    ports:
      - "192.168.111.20:53:1053"
      - "192.168.111.20:53:1053/udp"
      - "127.0.0.1:53:1053"
      - "127.0.0.1:53:1053/udp"
```

Edit or update the `Makefile` if you want additional hosts files.

Edit or update the `conf.d` files if you want to add additional unbound
configs.

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
