FROM alpine
MAINTAINER Eric Warnke

RUN apk update && \
    apk add unbound && \
    wget -O /etc/unbound/root.hints  ftp://ftp.internic.net/domain/named.cache && \
    rm -f /var/cache/apk/*
ADD unbound.conf /etc/unbound/unbound.conf
ADD ads.conf /etc/unbound/ads.conf

EXPOSE 53:53
EXPOSE 53:53/udp

#HEALTHCHECK CMD nslookup www.milosmeadow.com 127.0.0.1

CMD ["/usr/sbin/unbound","-d","-v"]

