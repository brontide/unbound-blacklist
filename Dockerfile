FROM fedora
MAINTAINER Eric Warnke

RUN dnf -y install unbound python-unbound bind-utils wget vim && \
    wget -O /etc/unbound/root.hints  ftp://ftp.internic.net/domain/named.cache && \
    ln -s /usr/lib64/python2.7/site-packages/unboundmodule.py /etc/unbound/unboundmodule.py
ADD unbound.conf /etc/unbound/unbound.conf
ADD dns_filter.py /etc/unbound/dns_filter.py
ADD filter.d /etc/unbound/filter.d

EXPOSE 53:53
EXPOSE 53:53/udp

HEALTHCHECK CMD dig @127.0.0.1 www.google.com

CMD ["/usr/sbin/unbound","-d","-v"]

