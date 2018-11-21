FROM fedora
MAINTAINER Eric Warnke

RUN dnf -y install unbound python-unbound bind-utils && \
    ln -s /usr/lib64/python2.7/site-packages/unboundmodule.py /etc/unbound/unboundmodule.py && \
    dnf clean all

ADD ftp://ftp.internic.net/domain/named.cache /etc/unbound/root.hints
ADD unbound.conf /etc/unbound/unbound.conf
ADD dns_filter.py /etc/unbound/dns_filter.py
ADD filter.d /etc/unbound/filter.d
ADD conf.d /etc/unbound/conf.d

ADD https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts filter.d/StevenBlack.hosts

EXPOSE 53:53
EXPOSE 53:53/udp

HEALTHCHECK CMD dig @127.0.0.1 www.google.com

CMD ["/usr/sbin/unbound","-d","-v"]

