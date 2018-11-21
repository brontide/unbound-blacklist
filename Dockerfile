FROM fedora
MAINTAINER Eric Warnke

RUN dnf -y install unbound python-unbound bind-utils && \
    ln -s /usr/lib64/python2.7/site-packages/unboundmodule.py /etc/unbound/unboundmodule.py && \
    dnf clean all && mkdir /etc/unbound/filter.d

ADD http://www.internic.net/domain/named.root /etc/unbound/root.hints
ADD unbound.conf /etc/unbound/unbound.conf
ADD dns_filter.py /etc/unbound/dns_filter.py
ADD conf.d /etc/unbound/conf.d

ADD https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts /etc/unbound/filter.d/StevenBlack.hosts

EXPOSE 53:53
EXPOSE 53:53/udp

HEALTHCHECK CMD dig @127.0.0.1 www.google.com

CMD ["/usr/sbin/unbound","-d","-v"]

