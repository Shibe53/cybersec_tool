FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    bind9 \
    bind9utils \
    dnsutils \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/cache/bind /var/lib/bind /var/log/bind && \
    chown -R bind:bind /var/cache/bind /var/lib/bind /var/log/bind

COPY named.conf.options /etc/bind/named.conf.options
COPY named.conf.local /etc/bind/named.conf.local
COPY db.website.ocs /etc/bind/db.website.ocs

EXPOSE 53/udp 53/tcp

# Start BIND9 in foreground mode
CMD ["/usr/sbin/named", "-g", "-c", "/etc/bind/named.conf", "-u", "bind"]

