FROM kalilinux/kali-rolling

RUN apt update && apt install -y \
    iptables \
    wireshark \
    tcpdump \
    tshark \
    nmap \
    curl \
    wget \
    net-tools \
    iproute2 \
    iputils-ping \
    iftop \
    nload \
    iptraf-ng \
    htop \
    python3 \
    python3-pip \
    python3-scapy \
    python3-nmap \
    python3-netifaces \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

CMD ["/bin/bash"]
