FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    hydra \
    sqlmap \
    nikto \
    curl \
    wget \
    ca-certificates \
    iputils-ping \
    dnsutils \
    net-tools \
    whois \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/share/wordlists \
    && wget -q https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O /usr/share/wordlists/rockyou.txt

CMD ["tail", "-f", "/dev/null"]
