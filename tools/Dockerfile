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
    whatweb \
    gobuster \
    masscan \
    sslscan \
    dnsrecon \
    smbclient \
    samba-common-bin \
    perl \
    dirb \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/share/wordlists \
    && wget -q https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O /usr/share/wordlists/rockyou.txt \
    && wget -q https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt -O /usr/share/wordlists/common.txt

RUN wget -q https://raw.githubusercontent.com/CiscoCXSecurity/enum4linux/master/enum4linux.pl -O /usr/local/bin/enum4linux \
    && chmod +x /usr/local/bin/enum4linux

RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.5/nuclei_3.3.5_linux_amd64.zip -O /tmp/nuclei.zip \
    && apt-get update && apt-get install -y --no-install-recommends unzip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && rm /tmp/nuclei.zip \
    && rm -rf /var/lib/apt/lists/* \
    && nuclei -update-templates || true

CMD ["tail", "-f", "/dev/null"]
