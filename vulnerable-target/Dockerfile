FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Intentionally weak lab target: SSH + FTP + Flask web, all with deliberate flaws.
RUN apt-get update && apt-get install -y \
    openssh-server \
    vsftpd \
    python3 \
    python3-flask \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# --- Weak user for hydra/ssh/ftp: admin with a password that lives near the top of rockyou.txt ---
RUN useradd -m -s /bin/bash admin \
    && echo 'admin:password' | chpasswd

# --- SSH setup (password auth enabled, deliberately weak) ---
RUN mkdir -p /run/sshd \
    && ssh-keygen -A \
    && sed -i 's/#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# --- FTP setup (anonymous login + weak local login) ---
RUN mkdir -p /var/run/vsftpd/empty
COPY vsftpd.conf /etc/vsftpd.conf

# --- Web app ---
COPY app.py /app/app.py

# --- Supervisor runs all three services ---
COPY supervisord.conf /etc/supervisor/conf.d/lab.conf

EXPOSE 21 22 80
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
