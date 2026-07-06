# Vulnerable Lab Target (`aiaudit-target`)

A deliberately-vulnerable multi-service container used as the TARGET for the AI auditor.
**Every flaw here is intentional. Never expose this container to an untrusted network.**

## Services & intentional vulnerabilities

| Port | Service | Intentional flaw | Detected by |
|------|---------|------------------|-------------|
| 22 | OpenSSH | user `admin` / password `password` (top of rockyou.txt) | `hydra` (`-l admin -P rockyou.txt`), `nmap` fingerprint |
| 21 | vsftpd | anonymous login enabled + `admin`/`password` local login; fake old banner `vsFTPd 2.3.4` | `hydra` (ftp), `nmap` |
| 80 | Flask web | SQL injection in `GET /product?id=1`; SQLi in `POST /login` form; verbose SQL errors; fake `Server: Apache/2.2.8` header; `/robots.txt` leaks `/admin` | `sqlmap` (`--forms --crawl`), `nmap`, `nikto` |

## Credentials (intentional weak)
- SSH / FTP: `admin` / `password`
- FTP anonymous: allowed
- Web app DB users table: `admin` / `S3cr3tAdminP@ss`, `john` / `john123` (exfiltrable via SQLi)

## How to run
```bash
docker compose up -d --build aiaudit-target
```
It joins `aiaudit-network`, so the `aiaudit-tools` container reaches it by DNS name `aiaudit-target`. Ports are also published to the host (8080->80, 2222->22, 2121->21) for manual testing.

## How to point the auditor at it
1. In the UI create a new audit with **host = `aiaudit-target`**.
2. nmap recon runs automatically. hydra will brute SSH/FTP.
3. For sqlmap, give the agent guidance with a full URL, e.g.:
   - `http://aiaudit-target/product?id=1`
   - or let `--forms --crawl` discover `http://aiaudit-target/login`
