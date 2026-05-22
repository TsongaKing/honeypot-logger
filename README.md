# Honeypot Logger

![CI - Honeypot Logger](https://github.com/TsongaKing/honeypot-logger/actions/workflows/ci.yml/badge.svg)

A multi-protocol honeypot for detecting and logging unauthorized connection attempts and attack patterns. Features real-time Discord alerts, full payload logging, and Docker deployment.

## Features

- Multi-protocol support: FTP, SSH, HTTP, MySQL, SMB
- Real-time attack detection: SQL injection, path traversal, shell injection, brute force, scanners
- Discord webhook alerts for instant notifications
- Full payload logging with JSON structured output
- Rich console dashboard with live color-coded alerts
- Dockerized for easy, isolated deployment
- GitHub Actions CI with automated tests

## Quick Start

### Option 1 - Docker (Recommended)

git clone https://github.com/TsongaKing/honeypot-logger.git
cd honeypot-logger
docker-compose up -d

Honeypot will listen on:
- Port 8021 (FTP)
- Port 8022 (SSH)
- Port 9080 (HTTP)
- Port 8306 (MySQL)
- Port 8081 (HTTP-ALT)

### Option 2 - Run Locally

pip install -r requirements.txt
python main.py --ports 8021,8022,9080,8306

## Discord Alerts

To receive real-time alerts when attacks are detected:

1. Create a Discord webhook in your server
2. Set the environment variable:

export DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your-webhook-url

Or add it to docker-compose.yml under environment.

## Attack Detection

| Attack Type | Examples Detected |
|-------------|------------------|
| SQL Injection | SELECT FROM, UNION SELECT, DROP TABLE |
| Path Traversal | ../, /etc/passwd, /etc/shadow |
| Shell Injection | ; curl, ; wget, pipe to bash |
| Brute Force | admin, root, password, 123456 |
| Scanner Detection | nmap, nikto, sqlmap user agents |

## Log Format

Logs saved to logs/connections_YYYY-MM-DD.json:

{
  "timestamp": "2026-05-22T20:44:48",
  "host": "192.168.1.100",
  "port": 80,
  "protocol": "HTTP",
  "data_full": "GET / HTTP/1.1...",
  "attacks_detected": ["sql_injection"],
  "severity": "Critical"
}

## Project Structure

- main.py              - CLI entry point and port listener
- src/honeypot.py      - Core protocol handler and attack detection
- src/console.py       - Rich live dashboard
- Dockerfile           - Container build definition
- docker-compose.yml   - Multi-port orchestration
- logs/                - JSON connection logs (volume mounted)

## Tech Stack

Python 3.11, asyncio, rich, requests, Docker, GitHub Actions

## Legal

For authorized defensive security monitoring only.
Only deploy on systems you own or have permission to monitor.
Built by @TsongaKing
