# Honeypot Logger

![CI - Honeypot Logger](https://github.com/TsongaKing/honeypot-logger/actions/workflows/ci.yml/badge.svg)

A multi-protocol honeypot for detecting and logging unauthorized connection attempts and attack patterns.

## Features

- Multi-protocol support: FTP, SSH, HTTP, MySQL, SMB
- Real-time attack detection: SQL injection, path traversal, shell injection, brute force, scanners
- JSON structured logging with timestamps and severity ratings
- Rich console dashboard with live alerts
- Fully isolated - safe to run on your own machine

## Quick Start

pip install -r requirements.txt
python main.py --ports 8021,8022,8180,8306

## Options

--ports   Comma-separated ports to monitor (default: 21,22,80,3306,8080)
--duration  Run duration in seconds (0 = run forever)

## Attack Detection

The honeypot detects the following attack patterns:

| Attack Type | Examples |
|-------------|---------|
| SQL Injection | SELECT FROM, UNION SELECT, DROP TABLE |
| Path Traversal | ../, /etc/passwd, /etc/shadow |
| Shell Injection | curl, wget, bash pipes |
| Brute Force | Common credentials like admin, root |
| Scanner Detection | nmap, nikto, sqlmap user agents |

## Log Format

Logs are saved to logs/connections_YYYY-MM-DD.json:

{
  "timestamp": "2026-05-21T09:10:27",
  "host": "192.168.1.100",
  "port": 8180,
  "protocol": "HTTP",
  "data_preview": "GET / HTTP/1.1...",
  "attacks_detected": ["sql_injection"],
  "severity": "Critical"
}

## Project Structure

- main.py - CLI entry point and port listener
- src/honeypot.py - Core honeypot protocol and attack detection
- src/console.py - Rich console dashboard
- logs/ - JSON connection logs

## Legal

For authorized defensive security monitoring only.
Only deploy on systems you own or have permission to monitor.
Built by @TsongaKing
