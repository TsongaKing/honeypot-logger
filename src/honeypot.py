import asyncio
import json
import logging
import datetime
import re
import os
import requests
from pathlib import Path


Path('logs').mkdir(exist_ok=True)

logging.basicConfig(
    filename='logs/honeypot.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

ATTACK_PATTERNS = {
    'sql_injection': [
        r'SELECT.*FROM', r'UNION.*SELECT', r'DROP.*TABLE',
        r'INSERT.*INTO', r"OR '1'='1", r'--', r'xp_cmdshell'
    ],
    'path_traversal': [
        r'\.\./', r'\.\.\\', r'/etc/passwd', r'/etc/shadow',
        r'C:\\Windows', r'%2e%2e'
    ],
    'shell_injection': [
        r';\s*cat\s', r';\s*ls\s', r';\s*wget\s', r';\s*curl\s',
        r'\|\s*bash', r'\$\(.*\)'
    ],
    'brute_force': [
        r'admin', r'root', r'password', r'123456',
        r'administrator', r'test', r'guest'
    ],
    'scanner': [
        r'nmap', r'masscan', r'nikto', r'sqlmap',
        r'zgrab', r'shodan', r'censys'
    ]
}


def send_discord_alert(entry: dict):
    webhook_url = os.environ.get('DISCORD_WEBHOOK_URL', '')
    if not webhook_url:
        return
    attacks = entry.get('attacks_detected', [])
    severity = entry.get('severity', 'Info')
    color = 16711680 if severity == 'Critical' else 16744272
    payload = {
        'embeds': [{
            'title': f'Honeypot Alert - {severity}',
            'color': color,
            'fields': [
                {'name': 'Host', 'value': entry.get('host', 'unknown'), 'inline': True},
                {'name': 'Port', 'value': str(entry.get('port', 0)), 'inline': True},
                {'name': 'Protocol', 'value': entry.get('protocol', 'TCP'), 'inline': True},
                {'name': 'Attacks', 'value': ', '.join(attacks) if attacks else 'None', 'inline': False},
                {'name': 'Timestamp', 'value': entry.get('timestamp', ''), 'inline': False},
            ]
        }]
    }
    try:
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception:
        pass


def detect_attack(data: str) -> list:
    detected = []
    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, data, re.IGNORECASE):
                detected.append(attack_type)
                break
    return list(set(detected))


def log_connection(port: int, host: str, data: str = '', protocol: str = 'TCP'):
    attacks = detect_attack(data)
    severity = 'Critical' if attacks else 'Info'

    entry = {
        'timestamp': datetime.datetime.now().isoformat(),
        'host': host,
        'port': port,
        'protocol': protocol,
        'data_full': data,
        'attacks_detected': attacks,
        'severity': severity
    }

    log_file = f'logs/connections_{datetime.date.today()}.json'
    with open(log_file, 'a') as f:
        f.write(json.dumps(entry) + '\n')

    logging.info(f'Connection from {host}:{port} - attacks: {attacks}')

    if attacks:
        send_discord_alert(entry)

    return entry


class HoneypotProtocol(asyncio.Protocol):

    def __init__(self, port: int, service: str, banner: str, console=None):
        self.port = port
        self.service = service
        self.banner = banner
        self.console = console
        self.host = ''

    def connection_made(self, transport):
        self.transport = transport
        peername = transport.get_extra_info('peername')
        self.host = peername[0] if peername else 'unknown'
        transport.write(self.banner.encode())

    def data_received(self, data):
        try:
            decoded = data.decode('utf-8', errors='replace').strip()
        except Exception:
            decoded = str(data)

        entry = log_connection(self.port, self.host, decoded, self.service)

        if self.console:
            self.console.print_connection(entry)

        self.transport.write(b'Access denied.\r\n')
        self.transport.close()

    def connection_lost(self, exc):
        pass
