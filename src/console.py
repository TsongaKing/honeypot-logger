from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import datetime


console = Console()


class HoneypotConsole:

    def __init__(self):
        self.connections = []
        self.console = Console()

    def print_banner(self):
        self.console.print(Panel.fit(
            '[bold blue]Honeypot Logger[/bold blue]\n'
            '[dim]Defensive Security Monitoring Tool[/dim]\n'
            '[dim]All activity logged for security research[/dim]',
            border_style='blue'
        ))

    def print_connection(self, entry: dict):
        host = entry.get('host', 'unknown')
        port = entry.get('port', 0)
        attacks = entry.get('attacks_detected', [])
        severity = entry.get('severity', 'Info')
        timestamp = entry.get('timestamp', '')[:19]

        if attacks:
            color = 'red' if severity == 'Critical' else 'yellow'
            attack_str = ', '.join(attacks)
            self.console.print(
                f'[{color}][ALERT][/{color}] {timestamp} | '
                f'[bold]{host}[/bold] -> Port {port} | '
                f'Attacks: [red]{attack_str}[/red]'
            )
        else:
            self.console.print(
                f'[green][CONN][/green] {timestamp} | '
                f'[bold]{host}[/bold] -> Port {port}'
            )

        self.connections.append(entry)

    def print_summary(self):
        total = len(self.connections)
        attacks = [c for c in self.connections if c.get('attacks_detected')]

        table = Table(title='Session Summary')
        table.add_column('Metric', style='cyan')
        table.add_column('Value', style='white')

        table.add_row('Total Connections', str(total))
        table.add_row('Attack Attempts', str(len(attacks)))
        table.add_row('Clean Connections', str(total - len(attacks)))
        table.add_row('Session End', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

        self.console.print(table)
