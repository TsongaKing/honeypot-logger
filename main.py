import asyncio
import click
import signal
from src.honeypot import HoneypotProtocol
from src.console import HoneypotConsole


SERVICES = {
    8021: ('FTP', b'220 FTP Server Ready\r\n'),
    8022: ('SSH', b'SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n'),
    8180: ('HTTP', b'HTTP/1.1 200 OK\r\nServer: Apache/2.4\r\n\r\n<html><body>Welcome</body></html>'),
    8306: ('MySQL', b'\x4a\x00\x00\x00\x0a\x38\x2e\x30\x00'),
    21: ('FTP', b'220 FTP Server Ready\r\n'),
    22: ('SSH', b'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n'),
    80: ('HTTP', b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n<html><body>Welcome</body></html>'),
    3306: ('MySQL', b'\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x32\x36\x00'),
    445: ('SMB', b'\x00\x00\x00\x00'),
    8080: ('HTTP-ALT', b'HTTP/1.1 200 OK\r\nServer: Tomcat/9.0\r\n\r\n'),
}


async def start_honeypot(ports, console):
    loop = asyncio.get_event_loop()
    servers = []

    for port in ports:
        if port not in SERVICES:
            continue
        service, banner = SERVICES[port]
        try:
            server = await loop.create_server(
                lambda p=port, s=service, b=banner: HoneypotProtocol(p, s, b, console),
                '0.0.0.0', port
            )
            servers.append(server)
            console.console.print(f'[green]Listening on port {port} ({service})[/green]')
        except PermissionError:
            console.console.print(f'[red]Permission denied on port {port} - try running with sudo[/red]')
        except OSError as e:
            console.console.print(f'[yellow]Could not bind port {port}: {e}[/yellow]')

    return servers


@click.command()
@click.option('--ports', default='21,22,80,3306,8080', help='Comma-separated ports to listen on')
@click.option('--duration', default=0, help='Duration in seconds (0 = run forever)')
def main(ports, duration):
    port_list = [int(p.strip()) for p in ports.split(',')]

    console = HoneypotConsole()
    console.print_banner()
    console.console.print(f'[dim]Monitoring ports: {port_list}[/dim]')
    console.console.print('[dim]Press Ctrl+C to stop[/dim]\n')

    async def run():
        servers = await start_honeypot(port_list, console)

        if not servers:
            console.console.print('[red]No ports could be bound. Exiting.[/red]')
            return

        try:
            if duration > 0:
                await asyncio.sleep(duration)
            else:
                await asyncio.Future()
        except asyncio.CancelledError:
            pass
        finally:
            for server in servers:
                server.close()
            console.print_summary()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        console.print_summary()


if __name__ == '__main__':
    main()
