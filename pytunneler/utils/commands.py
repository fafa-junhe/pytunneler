from __future__ import annotations

from websockets import WebSocketServerProtocol

from pytunneler.server.server import WebsocketServer
from tabulate import tabulate
import traceback
from pytunneler.utils import network


class CommandContext:
    def __init__(self, args, websocket: WebSocketServerProtocol, server: WebsocketServer):
        self.args = args
        self.server = server
        self.websocket = websocket

class Command:
    def __init__(self):
        self.name = "Reversed Command"
        self.description = "This is a Reversed Command"
        self.trigger = "reversed"

    @staticmethod
    def on_command(context: CommandContext):
        return "Hello World"

class LsCommandCommand(Command):
    def __init__(self):
        super().__init__()
        self.name = "List of Commands"
        self.description = "List of Commands"
        self.trigger = "lsc"

    @staticmethod
    def on_command(context: CommandContext):
        result = []
        for command in CommandTypes:
            result.append(
                [command.name, command.description, command.trigger]
            )
        return tabulate(result, headers=["name", "description", "trigger"])

class LsPortCommand(Command):
    def __init__(self):
        super().__init__()
        self.name = "List of Ports"
        self.description = "List of Ports"
        self.trigger = "lsp"

    @staticmethod
    def on_command(context: CommandContext):
        ports = network.scan_port()

        result = []
        start = ports[0]
        end = ports[0]

        for i in range(1, len(ports)): # Compress ports to ranges and numbers
            if ports[i] == end + 1:
                end = ports[i]
            else:
                if start == end:
                    result.append(f"{start}")
                else:
                    result.append(f"{start}-{end}")
                start = ports[i]
                end = ports[i]

        if start == end:
            result.append(f"{start}")
        else:
            result.append(f"{start}-{end}")

        return f"Available Ports: {" ".join(result)}"

class TcpTunnelCommand(Command):
    def __init__(self):
        super().__init__()
        self.name = "TcpTunneling"
        self.description = "make a tcp socket tunnel to server"
        self.trigger = "tcptunnel"

    @staticmethod
    def usage():
        return "Usage: tcptunnel [localhost]:<port> :[target_port]"

    @staticmethod
    def on_command(context: CommandContext):
        if len(context.args) != 2:
            return TcpTunnelCommand.usage()
        try:
            local_ip, local_port = context.args[0].split(":")
            target_ip, target_port = context.args[1].split(":")
            if not local_ip: local_ip = "127.0.0.1"
            if not target_ip: target_ip = "0.0.0.0"
            context.server.start_tcp_server(context.websocket, local_ip, local_port, target_ip, target_port)
            return f"tunneling {local_ip}:{local_port} to {target_ip}:{target_port}"
        except Exception:
            return traceback.format_exc()

CommandTypes : list[type[Command]] = [
    LsCommandCommand(), LsPortCommand(), TcpTunnelCommand()
]

