#!/usr/bin/env python

import asyncio
import logging
from queue import Queue
import threading
import aioconsole
from websockets import WebSocketClientProtocol
from websockets.client import connect
import socket
import argparse

from pytunneler.utils import commands, network, packet, host_hex


parser = argparse.ArgumentParser(description='pytunneler Websocket client')

parser.add_argument('address', type=str, nargs='?',
                    help='websocket server address', default='127.0.0.1:8321')

# Optional argument
parser.add_argument('--password', type=str,
                    help='password')


class WebsocketClient:
    def __init__(self, ip, port, password) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.tcp_clients: dict[str, TCPClient] = dict()
        self.local_remote: dict[str, str] = dict()
        self.ip = ip
        self.port = port
        self.password = password


    async def handle_command_input(self, websocket: WebSocketClientProtocol):
        """Handle user command and send it to the websocket"""
        print("> ", end='', flush=True)
        try:
            while True:
                command = await aioconsole.ainput("")
                print(command)
                if not command.strip():
                    print("> ", end='', flush=True)
                    continue
                for command_type in commands.CommandTypes:
                    if command.split()[0] == command_type.trigger:  # 找到命令
                        command_packet = packet.CommandPacket(command)
                        network.websocket_send(self.loop, websocket, command_packet.create_packet())
                        break
                else:
                    print(f"Unknown command: {command.split()[0]}")
        except asyncio.CancelledError:
            return

    def start_tcp_client(self, websocket, target_ip, target_port, ip, port):
        thread = TCPClient(websocket, self, target_ip, int(target_port), ip, int(port))
        self.tcp_clients[f"{ip}:{port}"] = thread
        thread.start()


    def handle_packet(self, raw_packet, websocket):
        packet_ = packet.Packet.bytes2packet(raw_packet)
        if isinstance(packet_, packet.CommandCallbackPacket):
            print(packet_.message)
            print("> ", end='', flush=True)
        elif isinstance(packet_, packet.ConnectedPacket):
            ip, port = host_hex.hex2host(packet_.host).split(":")
            target_ip, target_port = host_hex.hex2host(packet_.target_host).split(":")
            self.start_tcp_client(websocket, target_ip, target_port, ip, port)

        elif isinstance(packet_, packet.BinaryPacket):
            ip, port = host_hex.hex2host(packet_.host).split(":")
            target_ip, target_port = host_hex.hex2host(packet_.target_host).split(":")
            client = self.tcp_clients[f"{ip}:{port}"]
            if not client.sock:
                print("error")
            network.tcp_send(client.sock, packet_.data)


    async def handle_websocket_recv(self, websocket: WebSocketClientProtocol):
        """Handle receiving packets from websocket"""
        while True:
            raw_packet = await network.websocket_recv(websocket)
            if not raw_packet:
                break
            self.handle_packet(raw_packet, websocket)



    def send_password(self, websocket):
        password_packet = packet.PasswordPacket(self.password)         # send password first
        network.websocket_send(self.loop, websocket, password_packet.create_packet())


    async def process(self, websocket: WebSocketClientProtocol):
        """Run both the input handler and websocket receiver concurrently"""

        self.send_password(websocket)

        recv_task = asyncio.create_task(self.handle_websocket_recv(websocket))
        input_task = asyncio.create_task(self.handle_command_input(websocket))

        _, pending = await asyncio.wait(
            [input_task, recv_task],
            return_when=asyncio.FIRST_COMPLETED  # Exit when the first task is done
        )

        # Cancel any remaining tasks
        for task in pending:
            task.cancel()

    async def main(self):
        async with connect(f"ws://{self.ip}:{self.port}") as websocket:
            logging.info(f"Websocket client connected to ws://{self.ip}:{self.port}")
            await self.process(websocket)

    def run(self):
        return self.loop.run_until_complete(self.main())


class TCPClient(threading.Thread):
    def __init__(self, websocket: WebSocketClientProtocol, client: WebsocketClient, target_ip, target_port, ip, port):
        self.packet_queue = Queue()
        self.target_ip = target_ip
        self.target_port = target_port
        self.target_hex =host_hex.host2hex(f"{target_ip}:{target_port}")
        self.hex = host_hex.host2hex(f"{ip}:{port}")
        self.client = client
        self.websocket = websocket
        self.sock = None
        super().__init__()

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            self.sock = sock
            sock.settimeout(5)
            sock.connect((self.target_ip, self.target_port))
            logging.info("Tcp client connected to " + str((self.target_ip, self.target_port)))
            while True:
                data = network.tcp_recv(sock)
                if not data:
                    logging.info("no data, shutdowning")
                    break
                binary_packet = packet.BinaryPacket(self.target_hex, self.hex, data)
                network.websocket_send(self.client.loop, self.websocket, binary_packet.create_packet())


if __name__ == "__main__":
    args = parser.parse_args()
    ip, port = args.address.split(":")
    password = ""
    if args.password:
        password = args.password
    client = WebsocketClient(ip, int(port), password)
    client.run()