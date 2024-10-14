#!/usr/bin/env python

import asyncio
import logging
from queue import Queue
from picows import ws_connect, WSFrame, WSTransport, WSListener, WSMsgType, WSCloseCode, WSUpgradeRequest
import threading
import aioconsole
import socket
import argparse

from pytunneler.utils import commands, network, packet, host_hex


parser = argparse.ArgumentParser(description='pytunneler Websocket client')

parser.add_argument('address', type=str, nargs='?',
                    help='websocket server address', default='127.0.0.1:8321')

parser.add_argument('--password', type=str,
                    help='password')

parser.add_argument('--init_commands', type=str,
                    help='password')

class WebsocketClient:
    def __init__(self, ip, port, password, init_commands) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.tcp_clients: dict[str, TCPClient] = dict()
        self.local_remote: dict[str, str] = dict()
        self.init_commands = init_commands
        self.ip = ip
        self.port = port
        self.password = password

    def send_command(self, transport: WSTransport, command):
        print(command)
        if not command.strip():
            print("> ", end='', flush=True)
            return
        for command_type in commands.CommandTypes:
            if command.split()[0] == command_type.trigger:  # 找到命令
                command_packet = packet.CommandPacket(command)
                network.websocket_send(transport, command_packet.create_packet())
                break
        else:
            print(f"Unknown command: {command.split()[0]}")


    async def handle_command_input(self, transport: WSTransport):
        """Handle user command and send it to the websocket"""
        print("> ", end='', flush=True)
        while True:
            command = await aioconsole.ainput("")
            self.send_command(transport, command)

    def start_tcp_client(self, transport, target_ip, target_port, ip, port):
        thread = TCPClient(transport, self, target_ip, int(target_port), ip, int(port))
        self.tcp_clients[f"{ip}:{port}"] = thread
        thread.start()


    def handle_packet(self, raw_packet, transport):
        packet_ = packet.Packet.bytes2packet(raw_packet)
        if isinstance(packet_, packet.CommandCallbackPacket):
            print(packet_.message)
            print("> ", end='', flush=True)
        elif isinstance(packet_, packet.ConnectedPacket):
            ip, port = host_hex.hex2host(packet_.host).split(":")
            target_ip, target_port = host_hex.hex2host(packet_.target_host).split(":")
            self.start_tcp_client(transport, target_ip, target_port, ip, port)

        elif isinstance(packet_, packet.BinaryPacket):
            ip, port = host_hex.hex2host(packet_.host).split(":")
            target_ip, target_port = host_hex.hex2host(packet_.target_host).split(":")
            client = self.tcp_clients[f"{ip}:{port}"]
            if not client.sock:
                print("error")
            network.tcp_send(client.sock, packet_.data)



    def send_password(self, transport):
        password_packet = packet.PasswordPacket(self.password)         # send password first
        network.websocket_send(transport, password_packet.create_packet())

    def send_init_commands(self, transport):
        for command in init_commands:
            self.send_command(transport, command)

    class ClientListener(WSListener):
        def on_ws_connected(self, transport: WSTransport):
            self.transport = transport
            client.send_password(transport)
            client.send_init_commands(transport)
            self.input_thread = threading.Thread(target=asyncio.run_coroutine_threadsafe, args=(client.handle_command_input(transport), client.loop))
            self.input_thread.start()


        def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
            raw_packet = frame.get_payload_as_bytes()
            if not raw_packet:
                transport.send_close(WSCloseCode.BAD_GATEWAY)
                transport.disconnect()
                return
            client.handle_packet(raw_packet, transport)


        def on_ws_disconnected(self, transport):
            self.input_thread.join()



    async def main(self):
        logging.info(f"Websocket client connected to ws://{self.ip}:{self.port}")
        (_, client) = await ws_connect(self.ClientListener, f"ws://{self.ip}:{self.port}")
        client.client = self # todo: hacky way
        await client.transport.wait_disconnected()

    def run(self):
        return self.loop.run_until_complete(self.main())


class TCPClient(threading.Thread):
    def __init__(self, websocket: WSTransport, client: WebsocketClient, target_ip, target_port, ip, port):
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
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(5)
            sock.connect((self.target_ip, self.target_port))
            logging.info("Tcp client connected to " + str((self.target_ip, self.target_port)))
            while True:
                data = network.tcp_recv(sock)
                if not data:
                    logging.info("no data, shutdowning")
                    break
                binary_packet = packet.BinaryPacket(self.target_hex, self.hex, data)
                network.websocket_send(self.websocket, binary_packet.create_packet())
        exit(0)


if __name__ == "__main__":
    args = parser.parse_args()
    init_commands = []
    if args.init_commands:
        init_commands = args.init_commands.replace('[', "").replace(']', "").replace("\"", "").split(",")
    open("ss", "w").write(",".join(init_commands))
    password = ""
    if args.password:
        password = args.password
    ip, port = args.address.split(":")
    client = WebsocketClient(ip, int(port), password, init_commands)
    client.run()
