#!/usr/bin/env python

import asyncio
import asyncio.trsock
import socket
import time
from picows import ws_create_server, WSFrame, WSTransport, WSListener, WSMsgType, WSUpgradeRequest, WSCloseCode
import threading
import logging
from queue import Queue
import argparse

from pytunneler.utils import commands, network, packet, host_hex

parser = argparse.ArgumentParser(description='pytunneler Websocket server')

parser.add_argument('address', type=str, nargs='?',
                    help='websocket server address', default='0.0.0.0:8321')

parser.add_argument('--password', type=str,
                    help='password')

class WebsocketServer(WSListener):
    def __init__(self, ip, port, password):
        self.tcp_thread = None
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.tcp_servers: dict[str, TCPServer] = dict()
        self.local_remote: dict[str, str] = dict()
        self.ip = ip
        self.port = port
        self.password = password


    def start_tcp_server(self, transport, local_ip, local_port, target_ip, target_port):
        thread = TCPServer(transport, self, local_ip, int(local_port), target_ip, int(target_port))
        self.tcp_servers[f"{target_ip}:{target_port}"] = thread
        self.local_remote[f"{local_ip}:{local_port}"] = f"{target_ip}:{target_port}"
        thread.start()

    def send_callback(self, transport, message):
        command_callback_packet = packet.CommandCallbackPacket(message)
        network.websocket_send(transport, command_callback_packet.create_packet())

    def handle_packet(self, raw_packet, transport: WSTransport):
        packet_ = packet.Packet.bytes2packet(raw_packet)
        if isinstance(packet_, packet.CommandPacket):
            command = packet_.command
            for command_type in commands.CommandTypes:
                if command.split()[0] == command_type.trigger:
                    context = commands.CommandContext(command.split()[1:], transport, self)
                    message = command_type.on_command(context)
                    self.send_callback(transport, message)
                    break
            else:
                print(f"Unknown command: {command.split()[0]}")
                self.send_callback(transport, f"Unknown command: {command.split()[0]}")
        elif isinstance(packet_, packet.BinaryPacket):
            ip, port = host_hex.hex2host(packet_.host).split(":")
            target_ip, target_port = host_hex.hex2host(packet_.target_host).split(":")
            remote_address = self.local_remote[f"{ip}:{port}"]
            network.tcp_send(self.tcp_servers[remote_address].clients[f"{target_ip}:{target_port}"], packet_.data)


    def check_password(self, transport, frame: WSFrame):
        try:
            password_packet = frame.get_payload_as_bytes()
            password_packet = packet.Packet.bytes2packet(password_packet)
            if isinstance(password_packet, packet.PasswordPacket):
                if self.password != password_packet.password:
                    self.send_callback(transport, "Wrong password")
                    time.sleep(1) # 给客户端时间反应，不然直接退出了信息看不到
                    return False
            else:
                self.send_callback(transport, "Wrong packet")
                time.sleep(1)
                return False
        except TimeoutError:
            self.send_callback(transport, "Timeout for password")
            time.sleep(1)
            return False
        return True




    class ServerListener(WSListener):
        def __init__(self, server):
            self.server = server
            self.password_checked = False
            super().__init__()

        def on_ws_connected(self, transport: WSTransport):
            atransport: asyncio.Transport = transport.underlying_transport
            transport_socket: asyncio.trsock.TransportSocket = atransport.get_extra_info('socket')
            peer = transport_socket.getpeername()
            logging.info(f"Connected by {peer[0]}:{peer[1]}")


        def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
            if frame.msg_type == WSMsgType.PING:
                transport.send_pong(frame.get_payload_as_bytes())
            elif frame.msg_type == WSMsgType.CLOSE:
                transport.send_close(frame.get_close_code(), frame.get_close_message())
                transport.disconnect()
            else:
                if not self.password_checked:
                    if server.check_password(transport, frame):
                        self.password_checked = True
                        return
                    else:
                        transport.send_close(WSCloseCode.INVALID_TEXT)
                        transport.disconnect()
                        return
                raw_packet = frame.get_payload_as_bytes()
                if not raw_packet:
                    transport.send_close(WSCloseCode.BAD_GATEWAY)
                    transport.disconnect()
                self.server.handle_packet(raw_packet, transport)


    def listener_factory(self, r: WSUpgradeRequest):
        return self.ServerListener(self)

    async def main(self):
        server: asyncio.Server = await ws_create_server(self.listener_factory, self.ip, self.port)
        for s in server.sockets:
            logging.info(f"Websocket server is running on {s.getsockname()}")
        await server.serve_forever()



    def run(self):
        try:
            return self.loop.run_until_complete(self.main())
        except KeyboardInterrupt:
            return self.loop.stop()

class TCPServer(threading.Thread):
    def __init__(self, websocket: WSTransport, server: WebsocketServer, local_ip, local_port, host, port):
        self.packet_queue = Queue()
        self.local_ip = local_ip
        self.local_port = local_port
        self.host = host
        self.port = port
        self.server = server
        self.server_socket = None
        self.websocket = websocket
        self.clients = {}
        self.shutdown = threading.Event()
        super().__init__()

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            self.server_socket = server_socket
            self.tcp_socket = server_socket
            logging.info(f"TCP server is running on {self.host}:{self.port}")
            local_hex = host_hex.host2hex(f"{self.local_ip}:{self.local_port}")

            while not self.shutdown.is_set():
                try:
                    client_socket, client_address = server_socket.accept()
                    client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    print(f"shutdowning TCP server {self.host}:{self.port}")

                client_host, client_port = client_address
                client_hex = host_hex.host2hex(f"{client_host}:{client_port}")
                self.clients[f"{client_host}:{client_port}"] = client_socket
                with client_socket:
                    logging.info(f"Connected by {client_address}")
                    connected_packet = packet.ConnectedPacket(client_hex, local_hex)
                    network.websocket_send(self.websocket, connected_packet.create_packet())
                    time.sleep(0.5) # 给客户端时间反应连接事件 TODO:更好的处理
                    while not self.shutdown.is_set():
                        data = network.tcp_recv(client_socket)
                        if data is None:
                            logging.info("no data, shutdowning")
                            break
                        binary_packet = packet.BinaryPacket(client_hex, local_hex, data)
                        network.websocket_send(self.websocket, binary_packet.create_packet())
            print(f"shutdowning TCP server {self.host}:{self.port}")

if __name__ == "__main__":
    args = parser.parse_args()
    ip, port = args.address.split(":")
    password = ""
    if args.password:
        password = args.password
    server = WebsocketServer(ip, port, password)
    server.run()

