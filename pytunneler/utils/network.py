import asyncio
import logging
import socket

from websockets import WebSocketCommonProtocol, WebSocketServerProtocol
BUFFER = 8192


def tcp_recv(client_socket):
    try:
        data = client_socket.recv(BUFFER)
        if not data:
            return None
        data = data.replace(b"127.0.0.1:99", b"afdian.com")
        logging.debug("TCP server received: " + str(data))
        return data
    except Exception as e:
        logging.error(f"Error receiving TCP data: {e}")
        return None

def tcp_send(client_socket, data):
    try:
        client_socket.sendall(data)
    except Exception as e:
        logging.error(f"Error sending TCP data: {e}")
        return False
    return True

def websocket_send(loop, websocket, data):
    try:
        asyncio.run_coroutine_threadsafe(websocket.send(data), loop)
    except Exception as e:
        logging.debug(f"Error sending WebSocket data: {e}")

async def websocket_recv(websocket: WebSocketCommonProtocol):
    try:
        msg = await websocket.recv()
        return msg
    except Exception as e:
        logging.error(f"Error with WebSocket: {e}")
        return None


def try_port(port):
    # Source: https://stackoverflow.com/a/43271125/24191134
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        result = False
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
            result = True
        except socket.error as e:
            pass
        finally:
            sock.close()
        return result

def scan_port():
    available_ports = []
    for i in range(1, 65535):
        if try_port(i):
            available_ports.append(i)
    return available_ports