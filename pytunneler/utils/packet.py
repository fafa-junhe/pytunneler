from typing import List, Type


#  websocket层传输的包定义
DATA_LENGTH = 15
#  前15字节保留为包信息



class Packet:
    def __init__(self, data: bytes):
        self.data = data
        self.addition_data = b""

    @staticmethod
    def get_type_magic_number() -> bytes:
        return b"\x01"

    def create_packet(self):
        if len(self.addition_data) > 14:
            raise RuntimeError(f"data has more than 9 bytes: {self.addition_data}")
        length_byte = len(self.addition_data).to_bytes(1, 'big')
        tmp = self.addition_data + (14 - len(self.addition_data)) * b"\x00"
        return self.get_type_magic_number() + length_byte + tmp + self.data

    @classmethod
    def from_packet(cls, bytes):
        if bytes[0:1] == cls.get_type_magic_number():
            data = bytes[16:]
            return cls(data)
        else:
            raise RuntimeError("packet type don't match")

    @staticmethod
    def bytes2packet(bytes: bytes):
        for type_ in PacketTypes:
            if bytes[0:1] == type_.get_type_magic_number():
                return type_.from_packet(bytes)
        raise RuntimeError("no such packet type")

class ConnectedPacket(Packet):
    def __init__(self, host: bytes, target_host: bytes):
        super().__init__(b'')
        self.host = host
        self.target_host = target_host
        self.addition_data = host + target_host

    @staticmethod
    def get_type_magic_number() -> bytes:
        return b"\x02"

    @classmethod
    def from_packet(cls, bytes):
        if bytes[0:1] == cls.get_type_magic_number():
            length = bytes[1]
            host = bytes[2:2 + int(length / 2)]
            target_host = bytes[2 + int(length / 2): length + 2]
            return cls(host, target_host)
        else:
            raise RuntimeError("packet type don't match")

class ShutdownPacket(Packet):
    def __init__(self, host):
        super().__init__(b'')
        self.addition_data = host

    @staticmethod
    def get_type_magic_number() -> bytes:
        return b"\x03"

    @classmethod
    def from_packet(cls, bytes):
        if bytes[0:1] == cls.get_type_magic_number():
            length = bytes[1]
            host = bytes[2:2 + length]
            return cls(host)
        else:
            raise RuntimeError("packet type don't match")

class BinaryPacket(Packet):
    def __init__(self, host: bytes, target_host: bytes, data: bytes):
        super().__init__(data)
        self.host = host
        self.target_host = target_host
        self.addition_data = host + target_host

    @staticmethod
    def get_type_magic_number() -> bytes:
        return b"\x04"

    @classmethod
    def from_packet(cls, bytes):
        if bytes[0:1] == cls.get_type_magic_number():
            length = bytes[1]
            host = bytes[2:2 + int(length / 2)]
            target_host = bytes[2 + int(length / 2): length + 2]
            data = bytes[16:]
            return cls(host, target_host, data)
        else:
            raise RuntimeError("packet type don't match")

class CommandPacket(Packet):
    def __init__(self, command: str):
        self.command = command
        super().__init__(command.encode())

    @staticmethod
    def get_type_magic_number() -> bytes:
        return b"\x05"

    @classmethod
    def from_packet(cls, bytes):
        if bytes[0:1] == cls.get_type_magic_number():
            command = bytes[16:]
            return cls(command.decode())
        else:
            raise RuntimeError("packet type don't match")

class CommandCallbackPacket(Packet):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message.encode())

    @staticmethod
    def get_type_magic_number() -> bytes:
        return b"\x06"

    @classmethod
    def from_packet(cls, bytes):
        if bytes[0:1] == cls.get_type_magic_number():
            message = bytes[16:]
            return cls(message.decode())
        else:
            raise RuntimeError("packet type don't match")

class PasswordPacket(Packet):
    def __init__(self, password: str):
        self.password = password
        super().__init__(password.encode())

    @staticmethod
    def get_type_magic_number() -> bytes:
        return b"\x07"

    @classmethod
    def from_packet(cls, bytes):
        if bytes[0:1] == cls.get_type_magic_number():
            password = bytes[16:]
            return cls(password.decode())
        else:
            raise RuntimeError("packet type don't match")


PacketTypes : List[Type[Packet]] = [
    Packet, ConnectedPacket, ShutdownPacket, BinaryPacket, CommandPacket, CommandCallbackPacket, PasswordPacket
]
