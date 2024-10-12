from pytunneler.utils.packet import Packet, ConnectedPacket, ShutdownPacket, BinaryPacket, DATA_LENGTH


def test_packet_creation():
    packet = Packet(b"testdata")
    packet.addition_data = b"host"
    created_packet = packet.create_packet()
    assert created_packet.startswith(Packet.get_type_magic_number())
    assert created_packet[1] == len(packet.addition_data)
    assert created_packet[2:DATA_LENGTH + 1].startswith(packet.addition_data)
    assert created_packet[16:] == b"testdata"

def test_connected_packet_creation():
    packet = ConnectedPacket(b"host")
    created_packet = packet.create_packet()
    assert created_packet.startswith(ConnectedPacket.get_type_magic_number())
    assert created_packet[1] == len(packet.addition_data)
    assert created_packet[2:DATA_LENGTH + 1].startswith(packet.addition_data)

def test_shutdown_packet_creation():
    packet = ShutdownPacket(b"host")
    created_packet = packet.create_packet()
    assert created_packet.startswith(ShutdownPacket.get_type_magic_number())
    assert created_packet[1] == len(packet.addition_data)
    assert created_packet[2:DATA_LENGTH + 1].startswith(packet.addition_data)

def test_binary_packet_creation():
    packet = BinaryPacket(b"host", b"data")
    created_packet = packet.create_packet()
    assert created_packet.startswith(BinaryPacket.get_type_magic_number())
    assert created_packet[1] == len(packet.addition_data)
    assert created_packet[2:DATA_LENGTH + 1].startswith(packet.addition_data)
    assert created_packet[DATA_LENGTH + 1:] == b"data"

def test_packet_parsing():
    original_packet = Packet(b"testdata")
    original_packet.addition_data = b"host"
    bytes_packet = original_packet.create_packet()
    parsed_packet = Packet.from_packet(bytes_packet)
    assert parsed_packet.data == original_packet.data

def test_connected_packet_parsing():
    original_packet = ConnectedPacket(b"host")
    bytes_packet = original_packet.create_packet()
    parsed_packet = ConnectedPacket.from_packet(bytes_packet)
    assert parsed_packet.addition_data == original_packet.addition_data

def test_shutdown_packet_parsing():
    original_packet = ShutdownPacket(b"host")
    bytes_packet = original_packet.create_packet()
    parsed_packet = ShutdownPacket.from_packet(bytes_packet)
    assert parsed_packet.addition_data == original_packet.addition_data

def test_binary_packet_parsing():
    original_packet = BinaryPacket(b"host", b"data")
    bytes_packet = original_packet.create_packet()
    parsed_packet = BinaryPacket.from_packet(bytes_packet)
    assert parsed_packet.data == original_packet.data
    assert parsed_packet.addition_data == original_packet.addition_data

def test_bytes2packet():
    original_packet = BinaryPacket(b"host", b"data")
    bytes_packet = original_packet.create_packet()
    parsed_packet = Packet.bytes2packet(bytes_packet)
    assert isinstance(parsed_packet, BinaryPacket)
    assert parsed_packet.data == original_packet.data
    assert parsed_packet.addition_data == original_packet.addition_data
