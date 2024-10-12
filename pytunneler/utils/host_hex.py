import socket

def host2hex(host):
    # Convert IP address to hash
    ip, port = host.split(":")
    ip = socket.inet_aton(ip)
    port = int(port).to_bytes(2, 'big')
    return ip + port

def hex2host(hash_):
    # Convert the IP address bytes back to a string
    ip = socket.inet_ntoa(hash_[:4])
    # Convert the port number bytes back to an integer
    port = int.from_bytes(hash_[4:], 'big')
    return f"{ip}:{port}"

