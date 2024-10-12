from utils.host_hex import hex2host, host2hex


def test_host_to_hash():
    hashes = set()
    for i in range(255):
        for p in range(1, 65535):
            host = f"255.255.255.{i}:{p}"
            hash_ = host2hex(host)
            assert hash_ not in hashes # little collision test
            assert len(hash_) < 7 # limit 6 hex
            assert host == hex2host(hash_)
            hashes.add(hash_)