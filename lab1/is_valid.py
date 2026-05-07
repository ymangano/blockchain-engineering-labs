import hashlib
import struct

def is_valid_pow(email: str, github_url: str, nonce: bytes) -> bool:
    data = (
        email.encode("utf-8")
        + b"\n"
        + github_url.encode("utf-8")
        + b"\n"
        + nonce
    )

    digest = hashlib.sha256(data).digest()

    return digest[:3] == b"\x00\x00\x00" and digest[3] < 16

nonce_int = 416660345
# nonce_bytes = struct.pack(">q", nonce_int)
nonce_bytes = nonce_int.to_bytes(8, "big", signed=True)

print(is_valid_pow("y.mangano@student.tudelft.nl", "https://github.com/ymangano/blockchain-engineering-labs", nonce_bytes))