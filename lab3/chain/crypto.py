import hashlib


def sha256(data: bytes) -> bytes:
    """
    Return SHA-256(data) as raw 32 bytes.
    """
    return hashlib.sha256(data).digest()


def u64_be(value: int) -> bytes:
    """
    Encode an integer as an unsigned 64-bit big-endian value.

    Used for:
    - transaction timestamp
    - block timestamp
    - block nonce
    """
    if value < 0 or value >= 2**64:
        raise ValueError("value does not fit in uint64")

    return value.to_bytes(8, "big")


def u32_be(value: int) -> bytes:
    """
    Encode an integer as an unsigned 32-bit big-endian value.

    Used for:
    - block difficulty
    """
    if value < 0 or value >= 2**32:
        raise ValueError("value does not fit in uint32")

    return value.to_bytes(4, "big")
