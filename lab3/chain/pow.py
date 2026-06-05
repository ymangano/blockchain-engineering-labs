def count_leading_zero_bits(data: bytes) -> int:
    """
    Count the number of leading zero bits in a byte string.

    Example:
        b"\\x00\\x7f..." starts with:
        - 8 zero bits from 0x00
        - then 1 zero bit from 0x7f = 01111111
        => total 9 leading zero bits
    """
    total = 0

    for byte in data:
        if byte == 0:
            total += 8
            continue

        # first nonzero byte
        for i in range(8):
            bit = (byte >> (7 - i)) & 1

            if bit == 0:
                total += 1
            else:
                return total

    return total


def valid_pow(block_hash: bytes, difficulty: int) -> bool:
    """
    Check whether block_hash satisfies the declared difficulty.

    Difficulty means:
        required number of leading zero bits in block_hash
    """
    if len(block_hash) != 32:
        print(f"Invalid block hash length: {len(block_hash)}. Expected 32 bytes.")
        return False

    if difficulty < 0 or difficulty > 256:
        print(f"Invalid difficulty: {difficulty}. Must be between 0 and 256.")
        return False

    return count_leading_zero_bits(block_hash) >= difficulty
