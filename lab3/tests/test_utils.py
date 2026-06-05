# from utils import (
#     Transaction,
#     BlockHeader,
#     compute_txs_hash,
#     count_leading_zero_bits,
#     mine_block,
#     valid_pow,
#     sha256
# )
from chain.crypto import sha256
from chain.transaction import Transaction
from chain.block import (
    BlockHeader,
    compute_txs_hash,
)
from chain.pow import (
    count_leading_zero_bits,
    valid_pow,
)
from chain.miner import mine_block

# ------------------------
# Transaction tests
# ------------------------


def test_tx_hash_is_32_bytes():
    tx = Transaction(
        sender_key=b"a",
        data=b"hello",
        timestamp=123,
        signature=b"sig",
    )

    h = tx.tx_hash()

    assert len(h) == 32


# ------------------------
# Commitment tests
# ------------------------


def test_empty_commitment():
    assert compute_txs_hash([]) == sha256(b"")


# ------------------------
# Block tests
# ------------------------


def test_header_is_84_bytes():
    header = BlockHeader(
        prev_hash=b"\x00" * 32,
        txs_hash=b"\x11" * 32,
        timestamp=1,
        difficulty=8,
        nonce=0,
    )

    packed = header.pack()

    assert len(packed) == 84


# ------------------------
# PoW tests
# ------------------------


def test_leading_zero_bits():
    assert count_leading_zero_bits(b"\x00") == 8
    assert count_leading_zero_bits(b"\x00\x00") == 16
    assert count_leading_zero_bits(b"\x0f") == 4


def test_mining():
    header = BlockHeader(
        prev_hash=b"\x00" * 32,
        txs_hash=b"\x11" * 32,
        timestamp=1,
        difficulty=12,
        nonce=0,
    )

    block = mine_block(
        header.prev_hash,
        [],
        header.timestamp,
        header.difficulty,
    )

    assert valid_pow(
        block.header.block_hash(),
        block.header.difficulty,
    )
