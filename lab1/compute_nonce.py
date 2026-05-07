import hashlib
import struct

email_address = "y.mangano@student.tudelft.nl"
github_repo = "https://github.com/ymangano/blockchain-engineering-labs"

encoded_string = f"{email_address}\n{github_repo}\n".encode("utf-8")

def find_nonce():
    nonce = 0
    max_nonce = 2**63 - 1  # Maximum value for a signed 8-byte integer

    while nonce <= max_nonce:
        nonce_bytes = nonce.to_bytes(8, "big", signed=True)
        combined_string = encoded_string + nonce_bytes
        hash_result = hashlib.sha256(combined_string).digest()
        
        if hash_result[0] == 0 and hash_result[1] == 0 and hash_result[2] == 0 and hash_result[3] < 16:
            print(f"Nonce found: {nonce}")
            print(f"Hash (SHA256): {hash_result.hex()}")
            return nonce, hash_result.hex()
        
        if nonce % 1_000_000 == 0:
            print(f"Checked {nonce:,} nonces...")
        
        nonce += 1

find_nonce()

# Nonce found = 416660345
# Hash (SHA256): 00000007404357b2e27535bddad382ad23d2df062c9dc5f828130ac9e8014b9e