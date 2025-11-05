import hashlib
import ecdsa
import base58  # pip install base58
import secrets

def generate_bitcoin_address():
    """
    Generate a random Bitcoin address (P2PKH legacy format).
    
    Returns:
    tuple: (private_key_hex, public_key_hex, bitcoin_address)
    """
    # Step 1: Generate a random private key (32 bytes)
    private_key = secrets.token_bytes(32)
    private_key_hex = private_key.hex()
    
    # Step 2: Derive the public key using ECDSA (secp256k1 curve)
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.verifying_key
    public_key = b'\x04' + verifying_key.to_string()  # Uncompressed public key
    public_key_hex = public_key.hex()
    
    # Step 3: Hash the public key (SHA256 then RIPEMD160)
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    hashed_public_key = ripemd160.digest()
    
    # Step 4: Add version byte (0x00 for mainnet P2PKH)
    versioned_payload = b'\x00' + hashed_public_key
    
    # Step 5: Double SHA256 for checksum
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    
    # Step 6: Append checksum and encode in Base58
    full_payload = versioned_payload + checksum
    bitcoin_address = base58.b58encode(full_payload).decode('utf-8')
    
    return private_key_hex, public_key_hex, bitcoin_address

# Example usage
if __name__ == "__main__":
    priv_key, pub_key, address = generate_bitcoin_address()
    print(f"Private Key (hex): {priv_key}")
    print(f"Public Key (hex): {pub_key}")
    print(f"Bitcoin Address: {address}")