import json
import os
from ecdsa import Ed25519, SigningKey, VerifyingKey


def generate_keypair():
    """Generate an EdDSA keypair using ecdsa library."""
    private_key = SigningKey.generate(curve=Ed25519)
    public_key = private_key.get_verifying_key()
    return private_key, public_key


def serialize_private_key(private_key):
    """Serialize private key to hex string."""
    return private_key.to_string().hex()


def serialize_public_key(public_key):
    """Serialize public key to hex string."""
    return public_key.to_string().hex()


def deserialize_private_key(key_hex):
    """Deserialize private key from hex string."""
    key_bytes = bytes.fromhex(key_hex)
    return SigningKey.from_string(key_bytes, curve=Ed25519)


def deserialize_public_key(key_hex):
    """Deserialize public key from hex string."""
    key_bytes = bytes.fromhex(key_hex)
    return VerifyingKey.from_string(key_bytes, curve=Ed25519)


def sign_message(private_key, message):
    """Sign a message using EdDSA private key."""
    message_bytes = message.encode('utf-8')
    signature = private_key.sign(message_bytes)
    return signature


def verify_signature(public_key, message, signature):
    """Verify a signature using EdDSA public key."""
    message_bytes = message.encode('utf-8')
    try:
        public_key.verify(signature, message_bytes)
        return True
    except Exception as e:
        print(f"   Verification failed: {e}")
        return False


def save_to_env_file(keypairs, filename=".env"):
    """Save only private keys to .env file."""
    with open(filename, 'w') as f:
        for i, (priv_key, _) in enumerate(keypairs):
            f.write(f"PRIVATE_KEY_{i}={serialize_private_key(priv_key)}\n")
    print(f"\n✓ Saved private keys to {filename}")


def save_public_keys_to_json(keypairs, filename="public_keys.json"):
    """Save public keys to JSON file."""
    public_keys_dict = {}
    for i, (_, pub_key) in enumerate(keypairs):
        public_keys_dict[f"key_{i}"] = serialize_public_key(pub_key)
    
    with open(filename, 'w') as f:
        json.dump(public_keys_dict, f, indent=2)
    print(f"✓ Saved public keys to {filename}")


def load_private_key_from_env(key_index, env_file=".env"):
    """Load a specific private key from .env file."""
    env_vars = {}
    with open(env_file, 'r') as f:
        for line in f:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                env_vars[key] = value
    
    priv_key_str = env_vars.get(f"PRIVATE_KEY_{key_index}")
    
    if not priv_key_str:
        raise ValueError(f"Private key for index {key_index} not found in {env_file}")
    
    return deserialize_private_key(priv_key_str)


def load_public_key_from_json(key_name, json_file="public_keys.json"):
    """Load a specific public key from JSON file."""
    with open(json_file, 'r') as f:
        public_keys = json.load(f)
    
    pub_key_str = public_keys.get(key_name)
    if not pub_key_str:
        raise ValueError(f"Key {key_name} not found in {json_file}")
    
    return deserialize_public_key(pub_key_str)


def print_keypairs(keypairs):
    """Print all keypairs to terminal."""
    print("\n" + "="*70)
    print("GENERATED KEYPAIRS")
    print("="*70)
    
    for i, (priv_key, pub_key) in enumerate(keypairs):
        priv_hex = serialize_private_key(priv_key)
        pub_hex = serialize_public_key(pub_key)
        
        print(f"\n--- Keypair {i} ---")
        print(f"Private Key: {priv_hex}")
        print(f"Public Key:  {pub_hex}")


def test_all_keypairs(num_keys):
    """Test signing and verification for each keypair."""
    print("\n" + "="*70)
    print("TESTING ALL KEYPAIRS")
    print("="*70)
    
    test_message = "Hello, EdDSA signatures work with private signing and public verification!"
    
    all_passed = True
    
    for i in range(num_keys):
        print(f"\n--- Testing Keypair {i} ---")
        
        # Load private key from .env
        print(f"1. Loading private key from .env (PRIVATE_KEY_{i})...")
        try:
            private_key = load_private_key_from_env(i)
            print(f"   ✓ Private key loaded")
            print(private_key)
        except Exception as e:
            print(f"   ✗ Failed to load private key: {e}")
            all_passed = False
            continue
        
        # Sign the message
        print(f"2. Signing message...")
        try:
            signature = sign_message(private_key, test_message)
            print(f"   ✓ Signature generated: {signature.hex()[:32]}...")
        except Exception as e:
            print(f"   ✗ Failed to sign: {e}")
            all_passed = False
            continue
        
        # Load public key from JSON
        print(f"3. Loading public key from JSON (key_{i})...")
        try:
            public_key = load_public_key_from_json(f"key_{i}")
            print(f"   ✓ Public key loaded")
        except Exception as e:
            print(f"   ✗ Failed to load public key: {e}")
            all_passed = False
            continue
        
        # Verify the signature with correct key
        print(f"4. Verifying signature with correct key...")
        is_valid = verify_signature(public_key, test_message, signature)
        if is_valid:
            print(f"   ✓ SIGNATURE VERIFIED SUCCESSFULLY!")
        else:
            print(f"   ✗ Signature verification FAILED!")
            all_passed = False
        
        # Test with wrong key (if available)
        if num_keys > 1:
            wrong_key_index = (i + 1) % num_keys
            print(f"5. Testing with wrong key (key_{wrong_key_index}) - should fail...")
            try:
                wrong_public_key = load_public_key_from_json(f"key_{wrong_key_index}")
                is_valid_wrong = verify_signature(wrong_public_key, test_message, signature)
                if not is_valid_wrong:
                    print(f"   ✓ Correctly rejected signature with wrong key!")
                else:
                    print(f"   ✗ ERROR: Wrong key accepted signature!")
                    all_passed = False
            except Exception as e:
                print(f"   ✗ Error testing wrong key: {e}")
    
    print("\n" + "="*70)
    if all_passed:
        print("✓ ALL TESTS PASSED!")
    else:
        print("✗ SOME TESTS FAILED!")
    print("="*70)


def main():
    """Main function to orchestrate key generation and demonstration."""
    print("EdDSA Key Generation and Signing Demo")
    print("="*70)
    
    # Generate 9 keypairs
    num_keys = 9
    print(f"\nGenerating {num_keys} EdDSA keypairs...")
    keypairs = [generate_keypair() for _ in range(num_keys)]
    print(f"✓ Generated {len(keypairs)} keypairs")
    
    # Print keypairs to terminal
    print_keypairs(keypairs)
    
    # Save to files
    print("\n" + "="*70)
    print("SAVING TO FILES")
    print("="*70)
    save_to_env_file(keypairs)
    save_public_keys_to_json(keypairs)
    
    # Test all keypairs
    test_all_keypairs(num_keys)
    
    print("\n" + "="*70)
    print("DEMO COMPLETE")
    print("="*70)
    print("\nFiles created:")
    print("  - .env (contains private keys only)")
    print("  - public_keys.json (contains public keys only)")

 
if __name__ == "__main__":
    main()
