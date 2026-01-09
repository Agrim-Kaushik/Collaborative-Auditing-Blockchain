from py_ecc.optimized_bls12_381 import (
    G1,
    curve_order,
    multiply,
    add,
    normalize,
    FQ,
)
import os
import json
import secrets 

def create_uncompressed_key_store(node_ids, filename="gms_public_keys.json"):
    
    key_store_data = {}
    generated_secrets = {}

    for node_id in node_ids:
        
        secret = secrets.randbelow(curve_order - 1) + 1
        generated_secrets[node_id] = secret

        print(f"\nGenerated key for '{node_id}':")
        print(f"  Secret number from Z*p: {secret}")
        print(f"  Bit Lengths (Secret, Curve Order): {secret.bit_length()}, {curve_order.bit_length()}")

        public_key_uncompressed = multiply(G1, secret)

        key_as_integers = [
            public_key_uncompressed[0].n,
            public_key_uncompressed[1].n,
            public_key_uncompressed[2].n
        ]

        key_store_data[node_id] = key_as_integers

    with open(filename, 'w') as f:
        json.dump(key_store_data, f, indent=4)

    print(f"\nSuccessfully saved all public keys to '{filename}'")
    return generated_secrets


def load_uncompressed_key_from_store(node_id, filename="gms_public_keys.json"):
    
    print(f"\n--- Loading Public Key for '{node_id}' ---")
    try:
        with open(filename, 'r') as f:
            key_store = json.load(f)
    except FileNotFoundError:
        print(f"Error: Keystore file '{filename}' not found.")
        return None

    key_as_integers = key_store.get(node_id)

    if not key_as_integers:
        print(f"Error: Node ID '{node_id}' not found in the key store.")
        return None

    reconstructed_key = (
        FQ(key_as_integers[0]),
        FQ(key_as_integers[1]),
        FQ(key_as_integers[2])
    )
    print(f"Successfully loaded and deserialized public key for '{node_id}'.")
    return reconstructed_key


def main():

    NODE_IDS = [f"GM{i}" for i in range(7)]
    KEY_STORE_FILE = "gms_public_keys.json"

    all_secrets = create_uncompressed_key_store(NODE_IDS, KEY_STORE_FILE)

    all_verified = True
    
    for node_id in NODE_IDS:

        loaded_public_key = load_uncompressed_key_from_store(node_id, KEY_STORE_FILE)

        if loaded_public_key:
            
            original_secret = all_secrets[node_id]
            expected_public_key = multiply(G1, original_secret)

            if loaded_public_key == expected_public_key:
                print(f"✅ SUCCESS: The loaded public key for '{node_id}' is correct.")
            else:
                print(f"❌ FAILURE: The loaded public key for '{node_id}' did not match.")
                all_verified = False
        else:
            all_verified = False

    print("\n" + "=" * 60)
    if all_verified:
        print("All keys were successfully stored, loaded, and verified!")
    else:
        print("An error occurred during the verification process.")
    print("=" * 60)


if __name__ == "__main__":
    main()
