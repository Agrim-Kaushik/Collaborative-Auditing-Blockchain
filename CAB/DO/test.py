from hashlib import sha256
from typing import List, Tuple
from py_ecc.optimized_bls12_381 import G1, G2, multiply, normalize, add, pairing, FQ
from py_ecc.bls.hash_to_curve import hash_to_G2, hash_to_G1
import os
from dotenv import load_dotenv
import json
import secrets 
from py_ecc.bls12_381 import curve_order

load_dotenv()

def load_gpk(node_id, filename="gms_public_keys.json"):
    
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

#---------key gen-------------


p = curve_order

gpk = load_gpk("GM1","../PKG/gpk.json")
print(gpk)

beta = int(os.getenv("sk"))
print("beta: ", beta)

pk = multiply(gpk, beta)

inv = pow(beta, -1, p)
gamma = multiply(gpk, inv)

#---------File to Aux-------------
FILE_PATH = "upload.txt" 
CHUNK_SIZE = 31

print("😀Reading original file...")
with open(FILE_PATH, 'rb') as f:
    file_data = f.read()
    
original_hash = sha256(file_data).hexdigest()

print(f"Original file size: {len(file_data)} bytes")
print(f"Original hash: {original_hash}")

# Step 2: Split into 31-byte chunks
print("\nSplitting into 31-byte chunks...")
chunks = []
for i in range(0, len(file_data), CHUNK_SIZE):
    chunk = file_data[i:i+CHUNK_SIZE]
    chunks.append(chunk)

print(f"Total chunks: {len(chunks)}")
print(f"Last chunk size: {len(chunks[-1])} bytes")

# Step 3: Reconstruct file from chunks
print("\nReconstructing file from chunks...")
reconstructed_data = b''.join(chunks)

reconstructed_hash = sha256(reconstructed_data).hexdigest()
print(f"Reconstructed size: {len(reconstructed_data)} bytes")
print(f"Reconstructed hash: {reconstructed_hash}")

# Step 4: Verify equality
print("\n=== VERIFICATION ===")
print(f"Original hash:      {original_hash}")
print(f"Reconstructed hash: {reconstructed_hash}")
print(f"Hashes match: {original_hash == reconstructed_hash}")
print(f"Files are identical: {file_data == reconstructed_data}")

if original_hash == reconstructed_hash:
    print("\n✅ SUCCESS: File reconstructed perfectly!")
else:
    print("\n❌ ERROR: Reconstruction failed!")
    

    

#---------File to CSP-------------


H1 = hash_to_G2(b'1+123',b'TAG_GEN_DST', sha256) #instead of 1+123 use ts of that chunk from act
H2 = hash_to_G2(b'1+124',b'TAG_GEN_DST', sha256)
H3 = hash_to_G2(b'1+125',b'TAG_GEN_DST', sha256)

b1 = 45859958992121299393414684354293432471870030661827545412249735 #use chunk byte instead
b2 = 25859958992121199393414684354293632471870000661827575412249737
b3 = 31859958912121199393414684354293632471870111661827545412249744

t1 = multiply(add(H1,multiply(G2,b1)),beta)
t2 = multiply(add(H2,multiply(G2,b2)),beta)
t3 = multiply(add(H3,multiply(G2,b3)),beta)

r1 = 7
r2 = 6
r3 = 2

TP = add(add(multiply(t1,r1),multiply(t2,r2)),multiply(t3,r3))

DP = ((b1*r1)%p + ((b2)*r2)%p + (b3*r3)%p)%p

a = pairing(TP,gamma)
b = pairing(multiply(G2,DP),gpk)
DBI = pairing(add(add(multiply(H1,r1),multiply(H2,r2)),multiply(H3,r3)), gpk)

print(a==DBI*b)




