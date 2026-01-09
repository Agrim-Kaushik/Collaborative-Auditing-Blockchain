
# DO/DO.py - WITH UPLOAD AND AUDIT COMMANDS - GAMMA CALCULATION FIXED

import json
import os
import socket
import time
import argparse
import secrets
from hashlib import sha256
from act import ACT
from dotenv import load_dotenv
from py_ecc.optimized_bls12_381 import G1, G2, multiply, add, FQ, pairing, FQ2
from py_ecc.bls.hash_to_curve import hash_to_G2
from py_ecc.bls12_381 import curve_order
from ecdsa import Ed25519, SigningKey, VerifyingKey

load_dotenv()

# EdDSA SIGNATURE UTILITIES

def deserialize_private_key(key_hex):
    """Deserialize EdDSA private key from hex string."""
    key_bytes = bytes.fromhex(key_hex)
    return SigningKey.from_string(key_bytes, curve=Ed25519)

def deserialize_public_key(key_hex):
    """Deserialize EdDSA public key from hex string."""
    key_bytes = bytes.fromhex(key_hex)
    return VerifyingKey.from_string(key_bytes, curve=Ed25519)

def sign_message_eddsa(private_key, message):
    """Sign a message using EdDSA private key."""
    if isinstance(message, str):
        message_bytes = message.encode('utf-8')
    else:
        message_bytes = message
    signature = private_key.sign(message_bytes)
    return signature

def verify_signature_eddsa(public_key, message, signature_hex):
    """Verify EdDSA signature."""
    try:
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        else:
            message_bytes = message
        signature = bytes.fromhex(signature_hex)
        public_key.verify(signature, message_bytes)
        return True
    except Exception as e:
        print(f" Signature verification failed: {e}")
        return False

# BLS UTILITIES

def load_gpk(node_id="GM0", filename="gpk.json"):
    """Load group manager public key"""
    try:
        with open(filename, 'r') as f:
            key_store = json.load(f)
        key_as_integers = key_store.get(node_id)
        if not key_as_integers:
            raise ValueError(f"Node ID '{node_id}' not found")
        gpk = (FQ(key_as_integers[0]), FQ(key_as_integers[1]), FQ(key_as_integers[2]))
        print(f"✓ Loaded GPK for {node_id}")
        return gpk
    except Exception as e:
        print(f" Error loading gpk: {e}")
        return None

def serialize_g1_point(point):
    """Serialize G1 point to list of integers."""
    return [int(point[0].n), int(point[1].n), int(point[2].n)]


# FILE PROCESSING

def file_to_chunks(filepath, chunk_size=31):
    """Read file and split into 31-byte chunks."""
    with open(filepath, 'rb') as f:
        file_data = f.read()
    chunks = [file_data[i:i+chunk_size] for i in range(0, len(file_data), chunk_size)]
    return chunks

def generate_bls_tags(chunks, file_blocks, beta):
    """Generate BLS tags for each chunk."""
    p = curve_order
    tags = []
    print("\n Generating BLS tags...")
    for i, chunk in enumerate(chunks):
        ts = file_blocks[i]['ts']
        v = file_blocks[i]['v']
        message = f"{v}+{ts}".encode()
        H_i = hash_to_G2(message, b'TAG_GEN_DST', sha256)
        b_i = int.from_bytes(chunk, 'big')
        G2_bi = multiply(G2, b_i)
        H_plus_G2bi = add(H_i, G2_bi)
        t_i = multiply(H_plus_G2bi, beta)
        tags.append(t_i)
        print(f"  ✓ Tag {i+1}/{len(chunks)}")
    return tags

def serialize_g2_point(point):
    """Serialize G2 point to list of integers."""
    return [
        [int(point[0].coeffs[0]), int(point[0].coeffs[1])],
        [int(point[1].coeffs[0]), int(point[1].coeffs[1])],
        [int(point[2].coeffs[0]), int(point[2].coeffs[1])]
    ]

def serialize_chunks(chunks):
    """Serialize chunks to hex strings."""
    return [chunk.hex() for chunk in chunks]

# ACT MANAGEMENT

def update_act_los(file_id, block_height):
    """Update los from -1 to 1 and set loh for all blocks of the file in ACT."""
    try:
        act = ACT()
        if os.path.exists("act.json"):
            act.load("act.json")
        else:
            print(" ACT file not found")
            return False
        
        file_blocks = act.get_file(file_id)
        if not file_blocks:
            print(f" File {file_id} not found in ACT")
            return False
        
        for block in file_blocks:
            if 'los' in block and block['los'] == -1:
                block['los'] = 1
                block['loh'] = block_height
        
        act.save("act.json")
        print(f"✓ Updated ACT: Set los=1 and loh={block_height} for all blocks of {file_id}")
        return True
    except Exception as e:
        print(f" Error updating ACT: {e}")
        import traceback
        traceback.print_exc()
        return False

def update_act_audit(file_id, block_height, challenged_indices):
    """Update ACT after audit operation."""
    try:
        act = ACT()
        if os.path.exists("act.json"):
            act.load("act.json")
        else:
            print(" ACT file not found")
            return False
        
        file_blocks = act.get_file(file_id)
        if not file_blocks:
            print(f" File {file_id} not found in ACT")
            return False
        
        for idx in challenged_indices:
            if idx < len(file_blocks):
                file_blocks[idx]['loh'] = block_height
                file_blocks[idx]['lot'] = 'audit'
                file_blocks[idx]['los'] = 1
        
        act.save("act.json")
        print(f"✓ Updated ACT: Set audit metadata for challenged blocks")
        return True
    except Exception as e:
        print(f" Error updating ACT: {e}")
        import traceback
        traceback.print_exc()
        return False

# MESSAGE CREATION - INSERT

def create_insert_message(file_id, filepath, do_signing_key):
    """Create insert message for GM."""
    print(f"\n Processing file: {file_id}")
    
    chunks = file_to_chunks(filepath)
    print(f"✓ Created {len(chunks)} chunks")
    
    act = ACT()
    if os.path.exists("act.json"):
        try:
            act.load("act.json")
        except:
            pass
    
    act.add_file(file_id, chunks)
    file_blocks = act.get_file(file_id)
    act.save("act.json")
    print(f"✓ Created ACT with {len(file_blocks)} blocks")
    
    sk_str = os.getenv("sk")
    if not sk_str:
        raise ValueError("Secret key 'sk' not found in .env file")
    beta = int(sk_str.strip())
    tags = generate_bls_tags(chunks, file_blocks, beta)
    
    file_hash = sha256(open(filepath, 'rb').read()).hexdigest()
    ts_ins = int(time.time())
    
    serialized_tags = [serialize_g2_point(tag) for tag in tags]
    serialized_chunks = serialize_chunks(chunks)
    
    block_metadata = []
    for i, block in enumerate(file_blocks):
        block_metadata.append({
            "v": block['v'],
            "ts": block['ts'],
            "loh": block.get('loh', -1)
        })
    
    sig_data = str(ts_ins)
    for meta in block_metadata:
        sig_data += f"{meta['v']}{meta['ts']}{meta['loh']}"
    
    sigma_do = sign_message_eddsa(do_signing_key, sig_data)
    
    message = {
        "operation": "insert",
        "ts_ins": ts_ins,
        "id_do": "DO",
        "id_file": file_id,
        "file_chunks": serialized_chunks,
        "tags": serialized_tags,
        "file_hash": file_hash,
        "id_csp": "CSP",
        "block_metadata": block_metadata,
        "sigma_do": sigma_do.hex()
    }
    
    print(f"✓ Created insert message")
    print(f"  - Timestamp: {ts_ins}")
    print(f"  - Chunks: {len(serialized_chunks)}")
    print(f"  - Tags: {len(serialized_tags)}")
    print(f"  - Signature: {sigma_do.hex()[:40]}...")
    
    return message

# MESSAGE CREATION - AUDIT (WITH GAMMA CALCULATION)

def create_audit_message(file_id, block_indices, do_signing_key):
    """Create audit message for GM with gamma calculation."""
    print(f"\n🔍 Processing audit for: {file_id}")
    
    act = ACT()
    if not os.path.exists("act.json"):
        raise ValueError("ACT file not found")
    act.load("act.json")
    
    file_blocks = act.get_file(file_id)
    if not file_blocks:
        raise ValueError(f"File {file_id} not found in ACT")
    
    ts_aud = int(time.time())
    
    p = curve_order
    chal = []
    loh_list = []
    
    for idx in block_indices:
        if idx >= len(file_blocks):
            print(f"Warning: Block index {idx} out of range, skipping")
            continue
        
        ri = secrets.randbelow(p)
        chal.append({"i": idx, "ri": ri})
        loh_list.append(file_blocks[idx].get('loh', -1))
    
    print(f"✓ Created challenge set with {len(chal)} blocks")
    
    # CALCULATE GAMMA (γ = gpk^(β^-1))
    print("\n Calculating gamma...")
    gpk = load_gpk("GM0", "gpk.json")
    if not gpk:
        raise ValueError("Could not load GPK")
    
    sk_str = os.getenv("sk")
    if not sk_str:
        raise ValueError("Secret key 'sk' not found in .env file")
    beta = int(sk_str.strip())
    
    inv = pow(beta, -1, p)
    gamma = multiply(gpk, inv)
    gamma_serialized = serialize_g1_point(gamma)
    print("gamma: ",gamma)
    print(f"✓ Calculated gamma")
    
    sig_data = str(ts_aud) + str(chal) + str(loh_list)
    sigma_do = sign_message_eddsa(do_signing_key, sig_data)
    
    message = {
        "operation": "audit",
        "ts_aud": ts_aud,
        "id_do": "DO",
        "id_file": file_id,
        "chal": chal,
        "loh_list": loh_list,
        "gamma": gamma_serialized,
        "id_csp": "CSP",
        "sigma_do": sigma_do.hex()
    }
    
    print(f"✓ Created audit message")
    print(f"  - Timestamp: {ts_aud}")
    print(f"  - Challenged blocks: {len(chal)}")
    print(f"  - Gamma: {str(gamma_serialized)[:60]}...")
    print(f"  - Signature: {sigma_do.hex()[:40]}...")
    
    return message, block_indices

# NETWORK COMMUNICATION

def send_to_gm(message, gm_host="localhost", gm_port=9001):
    """Send message to GM and wait for response."""
    print(f"\n Connecting to GM at {gm_host}:{gm_port}...")
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((gm_host, gm_port))
        print("✓ Connected to GM")
        
        json_data = json.dumps(message)
        client_socket.sendall(json_data.encode('utf-8'))
        client_socket.sendall(b"\n\n")
        print("✓ Sent message to GM")
        
        print(" Waiting for GM response...")
        response_data = b""
        while True:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            response_data += chunk
            if b"\n\n" in response_data:
                break
        
        response_data = response_data.replace(b"\n\n", b"")
        response = json.loads(response_data.decode('utf-8'))
        
        print("✓ Received response from GM")
        print(f"  - Status: {response.get('status')}")
        if response.get('status') == 'error':
            print(f"  - Error: {response.get('message')}")
        else:
            print(f"  - Proof Result: {response.get('proof_result')}")
            if response.get('block_height') is not None:
                print(f"  - Block Height: {response.get('block_height')}")
        
        client_socket.close()
        return response
    
    except Exception as e:
        print(f" Error communicating with GM: {e}")
        import traceback
        traceback.print_exc()
        return None

# MAIN UPLOAD FUNCTION

def upload_file(file_path):
    """Main function to upload file."""
    if not os.path.exists(file_path):
        print(f" Error: File not found: {file_path}")
        return
    
    try:
        ssk_str = os.getenv("ssk")
        if not ssk_str:
            raise ValueError("DO signing key 'ssk' not found in .env")
        do_signing_key = deserialize_private_key(ssk_str.strip())
        print("✓ Loaded DO signing key")
        
        file_id = os.path.basename(file_path)
        message = create_insert_message(file_id, file_path, do_signing_key)
        
        response = send_to_gm(message)
        
        if response and response.get('status') == 'success':
            proof_result = response.get('proof_result')
            block_height = response.get('block_height', 0)
            
            if proof_result == 'VALID':
                print("\nFile uploaded successfully!")
                print("✓ Proof is VALID")
                print("\n Updating ACT...")
                if update_act_los(file_id, block_height):
                    print("ACT updated: los set to 1 for all blocks")
                else:
                    print("ACT update failed")
            else:
                print("\nFile uploaded but proof is INVALID")
                print(" ACT not updated (los remains -1)")
        else:
            print("\n File upload failed!")
            if response:
                print(f"  Reason: {response.get('message', 'Unknown error')}")
    
    except Exception as e:
        print(f" Error: {e}")
        import traceback
        traceback.print_exc()

# MAIN AUDIT FUNCTION

def audit_file(file_id, block_indices):
    """Main function to audit file."""
    try:
        ssk_str = os.getenv("ssk")
        if not ssk_str:
            raise ValueError("DO signing key 'ssk' not found in .env")
        do_signing_key = deserialize_private_key(ssk_str.strip())
        print("✓ Loaded DO signing key")
        
        message, challenged_indices = create_audit_message(file_id, block_indices, do_signing_key)
        
        response = send_to_gm(message)
        
        if response and response.get('status') == 'success':
            proof_result = response.get('proof_result')
            block_height = response.get('block_height', 0)
            
            if proof_result == 'VALID':
                print("\nAudit completed successfully!")
                print("✓ Proof is VALID - File integrity confirmed")
                print("\nUpdating ACT...")
                if update_act_audit(file_id, block_height, challenged_indices):
                    print("ACT updated: audit metadata recorded")
                else:
                    print("ACT update failed")
            else:
                print("\n Audit FAILED!")
                print("Proof is INVALID - File may be corrupted")
        else:
            print("\n Audit operation failed!")
            if response:
                print(f"  Reason: {response.get('message', 'Unknown error')}")
    
    except Exception as e:
        print(f" Error: {e}")
        import traceback
        traceback.print_exc()

# MAIN CLI

def main():
    parser = argparse.ArgumentParser(description="Data Owner - Blockchain Cloud Client")
    subparsers = parser.add_subparsers(dest="command")
    
    upload_parser = subparsers.add_parser("upload", help="Upload a file")
    upload_parser.add_argument("filepath", help="Path to file to upload")
    
    audit_parser = subparsers.add_parser("audit", help="Audit a file")
    audit_parser.add_argument("filepath", help="Name of file to audit")
    audit_parser.add_argument("--blocks", nargs='+', type=int, help="Indices of blocks to audit (default: all blocks)", default=None)
    
    args = parser.parse_args()
    
    if args.command == "upload":
        upload_file(args.filepath)
    elif args.command == "audit":
        if args.blocks is None:
            act = ACT()
            if os.path.exists("act.json"):
                act.load("act.json")
                file_blocks = act.get_file(args.filepath)
                if file_blocks:
                    args.blocks = list(range(len(file_blocks)))
                else:
                    print(f" File {args.filepath} not found in ACT")
                    return
            else:
                print(" ACT file not found")
                return
        
        audit_file(args.filepath, args.blocks)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
