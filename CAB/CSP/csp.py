# CSP/csp.py - WITH INSERT AND AUDIT SUPPORT\

import json
import socket
import os
import secrets
import time
import threading
from hashlib import sha256
from py_ecc.optimized_bls12_381 import G1, G2, multiply, add, FQ, pairing, FQ2
from py_ecc.bls.hash_to_curve import hash_to_G2
from py_ecc.bls12_381 import curve_order
from ecdsa import Ed25519, SigningKey, VerifyingKey
from dotenv import load_dotenv

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
        print(f"❌ Signature verification failed: {e}")
        return False

# BLS TAG UTILITIES

def deserialize_g2_point(point_data):
    """Deserialize G2 point from list of integers."""
    return (
        FQ2(point_data[0]),
        FQ2(point_data[1]),
        FQ2(point_data[2])
    )

def serialize_g2_point(point):
    """Serialize G2 point to list of integers."""
    return [
        [int(point[0].coeffs[0]), int(point[0].coeffs[1])],
        [int(point[1].coeffs[0]), int(point[1].coeffs[1])],
        [int(point[2].coeffs[0]), int(point[2].coeffs[1])]
    ]

def deserialize_chunks(chunks_hex):
    """Deserialize chunks from hex strings."""
    return [bytes.fromhex(chunk) for chunk in chunks_hex]

# FILE STORAGE UTILITIES

def save_chunks_to_directory(chunks, file_id):
    """Save chunks to directory based on file ID."""
    dir_name = f"{file_id}_storage"
    os.makedirs(dir_name, exist_ok=True)
    print(f"\n Saving {len(chunks)} chunks to {dir_name}/")
    for i, chunk in enumerate(chunks):
        chunk_path = os.path.join(dir_name, f"{i}.chunk")
        with open(chunk_path, 'wb') as f:
            f.write(chunk)
    print(f"✓ Saved all chunks")
    return dir_name

def load_chunks_from_directory(file_id):
    """Load chunks from directory."""
    dir_name = f"{file_id}_storage"
    if not os.path.exists(dir_name):
        print(f"❌ Storage directory not found: {dir_name}")
        return None

    chunks = []
    i = 0
    while True:
        chunk_path = os.path.join(dir_name, f"{i}.chunk")
        if not os.path.exists(chunk_path):
            break
        with open(chunk_path, 'rb') as f:
            chunks.append(f.read())
        i += 1

    print(f"✓ Loaded {len(chunks)} chunks from {dir_name}/")
    return chunks

def save_tags_to_file(tags, file_id):
    """Save tags to JSON file."""
    tags_filename = f"{file_id}_tags.json"
    with open(tags_filename, 'w') as f:
        json.dump(tags, f, indent=2)
    print(f"✓ Saved tags to {tags_filename}")
    return tags_filename

def load_tags_from_file(file_id):
    """Load tags from JSON file."""
    tags_filename = f"{file_id}_tags.json"
    if not os.path.exists(tags_filename):
        print(f"❌ Tags file not found: {tags_filename}")
        return None

    with open(tags_filename, 'r') as f:
        tags = json.load(f)

    print(f"✓ Loaded {len(tags)} tags from {tags_filename}")
    return tags

def verify_file_integrity(chunks, file_hash):
    """Verify file integrity via hash."""
    print("\n Verifying file integrity...")
    file_data = b''.join(chunks)
    computed_hash = sha256(file_data).hexdigest()

    if computed_hash == file_hash:
        print(f"✓ File integrity verified: {computed_hash}")
        return True
    else:
        print(f"❌ File integrity check failed!")
        print(f"  Expected: {file_hash}")
        print(f"  Got: {computed_hash}")
        return False

# PROOF COMPUTATION FOR INSERT

def compute_tp_dp_insert(chunks, tags):
    """Compute TP (Tag Proof) and DP (Data Proof) for insertion verification."""
    print("\n Computing TP and DP for insert...")
    p = curve_order
    n = len(chunks)

    # Generate random coefficients
    coefficients = [secrets.randbelow(p) for _ in range(n)]
    print(f"✓ Generated {n} random coefficients")

    # Compute TP = Σ(r_i * t_i)
    TP = None
    for i in range(n):
        r_i = coefficients[i]
        t_i = deserialize_g2_point(tags[i])
        term = multiply(t_i, r_i)
        if TP is None:
            TP = term
        else:
            TP = add(TP, term)

    print("✓ Computed TP (aggregated tags)")

    # Compute DP = Σ(r_i * b_i) mod p
    DP = 0
    for i in range(n):
        r_i = coefficients[i]
        b_i = int.from_bytes(chunks[i], 'big')
        DP = (DP + (r_i * b_i) % p) % p

    print(f"✓ Computed DP: {DP}")

    return TP, DP

# PROOF COMPUTATION FOR AUDIT

def compute_tp_dp_audit(chunks, tags, chal):
    """Compute TP and DP for audit based on challenge set."""
    print("\n Computing TP and DP for audit...")
    p = curve_order

    # Compute TP = Σ(r_i * t_i) for challenged blocks
    TP = None
    for challenge in chal:
        idx = challenge['i']
        r_i = challenge['ri']

        if idx >= len(tags):
            print(f" Warning: Tag index {idx} out of range")
            continue

        t_i = deserialize_g2_point(tags[idx])
        term = multiply(t_i, r_i)

        if TP is None:
            TP = term
        else:
            TP = add(TP, term)

    print(f"✓ Computed TP for {len(chal)} challenged blocks")

    # Compute DP = Σ(r_i * b_i) mod p for challenged blocks
    DP = 0
    for challenge in chal:
        idx = challenge['i']
        r_i = challenge['ri']

        if idx >= len(chunks):
            print(f" Warning: Chunk index {idx} out of range")
            continue

        b_i = int.from_bytes(chunks[idx], 'big')
        DP = (DP + (r_i * b_i) % p) % p

    print(f"✓ Computed DP: {DP}")

    return TP, DP

# TRANSACTION BROADCASTING

def broadcast_transaction_to_gm_network(transaction):
    """Broadcast transaction to all GM nodes (GM0 to GM6)."""
    print("\n Broadcasting transaction to CAB network...")
    gm_ports = [9001, 9011, 9012, 9013, 9014, 9015, 9016]  # GM0-GM6
    success_count = 0

    for port in gm_ports:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(2)
            client_socket.connect(("localhost", port))

            json_data = json.dumps(transaction)
            client_socket.sendall(json_data.encode('utf-8'))
            client_socket.sendall(b"\n\n")
            client_socket.close()

            success_count += 1
            print(f"✓ Sent to GM at port {port}")
        except Exception as e:
            print(f" Failed to send to GM at port {port}: {e}")

    print(f"✓ Transaction broadcast complete ({success_count}/{len(gm_ports)} successful)")

# CLIENT HANDLER

def handle_client(client_socket, csp_signing_key, gm_public_keys):
    """Handle incoming connection from GM."""
    try:
        # Receive data from GM
        print("\n Receiving message from GM...")
        data = b""
        while True:
            chunk = client_socket.recv(8192)
            if not chunk:
                break
            data += chunk
            if b"\n\n" in data:
                break

        data = data.replace(b"\n\n", b"")
        gm_message = json.loads(data.decode('utf-8'))

        operation = gm_message.get("operation")
        print("✓ Received message from GM")
        print(f"  - Operation: {operation}")
        print(f"  - GM ID: {gm_message.get('id_gm')}")
        print(f"  - File ID: {gm_message.get('id_file')}")

        # HANDLE INSERT OPERATION
        if operation == "insert":
            ts_ins = gm_message["ts_ins"]
            id_gm = gm_message["id_gm"]
            file_id = gm_message["id_file"]
            chunks_hex = gm_message["file_chunks"]
            tags = gm_message["tags"]
            file_hash = gm_message["file_hash"]
            sigma_gm = gm_message["sigma_gm"]

            print(f"  - Chunks: {len(chunks_hex)}")
            print(f"  - Tags: {len(tags)}")

            # STEP 1: Verify GM's signature (sigma_gm)
            print("\n Verifying GM signature...")
            sig_data = str(ts_ins)
            for tag in tags:
                sig_data += str(tag)

            gm_public_key = gm_public_keys.get(id_gm)
            if not gm_public_key:
                print(f"❌ Public key not found for {id_gm}")
                response = {"status": "error", "message": "GM public key not found"}
                client_socket.sendall(json.dumps(response).encode('utf-8'))
                client_socket.sendall(b"\n\n")
                return

            if not verify_signature_eddsa(gm_public_key, sig_data, sigma_gm):
                print(f"❌ GM signature verification failed!")
                response = {"status": "error", "message": "Invalid GM signature"}
                client_socket.sendall(json.dumps(response).encode('utf-8'))
                client_socket.sendall(b"\n\n")
                return

            print("✓ GM signature verified")

            # Deserialize chunks
            chunks = deserialize_chunks(chunks_hex)
            print(f"\n✓ Deserialized {len(chunks)} chunks")

            # STEP 2: Check file integrity via H(F)
            if not verify_file_integrity(chunks, file_hash):
                print(f"❌ File integrity check failed!")
                response = {"status": "error", "message": "File integrity verification failed"}
                client_socket.sendall(json.dumps(response).encode('utf-8'))
                client_socket.sendall(b"\n\n")
                return

            # STEP 3: Save file chunks and tags
            storage_dir = save_chunks_to_directory(chunks, file_id)
            tags_file = save_tags_to_file(tags, file_id)

            # Compute TP and DP (dummy proof)
            TP, DP = compute_tp_dp_insert(chunks, tags)
            tp_serialized = serialize_g2_point(TP)

            # STEP 4: Create TXres2ins transaction
            print("\n Creating TXres2ins transaction...")

            # Sign: σ_CSP = σ_cssk(1 || ts_ins)
            sig_data_csp = "1" + str(ts_ins)
            sigma_csp = sign_message_eddsa(csp_signing_key, sig_data_csp)

            tx_res2ins = {
                "tx_type": "TXres2ins",
                "id_csp": "CSP",
                "ts_ins": ts_ins,
                "id_gm": id_gm,
                "id_file": file_id,
                "result": 1,  # 1 indicates success
                "sigma_csp": sigma_csp.hex()
            }

            print(f"✓ Created TXres2ins transaction")
            print(f"  - Result: {tx_res2ins['result']}")
            print(f"  - Signature: {sigma_csp.hex()[:40]}...")

            # STEP 5: Broadcast TXres2ins to all GM nodes
            broadcast_transaction_to_gm_network(tx_res2ins)

            # Send response back to GM
            response = {
                "status": "success",
                "message": "File stored successfully",
                "storage_dir": storage_dir,
                "tags_file": tags_file,
                "tp": tp_serialized,
                "dp": DP
            }

            print("\n✅ File processed successfully")
            print(f"  - Storage: {storage_dir}")
            print(f"  - Tags: {tags_file}")

        # HANDLE AUDIT OPERATION
        elif operation == "audit":
            ts_aud = gm_message["ts_aud"]
            id_gm = gm_message["id_gm"]
            file_id = gm_message["id_file"]
            chal = gm_message["chal"]
            sigma_gm = gm_message["sigma_gm"]

            print(f"  - Challenged blocks: {len(chal)}")

            # STEP 1: Verify GM's signature
            print("\n Verifying GM signature...")
            sig_data = str(ts_aud) + str(chal)

            gm_public_key = gm_public_keys.get(id_gm)
            if not gm_public_key:
                print(f"❌ Public key not found for {id_gm}")
                response = {"status": "error", "message": "GM public key not found"}
                client_socket.sendall(json.dumps(response).encode('utf-8'))
                client_socket.sendall(b"\n\n")
                return

            if not verify_signature_eddsa(gm_public_key, sig_data, sigma_gm):
                print(f"❌ GM signature verification failed!")
                response = {"status": "error", "message": "Invalid GM signature"}
                client_socket.sendall(json.dumps(response).encode('utf-8'))
                client_socket.sendall(b"\n\n")
                return

            print("✓ GM signature verified")

            # STEP 2: Load stored chunks and tags
            chunks = load_chunks_from_directory(file_id)
            tags = load_tags_from_file(file_id)

            if chunks is None or tags is None:
                print(f"❌ File data not found for {file_id}")
                response = {"status": "error", "message": "File data not found"}
                client_socket.sendall(json.dumps(response).encode('utf-8'))
                client_socket.sendall(b"\n\n")
                return

            # STEP 3: Compute TP and DP based on challenge
            TP, DP = compute_tp_dp_audit(chunks, tags, chal)
            tp_serialized = serialize_g2_point(TP)

            # STEP 4: Create TXres2aud transaction
            print("\n Creating TXres2aud transaction...")

            # Sign: σ_CSP = σ_cssk(TP || DP || ts_aud)
            sig_data_csp = str(tp_serialized) + str(DP) + str(ts_aud)
            sigma_csp = sign_message_eddsa(csp_signing_key, sig_data_csp)

            tx_res2aud = {
                "tx_type": "TXres2aud",
                "id_csp": "CSP",
                "ts_aud": ts_aud,
                "id_gm": id_gm,
                "id_file": file_id,
                "tp": tp_serialized,
                "dp": DP,
                "sigma_csp": sigma_csp.hex()
            }

            print(f"✓ Created TXres2aud transaction")
            print(f"  - TP: {str(tp_serialized)[:60]}...")
            print(f"  - DP: {DP}")
            print(f"  - Signature: {sigma_csp.hex()[:40]}...")

            # STEP 5: Broadcast TXres2aud to all GM nodes
            broadcast_transaction_to_gm_network(tx_res2aud)

            # Send response back to GM
            response = {
                "status": "success",
                "message": "Audit proof generated",
                "tp": tp_serialized,
                "dp": DP
            }

            print("\n✅ Audit proof processed successfully")

        else:
            response = {
                "status": "error",
                "message": "Unknown operation"
            }

        # Send response
        response_json = json.dumps(response)
        client_socket.sendall(response_json.encode('utf-8'))
        client_socket.sendall(b"\n\n")
        print("✓ Sent response to GM")

    except Exception as e:
        print(f"❌ Error handling client: {e}")
        import traceback
        traceback.print_exc()

        # Send error response
        error_response = {
            "status": "error",
            "message": str(e)
        }
        try:
            client_socket.sendall(json.dumps(error_response).encode('utf-8'))
            client_socket.sendall(b"\n\n")
        except:
            pass

    finally:
        client_socket.close()

# SERVER STARTUP

def load_public_keys():
    """Load public keys for verification."""
    try:
        with open("public_keys.json", "r") as f:
            keys_data = json.load(f)

        public_keys = {}

        # Load GM public keys
        for gm_id in ["GM0", "GM1", "GM2", "GM3", "GM4", "GM5", "GM6"]:
            if gm_id in keys_data:
                public_keys[gm_id] = deserialize_public_key(keys_data[gm_id])
                print(f"✓ Loaded public key for {gm_id}")

        return public_keys

    except Exception as e:
        print(f"❌ Error loading public keys: {e}")
        return {}

def start_csp_server(host="localhost", port=9002):
    """Start CSP server to listen for GM requests."""
    try:
        # Load CSP signing key from local .env
        cssk_str = os.getenv("cssk")
        if not cssk_str:
            raise ValueError("CSP signing key 'cssk' not found in .env")
        csp_signing_key = deserialize_private_key(cssk_str.strip())
        print("✓ Loaded CSP signing key")

        # Load public keys for verification
        gm_public_keys = load_public_keys()

        # Create server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(5)

        print(f"\n CSP server started on {host}:{port}")
        print(" Waiting for GM connections...")

        while True:
            client_socket, addr = server_socket.accept()
            print(f"\n Connection from {addr}")

            # Handle each client in a separate thread
            threading.Thread(target=handle_client, args=(client_socket, csp_signing_key, gm_public_keys)).start()

    except KeyboardInterrupt:
        print("\n\n🛑 CSP server stopped")
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    start_csp_server()
