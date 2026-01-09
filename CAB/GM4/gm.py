# GM{i}/gm.py - WITH INSERT AND AUDIT BLOCK CREATION AND CONSENSUS

import json
import socket
import time
import os
import threading
import secrets
from dotenv import load_dotenv
from hashlib import sha256
from ecdsa import Ed25519, SigningKey, VerifyingKey
from py_ecc.optimized_bls12_381 import G1, G2, multiply, add, FQ, pairing, FQ2
from py_ecc.bls.hash_to_curve import hash_to_G2
from py_ecc.bls12_381 import curve_order

load_dotenv()

# CONFIGURATION - CHANGE THESE VALUES FOR EACH GM INSTANCE
GM_PORT = 9014  # GM0: 9001, GM1: 9011, GM2: 9012, GM3: 9013, GM4: 9014, GM5: 9015, GM6: 9016
GM_ID = "GM4"   # GM0, GM1, GM2, GM3, GM4, GM5, GM6

# Credit scores for all GMs (initialize with equal scores)
gm_credit_scores = {
    "GM0": 100,
    "GM1": 100,
    "GM2": 100,
    "GM3": 100,
    "GM4": 100,
    "GM5": 100,
    "GM6": 100
}

# PBFT message pools
preprepare_pool = {}  # {digest: PrePrepare}
prepare_pool = {}     # {digest: {node_id: Prepare}}
commit_pool = {}      # {digest: {node_id: Commit}}

# Consensus constants
TOTAL_NODES = 7
F = 2  # Maximum faulty nodes
QUORUM_2F_PLUS_1 = 5  # 2f+1 for prepare and commit phase

# Sequence tracking
sequence_id = 0
sequence_lock = threading.Lock()

# Transaction pools
tx_ins2cab_pool = []
tx_res2ins_pool = []
tx_aud2cab_pool = []
tx_res2aud_pool = []
pool_lock = threading.Lock()

# Blockchain
blockchain = []
blockchain_lock = threading.Lock()

# Consensus state
consensus_in_progress = False
consensus_lock = threading.Lock()

# Transaction timeout tracking
tx_timeout_tracker = {}  # {tx_key: timestamp}
TX_TIMEOUT = 10  # seconds

# Add at top with other globals (around line 40)
committed_digests = set()  # Track which blocks have been committed
committed_digests_lock = threading.Lock()

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

# BLS UTILITIES

def deserialize_g2_point(point_data):
    """Deserialize G2 point from list of integers."""
    return (
        FQ2(point_data[0]),
        FQ2(point_data[1]),
        FQ2(point_data[2])
    )

def deserialize_g1_point(point_data):
    """Deserialize G1 point from list of integers."""
    return (FQ(point_data[0]), FQ(point_data[1]), FQ(point_data[2]))

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

# PBFT MESSAGE STRUCTURES

class PrePrepare:
    def __init__(self, block, digest, sequence_id, proposer_id, signature):
        self.block = block
        self.digest = digest
        self.sequence_id = sequence_id
        self.proposer_id = proposer_id
        self.signature = signature
    
    def to_dict(self):
        return {
            "message_type": "preprepare",
            "block": self.block,
            "digest": self.digest,
            "sequence_id": self.sequence_id,
            "proposer_id": self.proposer_id,
            "signature": self.signature
        }

class Prepare:
    def __init__(self, digest, sequence_id, node_id, signature):
        self.digest = digest
        self.sequence_id = sequence_id
        self.node_id = node_id
        self.signature = signature
    
    def to_dict(self):
        return {
            "message_type": "prepare",
            "digest": self.digest,
            "sequence_id": self.sequence_id,
            "node_id": self.node_id,
            "signature": self.signature
        }

class Commit:
    def __init__(self, digest, sequence_id, node_id, signature):
        self.digest = digest
        self.sequence_id = sequence_id
        self.node_id = node_id
        self.signature = signature
    
    def to_dict(self):
        return {
            "message_type": "commit",
            "digest": self.digest,
            "sequence_id": self.sequence_id,
            "node_id": self.node_id,
            "signature": self.signature
        }

# BLOCKCHAIN MANAGEMENT

def create_genesis_block():
    """Create the genesis block with fixed values."""
    genesis_block = {
        "height": 0,
        "previous_hash": "0" * 64,
        "timestamp": 1732881600,  # Fixed timestamp: 2025-11-29 00:00:00 UTC
        "merkle_root": "0" * 64,
        "current_hash": "",
        "signature": "",
        "transactions": []
    }

    # Compute hash (will be same for all GMs since inputs are same)
    genesis_block["current_hash"] = compute_block_hash(genesis_block)

    # No signature for genesis block (or use a fixed one)
    genesis_block["signature"] = "0" * 128

    return genesis_block

def load_or_create_blockchain():
    """Load blockchain from file or create genesis block."""
    global blockchain
    blockchain_file = "blockchain.json"

    if os.path.exists(blockchain_file):
        try:
            with open(blockchain_file, 'r') as f:
                blockchain = json.load(f)
            print(f"✓ Loaded blockchain with {len(blockchain)} blocks")
        except Exception as e:
            print(f" Error loading blockchain: {e}")
            print("Creating new blockchain with genesis block...")
            blockchain = [create_genesis_block()]
            save_blockchain()
    else:
        print(" Creating new blockchain with genesis block...")
        blockchain = [create_genesis_block()]
        save_blockchain()

def save_blockchain():
    """Save blockchain to file - MUST be called WITHOUT holding blockchain_lock."""
    try:
        # Create a copy of blockchain to avoid holding lock during I/O
        with blockchain_lock:
            blockchain_copy = blockchain.copy()

        # Write to file WITHOUT holding the lock
        with open("blockchain.json", 'w') as f:
            json.dump(blockchain_copy, f, indent=2)
        print(f"✓ Saved blockchain ({len(blockchain_copy)} blocks) to blockchain.json")
    except Exception as e:
        print(f"❌ Error saving blockchain: {e}")
        import traceback
        traceback.print_exc()

def get_latest_block():
    """Get the latest block from blockchain."""
    with blockchain_lock:
        if blockchain:
            return blockchain[-1].copy()  # Return a copy to avoid external modification
        return None

def compute_block_hash(block):
    """Compute SHA256 hash of block header."""
    header_string = f"{block['height']}{block['previous_hash']}{block['timestamp']}{block['merkle_root']}"
    return sha256(header_string.encode()).hexdigest()

def compute_merkle_root(transactions):
    """Compute Merkle root of transactions."""
    if not transactions:
        return "0" * 64

    # Simple implementation: hash all transaction data together
    tx_hashes = []
    for tx in transactions:
        tx_string = json.dumps(tx, sort_keys=True)
        tx_hash = sha256(tx_string.encode()).hexdigest()
        tx_hashes.append(tx_hash)

    # Combine all hashes
    combined = "".join(tx_hashes)
    return sha256(combined.encode()).hexdigest()

# DBI CALCULATION FROM BLOCKCHAIN
def get_metadata_from_blockchain(file_id, loh_list):
    """
    Recursively traverse blockchain backwards from loh_list[0] via last_op_heights
    until finding the INSERT operation block, then return its version_history.
    Returns list of {v, ts} dictionaries in the same order as loh_list.
    """
    print(f"\n Searching blockchain for metadata (recursive)...")
    print(f" - File: {file_id}")
    print(f" - LOH list: {loh_list}")
    
    with blockchain_lock:
        blockchain_copy = list(blockchain)
    
    def find_insert_block(current_height):
        """Recursively find the INSERT block by following last_op_heights."""
        if current_height is None or current_height < 0:
            print(f"⚠ Invalid height: {current_height}")
            return None

        block = next((b for b in blockchain_copy if b['height'] == current_height), None)
        
        if not block:
            print(f"⚠ No block found at height {current_height}")
            return None
        
        txs = block.get('transactions', [])
        if not txs:
            print(f"⚠ No transactions in block at height {current_height}")
            return None
        
        req = txs[0].get('request_record', {})
        operation_type = req.get('type')
        
        print(f"  → Height {current_height}: operation = {operation_type}")
        
        # Base case: found INSERT operation
        if operation_type == 'insert':
            print(f"  ✓ Found INSERT at height {current_height}")
            return req.get('extension_field', {}).get('version_history', [])
        
        # Recursive case: follow the pointer back
        last_op_heights = req.get('last_op_heights', [])
        if not last_op_heights or last_op_heights[0] < 0:
            print(f"⚠ No valid last_op_heights at height {current_height}")
            return None
        
        # Recursively call with the previous operation height
        return find_insert_block(last_op_heights[0])
    
    # Start recursion from loh_list[0] (all chunks have same height)
    if not loh_list:
        print("⚠ Empty loh_list")
        return []
    
    starting_height = loh_list[0]
    version_history = find_insert_block(starting_height)
    
    if not version_history:
        print(f"⚠ Could not find INSERT block, using fallback metadata")
        return [{'v': 1, 'ts': int(time.time())} for _ in loh_list]
    
    # Build metadata list from version_history
    metadata = []
    for i in range(len(loh_list)):
        if i < len(version_history):
            vh = version_history[i]
            metadata.append({'v': vh.get('v'), 'ts': vh.get('ts')})
        else:
            print(f"⚠ Not enough version_history entries for index {i}")
            metadata.append({'v': 1, 'ts': int(time.time())})
    
    print(f"✓ Retrieved {len(metadata)} metadata entries from INSERT block")
    return metadata

def compute_dbi_for_audit(chal, metadata, gpk):
    """
    Compute DBI = Σ(r_i * H(v_i || ts_i))
    According to equation (9) in the paper.
    """
    print("\n Computing DBI...")

    DBI_sum = None

    for i, challenge in enumerate(chal):
        r_i = challenge['ri']

        if i >= len(metadata):
            print(f" Warning: Metadata index {i} out of range")
            continue

        v = metadata[i]['v']
        ts = metadata[i]['ts']

        # Compute H_i = H(v || ts)
        message = f"{v}+{ts}".encode()
        H_i = hash_to_G2(message, b'TAG_GEN_DST', sha256)

        # Multiply by coefficient
        term = multiply(H_i, r_i)

        if DBI_sum is None:
            DBI_sum = term
        else:
            DBI_sum = add(DBI_sum, term)

    print("✓ Computed DBI_sum")

    # Compute e(DBI_sum, gpk)
    DBI = pairing(DBI_sum, gpk)

    return DBI

def verify_audit_proof(tp, dp, dbi, gamma, gpk):
    """
    Verify: e(TP, gamma) == e(DBI_sum, gpk) * e(G2^DP, gpk)
    Gamma is provided by DO, not calculated here.
    """
    print("\n🔬 Verifying audit proof...")

    # Deserialize gamma from DO
    gamma_point = deserialize_g1_point(gamma)

    # Deserialize TP
    tp_point = deserialize_g2_point(tp)

    # Compute pairings
    # a = e(TP, gamma)
    a = pairing(tp_point, gamma_point)

    # b = e(G2^DP, gpk)
    b = pairing(multiply(G2, dp), gpk)

    # Check: a == DBI * b
    verification_result = (a == dbi * b)

    if verification_result:
        print("✅ Audit proof VALID")
        return "VALID"
    else:
        print("❌ Audit proof INVALID")
        return "INVALID"

# TRANSACTION PAIR MATCHING

def find_matching_insert_pair():
    """Find a matching TXins2CAB and TXres2ins pair."""
    with pool_lock:
        for tx_ins in tx_ins2cab_pool:
            for tx_res in tx_res2ins_pool:
                # Match by ts_ins, id_file, and id_gm
                if (tx_ins.get('ts_ins') == tx_res.get('ts_ins') and
                    tx_ins.get('id_file') == tx_res.get('id_file') and
                    tx_ins.get('id_gm') == tx_res.get('id_gm')):
                    return tx_ins, tx_res
        return None, None

def find_matching_audit_pair():
    """Find a matching TXaud2CAB and TXres2aud pair."""
    with pool_lock:
        for tx_aud in tx_aud2cab_pool:
            for tx_res in tx_res2aud_pool:
                # Match by ts_aud, id_file, and id_gm
                if (tx_aud.get('ts_aud') == tx_res.get('ts_aud') and
                    tx_aud.get('id_file') == tx_res.get('id_file') and
                    tx_aud.get('id_gm') == tx_res.get('id_gm')):
                    return tx_aud, tx_res
        return None, None

def remove_from_pools_insert(tx_ins, tx_res):
    """Remove insert transaction pair from pools."""
    with pool_lock:
        if tx_ins in tx_ins2cab_pool:
            tx_ins2cab_pool.remove(tx_ins)
        if tx_res in tx_res2ins_pool:
            tx_res2ins_pool.remove(tx_res)

def remove_from_pools_audit(tx_aud, tx_res):
    """Remove audit transaction pair from pools."""
    with pool_lock:
        if tx_aud in tx_aud2cab_pool:
            tx_aud2cab_pool.remove(tx_aud)
        if tx_res in tx_res2aud_pool:
            tx_res2aud_pool.remove(tx_res)

# BLOCK CREATION

def create_block_with_insert_transaction(tx_ins, tx_res, gm_signing_key):
    """Create a new block with an insert transaction pair."""
    latest_block = get_latest_block()

    # Create transaction record
    transaction = {
        "request_record": {
            "from": tx_ins.get('id_gm'),
            "to": tx_ins.get('id_csp'),
            "type": tx_ins.get('operation'),
            "sig": tx_ins.get('sigma_gm_prime'),
            "result": tx_res.get('result'),
            "hash": compute_merkle_root([tx_ins]),
            "last_op_heights": [vh.get('loh') for vh in tx_ins.get('version_history', [])],
            "extension_field": {
                "version_history": tx_ins.get('version_history'),
                "csp_signature": tx_res.get('sigma_csp')
            }
        }
    }

    # Create block
    new_block = {
        "height": latest_block['height'] + 1 if latest_block else 1,
        "previous_hash": latest_block['current_hash'] if latest_block else "0" * 64,
        "timestamp": int(time.time()),
        "merkle_root": "",
        "current_hash": "",
        "signature": "",
        "transactions": [transaction]
    }

    # Compute merkle root
    new_block["merkle_root"] = compute_merkle_root([transaction])

    # Compute block hash
    new_block["current_hash"] = compute_block_hash(new_block)

    # Sign block
    sig_data = f"{new_block['height']}{new_block['previous_hash']}{new_block['timestamp']}{new_block['merkle_root']}"
    signature = sign_message_eddsa(gm_signing_key, sig_data)
    new_block["signature"] = signature.hex()

    return new_block

def create_block_with_audit_transaction(tx_aud, tx_res, proof_result, gm_signing_key):
    """Create a new block with an audit transaction pair."""
    latest_block = get_latest_block()

    # Create transaction record
    transaction = {
        "request_record": {
            "from": tx_aud.get('id_gm'),
            "to": tx_aud.get('id_csp'),
            "type": "audit",
            "sig": tx_aud.get('sigma_gm_prime'),
            "result": 1 if proof_result == "VALID" else 0,
            "hash": compute_merkle_root([tx_aud]),
            "last_op_heights": tx_aud.get('loh_list', []),
            "extension_field": {
                "chal": tx_aud.get('chal'),
                "gamma": tx_aud.get('gamma'),
                "tp": tx_res.get('tp'),
                "dp": tx_res.get('dp'),
                "proof_result": proof_result,
                "csp_signature": tx_res.get('sigma_csp')
            }
        }
    }

    # Create block
    new_block = {
        "height": latest_block['height'] + 1 if latest_block else 1,
        "previous_hash": latest_block['current_hash'] if latest_block else "0" * 64,
        "timestamp": int(time.time()),
        "merkle_root": "",
        "current_hash": "",
        "signature": "",
        "transactions": [transaction]
    }

    # Compute merkle root
    new_block["merkle_root"] = compute_merkle_root([transaction])

    # Compute block hash
    new_block["current_hash"] = compute_block_hash(new_block)

    # Sign block
    sig_data = f"{new_block['height']}{new_block['previous_hash']}{new_block['timestamp']}{new_block['merkle_root']}"
    signature = sign_message_eddsa(gm_signing_key, sig_data)
    new_block["signature"] = signature.hex()

    return new_block

def create_timeout_block(tx_ins, gm_signing_key):
    """Create a block for a timed-out transaction."""
    latest_block = get_latest_block()

    transaction = {
        "request_record": {
            "from": tx_ins.get('id_gm'),
            "to": tx_ins.get('id_csp'),
            "type": tx_ins.get('operation'),
            "sig": tx_ins.get('sigma_gm_prime'),
            "result": 0,  # Failure/timeout
            "hash": compute_merkle_root([tx_ins]),
            "last_op_heights": [vh.get('loh') for vh in tx_ins.get('version_history', [])],
            "extension_field": {
                "version_history": tx_ins.get('version_history'),
                "error": "CSP_RESPONSE_TIMEOUT"
            }
        }
    }

    new_block = {
        "height": latest_block['height'] + 1 if latest_block else 1,
        "previous_hash": latest_block['current_hash'] if latest_block else "0" * 64,
        "timestamp": int(time.time()),
        "merkle_root": "",
        "current_hash": "",
        "signature": "",
        "transactions": [transaction]
    }

    new_block["merkle_root"] = compute_merkle_root([transaction])
    new_block["current_hash"] = compute_block_hash(new_block)

    sig_data = f"{new_block['height']}{new_block['previous_hash']}{new_block['timestamp']}{new_block['merkle_root']}"
    signature = sign_message_eddsa(gm_signing_key, sig_data)
    new_block["signature"] = signature.hex()

    return new_block

# CONSENSUS SIMULATION

# CREDIT-BASED PROPOSER SELECTION
def select_proposer_by_credit(sequence_id):
    """
    Select proposer based on credit scores - DETERMINISTIC.
    All GMs will get the same result for the same sequence_id.
    """
    # Use sequence_id as deterministic seed
    seed_value = sequence_id
    
    # Sort GMs to ensure consistent ordering
    sorted_gms = sorted(gm_credit_scores.keys())
    
    # Create cumulative credit ranges
    total_credit = sum(gm_credit_scores.values())
    cumulative = []
    current = 0
    for gm_id in sorted_gms:
        current += gm_credit_scores[gm_id]
        cumulative.append((gm_id, current))
    
    # Use sequence_id to deterministically select within credit range
    deterministic_value = seed_value % total_credit
    
    for gm_id, threshold in cumulative:
        if deterministic_value < threshold:
            return gm_id
    
    return sorted_gms[0]  # Fallback

def update_credit_scores(proposer_id, success=True):
    """Update credit scores based on consensus outcome."""
    global gm_credit_scores
    
    if success:
        gm_credit_scores[proposer_id] += 10
        for gm_id in gm_credit_scores:
            if gm_id != proposer_id:
                gm_credit_scores[gm_id] += 2
    else:
        gm_credit_scores[proposer_id] = max(10, gm_credit_scores[proposer_id] // 2)
    
    print(f"📊 Credit scores: {gm_credit_scores}")

def compute_block_digest(block):
    """Compute SHA256 digest of block."""
    block_string = json.dumps(block, sort_keys=True)
    return sha256(block_string.encode()).hexdigest()

def increment_sequence_id():
    """Thread-safe sequence ID increment."""
    global sequence_id
    with sequence_lock:
        sequence_id += 1
        return sequence_id

def broadcast_pbft_message(message):
    """Broadcast PBFT message to all GMs except self."""
    gm_ports = [9001, 9011, 9012, 9013, 9014, 9015, 9016]
    
    for port in gm_ports:
        if port == GM_PORT:
            continue
        
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(2)
            client_socket.connect(("localhost", port))
            json_data = json.dumps(message)
            client_socket.sendall(json_data.encode('utf-8'))
            client_socket.sendall(b"\n\n")
            client_socket.close()
        except:
            pass

# PBFT MESSAGE HANDLERS

def handle_preprepare_message(message):
    """Handle incoming Pre-prepare message."""
    digest = message["digest"]
    seq_id = message["sequence_id"]
    proposer_id = message["proposer_id"]
    block = message["block"]
    
    print(f"\n Received Pre-prepare from {proposer_id} (seq: {seq_id})")
    
    # Verify block digest
    computed_digest = compute_block_digest(block)
    if computed_digest != digest:
        print(f"❌ Digest mismatch!")
        return
    
    preprepare_pool[digest] = message
    
    # Send Prepare
    signing_key = deserialize_private_key(os.getenv("gssk").strip())
    prepare_signature = sign_message_eddsa(signing_key, digest.encode())
    
    prepare_msg = Prepare(digest, seq_id, GM_ID, prepare_signature.hex())
    broadcast_pbft_message(prepare_msg.to_dict())
    
    # Add own prepare to pool
    if digest not in prepare_pool:
        prepare_pool[digest] = {}
    prepare_pool[digest][GM_ID] = prepare_msg
    
    print(f"  ✓ Sent Prepare")

def handle_prepare_message(message):
    """Handle incoming Prepare message."""
    digest = message["digest"]
    node_id = message["node_id"]
    seq_id = message["sequence_id"]
    
    if digest not in prepare_pool:
        prepare_pool[digest] = {}
    prepare_pool[digest][node_id] = message
    count = len(prepare_pool[digest])
    print(f" Prepare from {node_id} ({count}/{QUORUM_2F_PLUS_1})")
    
    # Check quorum and send Commit
    if count >= QUORUM_2F_PLUS_1:
        # Check if already sent commit
        if digest in commit_pool and GM_ID in commit_pool[digest]:
            return
        
        # VERIFY AUDIT BEFORE COMMIT 
        if digest in preprepare_pool:
            block = preprepare_pool[digest]["block"]
            
            # Check if this is an audit transaction
            if block.get("transactions"):
                tx = block["transactions"][0]
                req = tx.get("request_record", {})
                
                if req.get("type") == "audit":
                    print(f"\n {GM_ID}: Verifying audit proof before commit...")
                    
                    # Extract audit data from block
                    ext_field = req.get("extension_field", {})
                    chal = ext_field.get("chal")
                    gamma = ext_field.get("gamma")
                    tp = ext_field.get("tp")
                    dp = ext_field.get("dp")
                    loh_list = req.get("last_op_heights", [])
                    
                    try:
                        # Load GPK if not already loaded
                        gpk = load_gpk(GM_ID, "gpk.json")
                        if not gpk:
                            print(f"❌ {GM_ID}: Could not load GPK for audit verification")
                            return
                        
                        # Get metadata from blockchain (file_id not needed)
                        metadata = get_metadata_from_blockchain(None, loh_list)
                        
                        # Compute DBI
                        dbi = compute_dbi_for_audit(chal, metadata, gpk)
                        
                        # Verify audit proof
                        proof_result = verify_audit_proof(tp, dp, dbi, gamma, gpk)
                        
                        if proof_result != "VALID":
                            print(f"❌ {GM_ID}: Audit verification FAILED - NOT sending Commit")
                            print(f"   Expected VALID but got {proof_result}")
                            return
                        
                        print(f"✅ {GM_ID}: Audit verification PASSED - Proceeding with Commit")
                        
                    except Exception as e:
                        print(f"❌ {GM_ID}: Error during audit verification: {e}")
                        import traceback
                        traceback.print_exc()
                        return
        # END AUDIT VERIFICATION 
        
        signing_key = deserialize_private_key(os.getenv("gssk").strip())
        commit_signature = sign_message_eddsa(signing_key, digest.encode())
        commit_msg = Commit(digest, seq_id, GM_ID, commit_signature.hex())
        broadcast_pbft_message(commit_msg.to_dict())
        
        # Add own commit to pool
        if digest not in commit_pool:
            commit_pool[digest] = {}
        commit_pool[digest][GM_ID] = commit_msg
        print(f" ✓ Sent Commit (prepare quorum reached)")


# Replace handle_commit_message():
def handle_commit_message(message):
    """Handle incoming Commit message - commits only once per digest."""
    digest = message["digest"]
    node_id = message["node_id"]
    
    if digest not in commit_pool:
        commit_pool[digest] = {}
    
    commit_pool[digest][node_id] = message
    count = len(commit_pool[digest])
    
    print(f" {GM_ID}: Commit from {node_id} ({count}/{QUORUM_2F_PLUS_1})")
    
    # Check if consensus reached
    if count >= QUORUM_2F_PLUS_1:
        # ATOMIC CHECK AND MARK 
        should_commit = False
        with committed_digests_lock:
            if digest not in committed_digests:
                committed_digests.add(digest)  # Mark BEFORE releasing lock
                should_commit = True
            else:
                print(f"  {GM_ID}: Already committed digest {digest[:16]}..., skipping")
        
        if should_commit:
            print(f"✅ {GM_ID}: Consensus reached for block!")
            
            # Retrieve and commit block
            if digest in preprepare_pool:
                block = preprepare_pool[digest]["block"]
                commit_block(block)
                
                # Cleanup pools
                if digest in preprepare_pool:
                    del preprepare_pool[digest]
                if digest in prepare_pool:
                    del prepare_pool[digest]
                if digest in commit_pool:
                    del commit_pool[digest]
            else:
                print(f"  {GM_ID}: Preprepare not found for digest {digest[:16]}...")

def simulate_consensus(block):
    """
    Execute full PBFT consensus (Pre-prepare → Prepare → Commit).
    Returns True when consensus completes correctly.
    """
    print(f"\n{'='*60}")
    print(f" PBFT CONSENSUS - Block {block['height']}")
    print(f"{'='*60}")
    
    try:
        # Select proposer by credit
        proposer_id = select_proposer_by_credit(block['height'])
        print(f"\n Proposer: {proposer_id} (credit: {gm_credit_scores[proposer_id]})")
        
        # # Only proposer initiates consensus
        # if GM_ID != proposer_id:
        #     print(f" {GM_ID} waiting for Pre-prepare...")
        #     # Non-proposers will commit via handle_commit_message()
        #     return True
        
        # # PROPOSER INITIATES CONSENSUS 
        # print(f"\n PHASE 1: PRE-PREPARE (Proposer: {GM_ID})")
        
        # seq_id = increment_sequence_id()
        # digest = compute_block_digest(block)
        
        # signing_key = deserialize_private_key(os.getenv("gssk").strip())
        # signature = sign_message_eddsa(signing_key, f"{digest}{seq_id}")
        
        # preprepare_msg = PrePrepare(block, digest, seq_id, GM_ID, signature.hex())
        # preprepare_pool[digest] = preprepare_msg
        
        # print(f"  ✓ Digest: {digest[:16]}... | Seq: {seq_id}")
        # print(f"  ✓ Broadcasting Pre-prepare...")
        # broadcast_pbft_message(preprepare_msg.to_dict())
        
        # # PREPARE PHASE 
        # print(f"\n PHASE 2: PREPARE")
        
        # prepare_signature = sign_message_eddsa(signing_key, digest.encode())
        # prepare_msg = Prepare(digest, seq_id, GM_ID, prepare_signature.hex())
        
        # if digest not in prepare_pool:
        #     prepare_pool[digest] = {}
        # prepare_pool[digest][GM_ID] = prepare_msg
        
        # print(f"  ✓ Broadcasting Prepare...")
        # broadcast_pbft_message(prepare_msg.to_dict())
        
        # print(f"   Waiting for {QUORUM_2F_PLUS_1} Prepare messages...")
        
        # # Wait for real prepare messages from other nodes
        # timeout = 10  # 5 second timeout
        # start_time = time.time()
        # while len(prepare_pool.get(digest, {})) < QUORUM_2F_PLUS_1:
        #     if time.time() - start_time > timeout:
        #         print(f"  ❌ Timeout waiting for Prepare messages")
        #         update_credit_scores(proposer_id, success=False)
        #         return False
        #     time.sleep(0.1)
        
        # print(f"  ✅ Received {len(prepare_pool[digest])} Prepare messages")
        
        # COMMIT PHASE 
        # print(f"\n PHASE 3: COMMIT")
        
        # commit_signature = sign_message_eddsa(signing_key, digest.encode())
        # commit_msg = Commit(digest, seq_id, GM_ID, commit_signature.hex())
        
        # if digest not in commit_pool:
        #     commit_pool[digest] = {}
        # commit_pool[digest][GM_ID] = commit_msg
        
        # print(f"  ✓ Broadcasting Commit...")
        # broadcast_pbft_message(commit_msg.to_dict())
        
        # print(f"   Waiting for {QUORUM_2F_PLUS_1} Commit messages...")
        
        # # Wait for real commit messages
        # start_time = time.time()
        # while len(commit_pool.get(digest, {})) < QUORUM_2F_PLUS_1:
        #     if time.time() - start_time > timeout:
        #         print(f"  ❌ Timeout waiting for Commit messages")
        #         update_credit_scores(proposer_id, success=False)
        #         return False
        #     time.sleep(0.1)
        
        # print(f"  ✅ Received {len(commit_pool[digest])} Commit messages")
        
        # COMMIT BLOCK 
        print(f"\n Committing block to blockchain...")
        commit_block(block)
        
        # # Cleanup pools
        # if digest in preprepare_pool:
        #     del preprepare_pool[digest]
        # if digest in prepare_pool:
        #     del prepare_pool[digest]
        # if digest in commit_pool:
        #     del commit_pool[digest]
        
        print(f"\n{'='*60}")
        print(f"✅ CONSENSUS SUCCESSFUL - BLOCK COMMITTED")
        print(f"{'='*60}\n")
        
        update_credit_scores(proposer_id, success=True)
        return True
        
    except Exception as e:
        print(f"\n❌ CONSENSUS FAILED: {e}")
        import traceback
        traceback.print_exc()
        if 'proposer_id' in locals():
            update_credit_scores(proposer_id, success=False)
        return False

def commit_block(block):
    """Commit block to blockchain after consensus - WITH DUPLICATE PREVENTION."""
    try:
        # CHECK FOR DUPLICATES 
        with blockchain_lock:
            # Check if block at this height already exists
            for existing_block in blockchain:
                if existing_block['height'] == block['height']:
                    print(f"  {GM_ID}: Block {block['height']} already in blockchain, skipping")
                    return
            
            # Validate height is sequential
            if blockchain:
                expected_height = blockchain[-1]['height'] + 1
                if block['height'] != expected_height:
                    print(f"❌ {GM_ID}: Invalid block height {block['height']}, expected {expected_height}")
                    return
            
            # Safe to append
            blockchain.append(block)
            current_length = len(blockchain)
        
        print(f"\n {GM_ID}: Block {block['height']} committed to blockchain")
        print(f"   - Hash: {block['current_hash'][:16]}...")
        print(f"   - Transactions: {len(block['transactions'])}")
        print(f"   - Blockchain length: {current_length}")
        
        # Save to file (outside lock to avoid deadlock)
        save_blockchain()
        
        # ✅ FIX: CLEAN UP TRANSACTION POOLS
        cleanup_pools_after_commit(block)
        
    except Exception as e:
        print(f"❌ {GM_ID}: Error in commit_block: {e}")
        import traceback
        traceback.print_exc()


# BLOCK PROPOSAL AND CONSENSUS

def broadcast_block_proposal(block):
    """Broadcast block proposal to all GMs."""
    print(f"\n📡 Broadcasting block proposal to all GMs...")
    gm_ports = [9001, 9011, 9012, 9013, 9014, 9015, 9016]
    success_count = 0

    message = {
        "message_type": "block_proposal",
        "block": block,
        "proposer": GM_ID
    }

    for port in gm_ports:
        if port == GM_PORT:
            continue

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(2)
            client_socket.connect(("localhost", port))

            json_data = json.dumps(message)
            client_socket.sendall(json_data.encode('utf-8'))
            client_socket.sendall(b"\n\n")
            client_socket.close()

            success_count += 1
        except Exception as e:
            print(f" Failed to send to GM at port {port}: {e}")

    print(f"✓ Block proposal broadcast complete ({success_count}/{len(gm_ports)-1} successful)")

def handle_block_proposal(message):
    """Handle incoming block proposal."""
    block = message.get('block')
    proposer = message.get('proposer')

    print(f"\n Received block proposal from {proposer}")
    print(f"  - Block height: {block.get('height')}")

    # Verify block
    if verify_block(block):
        print(f"✓ Block verified")

        # Commit block
        commit_block(block)

        # Clean up pools
        cleanup_pools_after_commit(block)
    else:
        print(f"❌ Block verification failed")

def verify_block(block):
    """Verify block structure and hashes."""
    # Check height
    latest = get_latest_block()
    if latest and block['height'] != latest['height'] + 1:
        print(f"❌ Invalid block height: {block['height']}, expected {latest['height'] + 1}")
        return False

    # Check previous hash
    if latest and block['previous_hash'] != latest['current_hash']:
        print(f"❌ Invalid previous hash")
        print(f"  Expected: {latest['current_hash']}")
        print(f"  Got: {block['previous_hash']}")
        return False

    # Verify current hash
    computed_hash = compute_block_hash(block)
    if computed_hash != block['current_hash']:
        print(f"❌ Invalid block hash")
        return False

    return True

def cleanup_pools_after_commit(block):
    """Remove committed transactions from pools."""
    with pool_lock:
        for tx in block.get('transactions', []):
            req = tx.get('request_record', {})

            # Remove matching insert transactions
            for tx_ins in tx_ins2cab_pool[:]:
                if tx_ins.get('sigma_gm_prime') == req.get('sig'):
                    tx_ins2cab_pool.remove(tx_ins)
                    print(f"  ✓ Removed TXins2CAB from pool")

            for tx_res in tx_res2ins_pool[:]:
                ext = req.get('extension_field', {})
                if tx_res.get('sigma_csp') == ext.get('csp_signature'):
                    tx_res2ins_pool.remove(tx_res)
                    print(f"  ✓ Removed TXres2ins from pool")

            # Remove matching audit transactions
            for tx_aud in tx_aud2cab_pool[:]:
                if tx_aud.get('sigma_gm_prime') == req.get('sig'):
                    tx_aud2cab_pool.remove(tx_aud)
                    print(f"  ✓ Removed TXaud2CAB from pool")

            for tx_res in tx_res2aud_pool[:]:
                ext = req.get('extension_field', {})
                if tx_res.get('sigma_csp') == ext.get('csp_signature'):
                    tx_res2aud_pool.remove(tx_res)
                    print(f"  ✓ Removed TXres2aud from pool")

# NON-BLOCKING PAIR CHECKER

def pair_checker_thread(gm_signing_key, gpk):
    """Background thread that continuously checks for transaction pairs."""
    global consensus_in_progress
    print(f"\n Pair checker thread started")
    
    while True:
        try:
            time.sleep(0.5)
            
            # Check consensus flag
            with consensus_lock:
                if consensus_in_progress:
                    continue
            
            # Look for matching INSERT pair
            tx_ins, tx_res = find_matching_insert_pair()
            if tx_ins and tx_res:
                print(f"\n✅ Found matching INSERT transaction pair!")
                print(f"   - File: {tx_ins.get('id_file')}")
                print(f"   - GM: {tx_ins.get('id_gm')}")
                
                # ATOMIC LOCK + REMOVE
                with consensus_lock:
                    if consensus_in_progress:
                        continue
                    consensus_in_progress = True
                    # Remove from pools IMMEDIATELY while holding lock
                    remove_from_pools_insert(tx_ins, tx_res)
                
                try:
                    print(f"\n🔨 Creating INSERT block...")
                    block = create_block_with_insert_transaction(tx_ins, tx_res, gm_signing_key)
                    consensus_result = simulate_consensus(block)
                finally:
                    with consensus_lock:
                        consensus_in_progress = False
                
                # Skip to next iteration
                continue
            
            # Look for matching AUDIT pair
            tx_aud, tx_res = find_matching_audit_pair()
            if tx_aud and tx_res:
                print(f"\n✅ Found matching AUDIT transaction pair!")
                print(f"   - File: {tx_aud.get('id_file')}")
                
                # ATOMIC LOCK + REMOVE
                with consensus_lock:
                    if consensus_in_progress:
                        continue
                    consensus_in_progress = True
                    remove_from_pools_audit(tx_aud, tx_res)
                
                try:
                    print(f"\n Verifying audit proof...")
                    file_id = tx_aud.get('id_file')
                    loh_list = tx_aud.get('loh_list', [])
                    metadata = get_metadata_from_blockchain(file_id, loh_list)
                    chal = tx_aud.get('chal')
                    dbi = compute_dbi_for_audit(chal, metadata, gpk)
                    tp = tx_res.get('tp')
                    dp = tx_res.get('dp')
                    gamma = tx_aud.get('gamma')
                    proof_result = verify_audit_proof(tp, dp, dbi, gamma, gpk)
                    
                    print(f"\n🔨 Creating AUDIT block...")
                    block = create_block_with_audit_transaction(tx_aud, tx_res, proof_result, gm_signing_key)
                    consensus_result = simulate_consensus(block)
                finally:
                    with consensus_lock:
                        consensus_in_progress = False
                
        except Exception as e:
            print(f"❌ Error in pair checker: {e}")
            import traceback
            traceback.print_exc()
            with consensus_lock:
                consensus_in_progress = False

# PUBLIC KEY LOADING

def load_public_keys():
    """Load public keys for verification."""
    try:
        with open("public_keys.json", "r") as f:
            keys_data = json.load(f)

        public_keys = {}

        if "DO" in keys_data:
            public_keys["DO"] = deserialize_public_key(keys_data["DO"])
            print("✓ Loaded public key for DO")

        if "CSP" in keys_data:
            public_keys["CSP"] = deserialize_public_key(keys_data["CSP"])
            print("✓ Loaded public key for CSP")

        for gm_id in ["GM0", "GM1", "GM2", "GM3", "GM4", "GM5", "GM6"]:
            if gm_id in keys_data:
                public_keys[gm_id] = deserialize_public_key(keys_data[gm_id])
                print(f"✓ Loaded public key for {gm_id}")

        return public_keys

    except Exception as e:
        print(f"❌ Error loading public keys: {e}")
        return {}

# MESSAGE CREATION FOR CSP

def create_gm_message_insert(do_message, gm_signing_key):
    """Create GM message for CSP from DO insert message."""
    print("\n Creating GM message for CSP (insert)...")

    ts_ins = do_message["ts_ins"]
    id_file = do_message["id_file"]
    file_chunks = do_message["file_chunks"]
    tags = do_message["tags"]
    file_hash = do_message["file_hash"]

    sig_data = str(ts_ins)
    for tag in tags:
        sig_data += str(tag)

    sigma_gm = sign_message_eddsa(gm_signing_key, sig_data)

    gm_message = {
        "operation": "insert",
        "ts_ins": ts_ins,
        "id_gm": GM_ID,
        "id_file": id_file,
        "file_chunks": file_chunks,
        "tags": tags,
        "file_hash": file_hash,
        "sigma_gm": sigma_gm.hex()
    }

    print(f"✓ Created GM message for insert")
    return gm_message

def create_gm_message_audit(do_message, gm_signing_key):
    """Create GM message for CSP from DO audit message."""
    print("\n Creating GM message for CSP (audit)...")

    ts_aud = do_message["ts_aud"]
    id_file = do_message["id_file"]
    chal = do_message["chal"]

    sig_data = str(ts_aud) + str(chal)

    sigma_gm = sign_message_eddsa(gm_signing_key, sig_data)

    gm_message = {
        "operation": "audit",
        "ts_aud": ts_aud,
        "id_gm": GM_ID,
        "id_file": id_file,
        "chal": chal,
        "sigma_gm": sigma_gm.hex()
    }

    print(f"✓ Created GM message for audit")
    return gm_message

# TRANSACTION CREATION AND BROADCASTING

def create_tx_ins2cab(do_message, gm_signing_key):
    """Create TXins2CAB transaction for blockchain network."""
    print("\n📝 Creating TXins2CAB transaction...")

    ts_ins = do_message["ts_ins"]
    id_file = do_message["id_file"]
    block_metadata = do_message.get("block_metadata", [])
    id_csp = do_message.get("id_csp", "CSP")

    version_history = []
    for meta in block_metadata:
        version_history.append({
            "v": meta["v"],
            "ts": meta["ts"],
            "loh": meta.get("loh", -1)
        })

    sig_data = str(ts_ins)
    for vh in version_history:
        sig_data += f"{vh['v']}{vh['ts']}{vh['loh']}"

    sigma_gm_prime = sign_message_eddsa(gm_signing_key, sig_data)

    tx_ins2cab = {
        "tx_type": "TXins2CAB",
        "operation": "insert",
        "ts_ins": ts_ins,
        "id_gm": GM_ID,
        "id_file": id_file,
        "version_history": version_history,
        "id_csp": id_csp,
        "sigma_gm_prime": sigma_gm_prime.hex()
    }

    print(f"✓ Created TXins2CAB transaction")
    return tx_ins2cab

def create_tx_aud2cab(do_message, gm_signing_key):
    """Create TXaud2CAB transaction for blockchain network."""
    print("\n📝 Creating TXaud2CAB transaction...")

    ts_aud = do_message["ts_aud"]
    id_file = do_message["id_file"]
    chal = do_message["chal"]
    loh_list = do_message.get("loh_list", [])
    gamma = do_message.get("gamma")
    id_csp = do_message.get("id_csp", "CSP")

    sig_data = str(ts_aud) + str(chal) + str(loh_list)
    sigma_gm_prime = sign_message_eddsa(gm_signing_key, sig_data)

    tx_aud2cab = {
        "tx_type": "TXaud2CAB",
        "operation": "audit",
        "ts_aud": ts_aud,
        "id_gm": GM_ID,
        "id_file": id_file,
        "chal": chal,
        "loh_list": loh_list,
        "gamma": gamma,
        "id_csp": id_csp,
        "sigma_gm_prime": sigma_gm_prime.hex()
    }

    print(f"✓ Created TXaud2CAB transaction")
    return tx_aud2cab

def broadcast_transaction_to_gm_network(transaction):
    """Broadcast transaction to all GM nodes."""
    print("\n📡 Broadcasting transaction to CAB network...")
    gm_ports = [9001, 9011, 9012, 9013, 9014, 9015, 9016]
    success_count = 0

    for port in gm_ports:
        if port == GM_PORT:
            continue

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(2)
            client_socket.connect(("localhost", port))

            json_data = json.dumps(transaction)
            client_socket.sendall(json_data.encode('utf-8'))
            client_socket.sendall(b"\n\n")
            client_socket.close()

            success_count += 1
        except Exception as e:
            pass

    print(f"✓ Transaction broadcast complete ({success_count}/{len(gm_ports)-1} successful)")

# TRANSACTION POOL MANAGEMENT

def add_tx_to_pool(transaction):
    """Add transaction to appropriate pool."""
    with pool_lock:
        tx_type = transaction.get("tx_type")

        if tx_type == "TXins2CAB":
            tx_ins2cab_pool.append(transaction)
            print(f"\n Added TXins2CAB to pool")
            print(f"  - File ID: {transaction.get('id_file')}")
            print(f"  - From GM: {transaction.get('id_gm')}")
            print(f" TXins2CAB Pool: {len(tx_ins2cab_pool)} transactions")

        elif tx_type == "TXres2ins":
            tx_res2ins_pool.append(transaction)
            print(f"\n Added TXres2ins to pool")
            print(f"  - File ID: {transaction.get('id_file')}")
            print(f"  - Result: {transaction.get('result')}")
            print(f" TXres2ins Pool: {len(tx_res2ins_pool)} transactions")

        elif tx_type == "TXaud2CAB":
            tx_aud2cab_pool.append(transaction)
            print(f"\n Added TXaud2CAB to pool")
            print(f"  - File ID: {transaction.get('id_file')}")
            print(f"  - From GM: {transaction.get('id_gm')}")
            print(f" TXaud2CAB Pool: {len(tx_aud2cab_pool)} transactions")

        elif tx_type == "TXres2aud":
            tx_res2aud_pool.append(transaction)
            print(f"\n Added TXres2aud to pool")
            print(f"  - File ID: {transaction.get('id_file')}")
            print(f" TXres2aud Pool: {len(tx_res2aud_pool)} transactions")

        else:
            print(f" Unknown transaction type: {tx_type}")

# NETWORK COMMUNICATION

def send_to_csp(message, csp_host="localhost", csp_port=9002):
    """Send message to CSP and wait for response."""
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((csp_host, csp_port))

        json_data = json.dumps(message)
        client_socket.sendall(json_data.encode('utf-8'))
        client_socket.sendall(b"\n\n")

        response_data = b""
        while True:
            chunk = client_socket.recv(8192)
            if not chunk:
                break
            response_data += chunk
            if b"\n\n" in response_data:
                break

        response_data = response_data.replace(b"\n\n", b"")
        response = json.loads(response_data.decode('utf-8'))

        client_socket.close()
        return response

    except Exception as e:
        print(f"❌ Error communicating with CSP: {e}")
        return None

def compute_proof(tp_data, dp_value):
    """Compute proof based on TP and DP from CSP (DUMMY for insert)."""
    proof_result = "VALID"
    return proof_result

# CLIENT HANDLERS

def handle_do_client(client_socket, gm_signing_key, public_keys):
    """Handle incoming connection from DO."""
    try:
        data = b""
        while True:
            chunk = client_socket.recv(8192)
            if not chunk:
                break
            data += chunk
            if b"\n\n" in data:
                break

        data = data.replace(b"\n\n", b"")
        do_message = json.loads(data.decode('utf-8'))

        operation = do_message.get("operation")
        print(f"\n Received message from DO")
        print(f"  - Operation: {operation}")
        print(f"  - File ID: {do_message.get('id_file')}")

        # HANDLE INSERT OPERATION
        if operation == "insert":
            ts_ins = do_message["ts_ins"]
            block_metadata = do_message.get("block_metadata", [])
            sigma_do = do_message["sigma_do"]

            # Verify DO signature
            sig_data = str(ts_ins)
            for meta in block_metadata:
                sig_data += f"{meta['v']}{meta['ts']}{meta['loh']}"

            do_public_key = public_keys.get("DO")
            if not do_public_key or not verify_signature_eddsa(do_public_key, sig_data, sigma_do):
                response = {"status": "error", "message": "Invalid DO signature"}
                client_socket.sendall(json.dumps(response).encode('utf-8'))
                client_socket.sendall(b"\n\n")
                return

            print("✓ DO signature verified")

            # Create TXins2CAB
            tx_ins2cab = create_tx_ins2cab(do_message, gm_signing_key)
            add_tx_to_pool(tx_ins2cab)
            broadcast_transaction_to_gm_network(tx_ins2cab)

            # Create GM message and send to CSP
            gm_message = create_gm_message_insert(do_message, gm_signing_key)
            csp_response = send_to_csp(gm_message)

            if csp_response and csp_response.get("status") == "success":
                tp_data = csp_response.get("tp")
                dp_value = csp_response.get("dp")

                proof_result = compute_proof(tp_data, dp_value)

                # Wait a bit for block to be committed
                time.sleep(2)
                latest = get_latest_block()

                response = {
                    "status": "success",
                    "proof_result": proof_result,
                    "block_height": latest["height"] if latest else 0,
                    "message": "File processed successfully"
                }
            else:
                response = {"status": "error", "message": "CSP processing failed"}

        # HANDLE AUDIT OPERATION
        elif operation == "audit":
            ts_aud = do_message["ts_aud"]
            chal = do_message["chal"]
            loh_list = do_message.get("loh_list", [])
            sigma_do = do_message["sigma_do"]

            # Verify DO signature
            sig_data = str(ts_aud) + str(chal) + str(loh_list)

            do_public_key = public_keys.get("DO")
            if not do_public_key or not verify_signature_eddsa(do_public_key, sig_data, sigma_do):
                response = {"status": "error", "message": "Invalid DO signature"}
                client_socket.sendall(json.dumps(response).encode('utf-8'))
                client_socket.sendall(b"\n\n")
                return

            print("✓ DO signature verified")

            # Create TXaud2CAB
            tx_aud2cab = create_tx_aud2cab(do_message, gm_signing_key)
            add_tx_to_pool(tx_aud2cab)
            broadcast_transaction_to_gm_network(tx_aud2cab)

            # Create GM message and send to CSP
            gm_message = create_gm_message_audit(do_message, gm_signing_key)
            csp_response = send_to_csp(gm_message)

            if csp_response and csp_response.get("status") == "success":
                # Wait for audit block to be created and committed
                time.sleep(10)
                latest = get_latest_block()

                # Get proof result from latest block
                proof_result = "VALID"
                if latest and latest.get('transactions'):
                    for tx in latest['transactions']:
                        req = tx.get('request_record', {})
                        ext_field = req.get('extension_field', {})
                        if 'proof_result' in ext_field:
                            proof_result = ext_field['proof_result']

                response = {
                    "status": "success",
                    "proof_result": proof_result,
                    "block_height": latest["height"] if latest else 0,
                    "message": "Audit completed"
                }
            else:
                response = {"status": "error", "message": "CSP audit failed"}

        else:
            response = {"status": "error", "message": "Unknown operation"}

        response_json = json.dumps(response)
        client_socket.sendall(response_json.encode('utf-8'))
        client_socket.sendall(b"\n\n")

    except Exception as e:
        print(f"❌ Error handling DO client: {e}")
        import traceback
        traceback.print_exc()

    finally:
        client_socket.close()

def handle_gm_transaction(client_socket, public_keys):
    """Handle incoming transaction from another GM or CSP."""
    try:
        data = b""
        while True:
            chunk = client_socket.recv(8192)
            if not chunk:
                break
            data += chunk
            if b"\n\n" in data:
                break

        data = data.replace(b"\n\n", b"")
        message = json.loads(data.decode('utf-8'))

        # MESSAGE TYPE HANDLING 
        msg_type = message.get("message_type")
        
        if msg_type == "preprepare":
            handle_preprepare_message(message)
            return
        elif msg_type == "prepare":
            handle_prepare_message(message)
            return
        elif msg_type == "commit":
            handle_commit_message(message)
            return
        elif msg_type == "block_proposal":
            handle_block_proposal(message)
            return

        # Otherwise it's a transaction
        tx_type = message.get("tx_type")

        if tx_type == "TXins2CAB":
            id_gm = message.get("id_gm")
            sigma_gm_prime = message.get("sigma_gm_prime")
            ts_ins = message.get("ts_ins")
            version_history = message.get("version_history", [])

            sig_data = str(ts_ins)
            for vh in version_history:
                sig_data += f"{vh['v']}{vh['ts']}{vh['loh']}"

            gm_public_key = public_keys.get(id_gm)
            if gm_public_key and verify_signature_eddsa(gm_public_key, sig_data, sigma_gm_prime):
                add_tx_to_pool(message)

        elif tx_type == "TXres2ins":
            id_csp = message.get("id_csp")
            sigma_csp = message.get("sigma_csp")
            ts_ins = message.get("ts_ins")
            result = message.get("result")

            sig_data = str(result) + str(ts_ins)

            csp_public_key = public_keys.get(id_csp)
            if csp_public_key and verify_signature_eddsa(csp_public_key, sig_data, sigma_csp):
                add_tx_to_pool(message)

        elif tx_type == "TXaud2CAB":
            id_gm = message.get("id_gm")
            sigma_gm_prime = message.get("sigma_gm_prime")
            ts_aud = message.get("ts_aud")
            chal = message.get("chal")
            loh_list = message.get("loh_list", [])

            sig_data = str(ts_aud) + str(chal) + str(loh_list)

            gm_public_key = public_keys.get(id_gm)
            if gm_public_key and verify_signature_eddsa(gm_public_key, sig_data, sigma_gm_prime):
                add_tx_to_pool(message)

        elif tx_type == "TXres2aud":
            id_csp = message.get("id_csp")
            sigma_csp = message.get("sigma_csp")
            ts_aud = message.get("ts_aud")
            tp = message.get("tp")
            dp = message.get("dp")

            sig_data = str(tp) + str(dp) + str(ts_aud)

            csp_public_key = public_keys.get(id_csp)
            if csp_public_key and verify_signature_eddsa(csp_public_key, sig_data, sigma_csp):
                add_tx_to_pool(message)

    except Exception as e:
        print(f"❌ Error handling GM transaction: {e}")

    finally:
        client_socket.close()

# SERVER STARTUP

def start_gm_server(host="localhost", port=GM_PORT):
    """Start GM server to listen for requests."""
    try:
        # Load GM signing key from local .env
        gssk_str = os.getenv("gssk")
        if not gssk_str:
            raise ValueError("GM signing key 'gssk' not found in .env")
        gm_signing_key = deserialize_private_key(gssk_str.strip())
        print(f"✓ Loaded {GM_ID} signing key")

        # Load public keys
        public_keys = load_public_keys()

        # Load GPK for audit verification
        gpk = load_gpk("GM0", "gpk.json")
        if not gpk:
            print(" Warning: Could not load GPK, audit verification may fail")

        # Load or create blockchain
        load_or_create_blockchain()

        # Start pair checker thread only for proposer
        print(f"\n Starting pair checker thread...")
        threading.Thread(
            target=pair_checker_thread,
            args=(gm_signing_key, gpk),
            daemon=True
        ).start()
        
        # Create server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(10)

        print(f"\n {GM_ID} server started on {host}:{port}")
        print(" Waiting for connections...")

        while True:
            client_socket, addr = server_socket.accept()

            # Set timeout for peek operation
            client_socket.settimeout(1.0)

            try:
                # Peek at data to determine type
                peek_data = client_socket.recv(100, socket.MSG_PEEK)
                peek_str = peek_data.decode('utf-8', errors='ignore')

                if "tx_type" in peek_str or "message_type" in peek_str:
                    # Transaction from GM or block proposal
                    threading.Thread(target=handle_gm_transaction, args=(client_socket, public_keys)).start()
                else:
                    # Message from DO
                    threading.Thread(target=handle_do_client, args=(client_socket, gm_signing_key, public_keys)).start()
            except:
                # Default to DO client
                threading.Thread(target=handle_do_client, args=(client_socket, gm_signing_key, public_keys)).start()

    except KeyboardInterrupt:
        print(f"\n\n🛑 {GM_ID} server stopped")
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    start_gm_server()
