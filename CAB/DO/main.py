from hashlib import sha256
from act import ACT
import argparse
import os
import json
import secrets
from dotenv import load_dotenv
from py_ecc.optimized_bls12_381 import G1, G2, multiply, add, FQ, pairing, FQ2
from py_ecc.bls.hash_to_curve import hash_to_G2
from py_ecc.bls12_381 import curve_order


load_dotenv()


def load_gpk(node_id="GM1", filename="../PKG/gpk.json"):
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
        print(f"Error loading gpk: {e}")
        return None


def generate_bls_tags(chunks, file_blocks, beta):
    """Generate BLS tags for each chunk"""
    p = curve_order
    tags = []
    
    print("\n🔐 Generating BLS tags...")
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


def save_tags(tags, filename="tags.json"):
    """Save tags to JSON file"""
    serialized_tags = []
    for tag in tags:
        tag_as_integers = [
            [int(tag[0].coeffs[0]), int(tag[0].coeffs[1])],
            [int(tag[1].coeffs[0]), int(tag[1].coeffs[1])],
            [int(tag[2].coeffs[0]), int(tag[2].coeffs[1])]
        ]
        serialized_tags.append(tag_as_integers)
    
    with open(filename, 'w') as f:
        json.dump(serialized_tags, f, indent=2)
    print(f"💾 Saved {len(tags)} tags to {filename}")


def load_tags(filename="tags.json"):
    """Load tags from JSON file"""
    with open(filename, 'r') as f:
        data = json.load(f)
    
    tags = []
    for tag_data in data:
        reconstructed_tag = (
            FQ2(tag_data[0]),
            FQ2(tag_data[1]),
            FQ2(tag_data[2])
        )
        tags.append(reconstructed_tag)
    
    print(f"📂 Loaded {len(tags)} tags from {filename}")
    return tags


def file_to_chunks(filepath, chunk_size=31):
    """Read file and split into 31-byte chunks"""
    with open(filepath, 'rb') as f:
        file_data = f.read()
    chunks = [file_data[i:i+chunk_size] for i in range(0, len(file_data), chunk_size)]
    return chunks


def save_chunks_to_directory(chunks, filename):
    """Save raw chunk data to directory"""
    # Create directory with filename
    dir_name = f"{filename}_chunks"
    os.makedirs(dir_name, exist_ok=True)
    
    print(f"\n💾 Saving chunks to {dir_name}/")
    for i, chunk in enumerate(chunks):
        chunk_path = os.path.join(dir_name, f"{i}.chunk")
        with open(chunk_path, 'wb') as f:
            f.write(chunk)
    
    print(f"✓ Saved {len(chunks)} chunk files")


def load_chunks_from_directory(filename):
    """Load chunks from directory"""
    dir_name = f"{filename}_chunks"
    
    if not os.path.exists(dir_name):
        print(f"❌ Error: Chunk directory not found: {dir_name}")
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
    
    print(f"📂 Loaded {len(chunks)} chunks from {dir_name}/")
    return chunks


def upload_file(file_path):
    """Upload a file - chunk it, create ACT, save chunks, and generate BLS tags"""
    if not os.path.exists(file_path):
        print(f"❌ Error: File not found: {file_path}")
        return
    
    try:
        filename = os.path.basename(file_path)
        
        print(f"📤 Uploading: {filename}")
        chunks = file_to_chunks(file_path)
        print(f"✓ Created {len(chunks)} chunks")
        
        # Save chunks to directory
        save_chunks_to_directory(chunks, filename)
        
        # Create ACT
        act = ACT()
        if os.path.exists("act.json"):
            try:
                act.load("act.json")
                print("✓ Loaded existing ACT")
            except:
                pass
        
        act.add_file(filename, chunks)
        file_blocks = act.get_file(filename)
        
        # Load secret key
        beta = int(os.getenv("sk"))
        if not beta:
            print("❌ Error: Secret key 'sk' not found in .env file")
            return
        print(f"✓ Loaded secret key")
        
        # Generate BLS tags
        tags = generate_bls_tags(chunks, file_blocks, beta)
        
        # Save tags
        tags_filename = f"{filename}.tags.json"
        save_tags(tags, tags_filename)
        
        print(f"\n✅ Upload complete: {filename}")
        print(f"   Chunks: {len(chunks)}")
        print(f"   Tags: {len(tags)}")
        
    except Exception as e:
        print(f"❌ Error uploading file: {e}")
        import traceback
        traceback.print_exc()


def verify_file(filename):
    """Verify file integrity using BLS proof"""
    try:
        p = curve_order
        
        # Load ACT
        act = ACT()
        if not os.path.exists("act.json"):
            print("❌ Error: No ACT file found")
            return
        
        act.load("act.json")
        
        # Get file blocks
        file_blocks = act.get_file(filename)
        if not file_blocks:
            print(f"❌ Error: File '{filename}' not found in ACT")
            return
        
        print(f"🔍 Verifying: {filename}")
        print(f"✓ Found {len(file_blocks)} blocks in ACT")
        
        # Load chunks from directory
        chunks = load_chunks_from_directory(filename)
        if not chunks:
            return
        
        # Load tags
        tags_filename = f"{filename}.tags.json"
        if not os.path.exists(tags_filename):
            print(f"❌ Error: Tags file not found: {tags_filename}")
            return
        tags = load_tags(tags_filename)
        
        # Load GPK
        gpk = load_gpk("GM0", "gpk.json")
        if not gpk:
            return
        
        # Load secret key and compute gamma
        beta = int(os.getenv("sk"))
        if not beta:
            print("❌ Error: Secret key 'sk' not found")
            return
        
        inv = pow(beta, -1, p)
        gamma = multiply(gpk, inv)
        
        print("\n🎲 Generating random coefficients...")
        # Generate random coefficients for all blocks
        coefficients = [secrets.randbelow(p) for _ in range(len(chunks))]
        print(f"✓ Generated {len(coefficients)} random coefficients")
        
        print("\n🔐 Computing proof...")
        # Compute TP = Σ(r_i * t_i)
        TP = None
        for i, (r_i, t_i) in enumerate(zip(coefficients, tags)):
            term = multiply(t_i, r_i)
            if TP is None:
                TP = term
            else:
                TP = add(TP, term)
        
        # Compute DP = Σ(r_i * b_i) mod p
        DP = 0
        for i, (r_i, chunk) in enumerate(zip(coefficients, chunks)):
            b_i = int.from_bytes(chunk, 'big')
            DP = (DP + (r_i * b_i) % p) % p
        
        # Compute DBI = Σ(r_i * H_i)
        DBI_sum = None
        for i in range(len(chunks)):
            ts = file_blocks[i]['ts']
            v = file_blocks[i]['v']
            message = f"{v}+{ts}".encode()
            H_i = hash_to_G2(message, b'TAG_GEN_DST', sha256)
            
            term = multiply(H_i, coefficients[i])
            if DBI_sum is None:
                DBI_sum = term
            else:
                DBI_sum = add(DBI_sum, term)
        
        print("\n🔬 Computing pairings...")
        # Verification: e(TP, gamma) == e(DBI_sum, gpk) * e(G2^DP, gpk)
        a = pairing(TP, gamma)
        b = pairing(multiply(G2, DP), gpk)
        DBI = pairing(DBI_sum, gpk)
        
        verification_result = (a == DBI * b)
        
        print(f"\n{'='*60}")
        if verification_result:
            print("✅ VERIFICATION SUCCESSFUL!")
            print("   File integrity confirmed via BLS proof")
        else:
            print("❌ VERIFICATION FAILED!")
            print("   File may be corrupted or tampered")
        print(f"{'='*60}")
        
    except Exception as e:
        print(f"❌ Error verifying file: {e}")
        import traceback
        traceback.print_exc()


def list_files():
    """List all files in ACT"""
    try:
        act = ACT()
        if not os.path.exists("act.json"):
            print("No files found (ACT not initialized)")
            return
        
        act.load("act.json")
        files = list(act.files.keys())
        
        if not files:
            print("No files found")
        else:
            print("📁 Files in ACT:")
            for filename in files:
                blocks = act.get_file(filename)
                tags_file = f"{filename}.tags.json"
                chunks_dir = f"{filename}_chunks"
                has_tags = "✓" if os.path.exists(tags_file) else "✗"
                has_chunks = "✓" if os.path.exists(chunks_dir) else "✗"
                print(f"  - {filename} ({len(blocks)} blocks) [Tags: {has_tags}] [Chunks: {has_chunks}]")
    
    except Exception as e:
        print(f"❌ Error listing files: {e}")


def main():
    parser = argparse.ArgumentParser(description='Data Owner - Cloud Storage Client')
    subparsers = parser.add_subparsers(dest='command')
    
    upload_parser = subparsers.add_parser('upload', help='Upload a file')
    upload_parser.add_argument('file_path', help='Path to file to upload')
    
    list_parser = subparsers.add_parser('list', help='List all files')
    
    verify_parser = subparsers.add_parser('verify', help='Verify file integrity')
    verify_parser.add_argument('filename', help='Name of file to verify')
    
    args = parser.parse_args()
    
    if args.command == 'upload':
        upload_file(args.file_path)
    elif args.command == 'list':
        list_files()
    elif args.command == 'verify':
        verify_file(args.filename)
    else:
        print("Commands:")
        print("  python DO.py upload <file_path>")
        print("  python DO.py list")
        print("  python DO.py verify <filename>")


if __name__ == "__main__":
    main()
