from flask import Flask, render_template, request, jsonify, send_from_directory
import os
import sys
import json
import time
from pathlib import Path

# Add CAB directories to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'CAB', 'DO'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'CAB', 'GM0'))

# Import DO functions - need to import the module first
import importlib.util

# Import ACT from act.py
act_path = os.path.join(os.path.dirname(__file__), 'CAB', 'DO', 'act.py')
act_spec = importlib.util.spec_from_file_location("act", act_path)
act_module = importlib.util.module_from_spec(act_spec)
act_spec.loader.exec_module(act_module)
ACT = act_module.ACT

# Import DO module
do_path = os.path.join(os.path.dirname(__file__), 'CAB', 'DO', 'DO.py')
do_spec = importlib.util.spec_from_file_location("DO_module", do_path)
DO_module = importlib.util.module_from_spec(do_spec)
do_spec.loader.exec_module(DO_module)

upload_file = DO_module.upload_file
audit_file = DO_module.audit_file

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('CAB/DO', exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/files', methods=['GET'])
def list_files():
    """List all files in ACT"""
    try:
        act_path = 'CAB/DO/act.json'
        if not os.path.exists(act_path):
            return jsonify({'files': []})
        
        act = ACT()
        act.load(act_path)
        
        files = []
        for filename in act.files.keys():
            blocks = act.get_file(filename)
            files.append({
                'name': filename,
                'blocks': len(blocks),
                'status': 'uploaded' if blocks[0].get('los', -1) == 1 else 'pending'
            })
        
        return jsonify({'files': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/act', methods=['GET'])
def get_act():
    """Get raw ACT.json data"""
    try:
        act_path = 'CAB/DO/act.json'
        if not os.path.exists(act_path):
            return jsonify({'data': {}, 'message': 'ACT file not found'})
        
        with open(act_path, 'r') as f:
            act_data = json.load(f)
        
        return jsonify({'data': act_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload():
    """Upload a file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Save file temporarily
        filename = file.filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Change to DO directory to run upload
        original_dir = os.getcwd()
        try:
            os.chdir('CAB/DO')
            # Convert to absolute path for upload_file (relative to original dir)
            abs_filepath = os.path.join(original_dir, filepath)
            upload_file(abs_filepath)
        finally:
            os.chdir(original_dir)
        
        # Clean up temp file
        if os.path.exists(filepath):
            os.remove(filepath)
        
        return jsonify({'success': True, 'message': f'File {filename} uploaded successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/audit', methods=['POST'])
def audit():
    """Audit a file"""
    try:
        data = request.json
        filename = data.get('filename')
        block_indices = data.get('blocks', None)
        
        if not filename:
            return jsonify({'error': 'Filename required'}), 400
        
        # Change to DO directory
        original_dir = os.getcwd()
        try:
            os.chdir('CAB/DO')
            
            # If no blocks specified, audit all blocks
            if block_indices is None:
                act = ACT()
                if os.path.exists('act.json'):
                    act.load('act.json')
                    file_blocks = act.get_file(filename)
                    if file_blocks:
                        block_indices = list(range(len(file_blocks)))
                    else:
                        return jsonify({'error': f'File {filename} not found'}), 404
                else:
                    return jsonify({'error': 'ACT file not found'}), 404
            
            audit_file(filename, block_indices)
            
        finally:
            os.chdir(original_dir)
        
        return jsonify({'success': True, 'message': f'Audit completed for {filename}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blockchain', methods=['GET'])
def get_blockchain():
    """Get blockchain data from GM0"""
    try:
        blockchain_path = 'CAB/GM0/blockchain.json'
        if not os.path.exists(blockchain_path):
            return jsonify({'blocks': [], 'height': 0})
        
        with open(blockchain_path, 'r') as f:
            blockchain = json.load(f)
        
        # Format blocks for display
        formatted_blocks = []
        for block in blockchain:
            tx_count = len(block.get('transactions', []))
            tx_type = 'N/A'
            if tx_count > 0:
                tx = block['transactions'][0]
                req = tx.get('request_record', {})
                tx_type = req.get('type', 'unknown')
            
            formatted_blocks.append({
                'height': block.get('height', 0),
                'hash': block.get('current_hash', '')[:16] + '...',
                'previous_hash': block.get('previous_hash', '')[:16] + '...',
                'timestamp': block.get('timestamp', 0),
                'transactions': tx_count,
                'type': tx_type
            })
        
        return jsonify({
            'blocks': formatted_blocks,
            'height': len(blockchain)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blockchain/<int:height>', methods=['GET'])
def get_block(height):
    """Get specific block details"""
    try:
        blockchain_path = 'CAB/GM0/blockchain.json'
        if not os.path.exists(blockchain_path):
            return jsonify({'error': 'Blockchain not found'}), 404
        
        with open(blockchain_path, 'r') as f:
            blockchain = json.load(f)
        
        block = next((b for b in blockchain if b.get('height') == height), None)
        if not block:
            return jsonify({'error': 'Block not found'}), 404
        
        return jsonify({'block': block})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get system statistics"""
    try:
        stats = {
            'files': 0,
            'blocks': 0,
            'transactions': 0
        }
        
        # Count files
        act_path = 'CAB/DO/act.json'
        if os.path.exists(act_path):
            act = ACT()
            act.load(act_path)
            stats['files'] = len(act.files)
        
        # Count blockchain blocks and transactions
        blockchain_path = 'CAB/GM0/blockchain.json'
        if os.path.exists(blockchain_path):
            with open(blockchain_path, 'r') as f:
                blockchain = json.load(f)
            stats['blocks'] = len(blockchain)
            stats['transactions'] = sum(len(b.get('transactions', [])) for b in blockchain)
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

