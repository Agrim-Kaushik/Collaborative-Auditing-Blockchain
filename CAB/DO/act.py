import time
import json

class ACT:
    def __init__(self):
        self.files = {}
        self.counter = 0  # Global counter for unique timestamps

    def add_file(self, filename, chunks):
        blocks = []
        base_time = int(time.time())
        for i, chunk in enumerate(chunks):
            block = {
                'index': i,
                'v': 1,
                'ts': base_time + self.counter,
                'loh': -1,
                'lot': 'insert',
                'los': -1
            }
            blocks.append(block)
            self.counter += 1

        self.files[filename] = blocks
        self.save()

    def get_file(self, filename):
        """Get blocks for a file"""
        return self.files.get(filename)

    def print_act(self):
        """Print ACT in pretty JSON format"""
        print(json.dumps(self.files, indent=2))

    def save(self, filepath="act.json"):
        """Save ACT to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(self.files, f, indent=2)
        print(f" Saved to {filepath}")

    def load(self, filepath="act.json"):
        """Load ACT from JSON file"""
        with open(filepath, 'r') as f:
            self.files = json.load(f)
