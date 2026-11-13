#file_triage.py
#Hashes files and compares them to a reference list.

import hashlib

def hash_file(file_path, hash_algo="sha256"):
    """return the hash of a file as a hex string, reading in chunks"""
    hash_obj = hashlib.new(hash_algo)
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_obj.update(chunk)
            
    return hash_obj.hexdigest()

if __name__ == "__main__":
    print (hash_file("samples/sample_c.txt"))