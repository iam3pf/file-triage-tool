#file_triage.py
#Hashes files and compares them to a reference list.

import hashlib
import csv

def hash_file(file_path, hash_algo="sha256"):
    """return the hash of a file as a hex string, reading in chunks"""
    hash_obj = hashlib.new(hash_algo)
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_obj.update(chunk)
            
    return hash_obj.hexdigest()

def load_reference(file_path):
    """Load the reference CSV into a dictionary: {sha256_hash_ label}."""
    reference = {}
   
    with open(file_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            reference[row["sha256"]] = row["label"]
            
    return reference

if __name__ == "__main__":
    reference = load_reference("data/hashes_reference.csv")
    print(reference) 
    print(len(reference), "reference hashes loaded")  
    print(reference.get("abc123")) 