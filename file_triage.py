#file_triage.py
#Hashes files and compares them to a reference list.

import hashlib
import csv
from pathlib import Path
from datetime import datetime

def hash_file(file_path, hash_algo="sha256"):
    """return the hash of a file as a hex string, reading in chunks"""
    hash_obj = hashlib.new(hash_algo)
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_obj.update(chunk)
            
    return hash_obj.hexdigest()

def load_reference(file_path):
    """load the reference CSV into a dictionary: {sha256_hash_label}"""
    reference = {}
   
    with open(file_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            reference[row["sha256"]] = row["label"]
            
    return reference

def get_files(folder):
    """return a sorted list of all files in a folder (including sub-folders)"""
    base = Path(folder)
    files = []
    
    for path in sorted(base.rglob("*")):
        if path.is_file() and not path.name.startswith("."):
            files.append(path)
            
    return files

def get_file_info(path):
    """return a dictionary of facts about one file"""
    stat = path.stat()
    
    return {
        "filename": path.name,
        "extension": path.suffix.lower(),
        "size": stat.st_size,
        "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        "sha256": hash_file(path)
    }
    
def classify_file(info, reference):
    """add a status (known/unknown) and reference label to a file info dictionary"""
    label = reference.get(info["sha256"])

    if label is not None:
        info["status"] = "known"
        info["label"] = label
    else:
        info["status"] = "unknown"
        info["label"] = None
    
    return info 

if __name__ == "__main__":
    reference = load_reference("data/hashes_reference.csv")

    results = []
    for path in get_files("samples"):
        info = get_file_info(path)
        results.append(classify_file(info, reference))

    for info in results:
        print(f"{info['filename']:15} {info['status']:8} {info['label']}")