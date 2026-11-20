#file_triage.py
#Hashes files and compares them to a reference list.

import hashlib
import csv
import json
import sys
from collections import Counter
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
   
    try: 
        with open(file_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                reference[row["sha256"]] = row["label"]
    except FileNotFoundError:
        print(f"Warning: reference file '{file_path}' not found. All files will be UNKNOWN.")
    except (KeyError, csv.Error, UnicodeDecodeError) as e:
        print(f"Warning: could not read reference file '{file_path}' ({e}). All files will be UNKNOWN.")
        reference = {}
            
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

    if info["error"]:
        info["status"] = "error"
        info["label"] = None 
    elif label is not None:
        info["status"] = "known"
        info["label"] = label
    else:
        info["status"] = "unknown"
        info["label"] = None
    
    return info 

def find_duplicates(results):
    """group filenames by sha-256 and return only hashes shared by 2+ files"""
    groups = {}

    for info in results:
        sha256 = info["sha256"]
        if sha256 == "":
            continue  # unreadable file, nothing to compare
        if sha256 not in groups:
            groups[sha256] = []
        groups[sha256].append(info["filename"])

    duplicates = {}
    for sha256, filenames in groups.items():
        if len(filenames) > 1:
            duplicates[sha256] = filenames

    return duplicates

def generate_report(results, duplicates, folder):
    """build the triage report as one block of text"""
    counts = Counter(info["status"] for info in results)
    lines = []
    
    lines.append("File Triage Report")
    lines.append("=" * 40)
    lines.append(f"Folder: {folder}")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Files processed: {len(results)}")
    lines.append(f"Known files: {counts.get('known', 0)}")
    lines.append(f"Unknown files: {counts.get('unknown', 0)}")
    lines.append(f"errors: {counts['error']}")
    
    for info in results:
        lines.append(f"{info['filename']:15} {info['status']:8}")
        if info["status"] == "error":
            lines.append(f"Error: {info['error']}")
        else:
            lines.append(f"size: {info['size']} bytes   modified: {info['modified']}")
            lines.append(f"sha256: {info['sha256']}")
            if info["label"]:
                lines.append(f"matches reference: {info['label']}")
        lines.append("")

    lines.append("DUPLICATE FILES (same hash, possibly different names)")
    lines.append("-" * 40)
    if duplicates:
        for sha256, filenames in duplicates.items():
            lines.append(f"{sha256[:16]}...: {', '.join(filenames)}")
    else:
        lines.append("No duplicates found.")
    lines.append("")

    lines.append("Explanation of codes:")
    lines.append("-" * 40)
    lines.append("KNOWN: the hash matches the reference list, so the content is identical to a")
    lines.append("sample already labelled.")
    lines.append("UNKNOWN: not in the reference list. This is not proof of malware, and a")
    lines.append("one-byte change to a known file also gives an UNKNOWN result.")

    return "\n".join(lines) + "\n"


def save_reports(results, duplicates, report_text, output_dir):
    """save the report as TXT, CSV and JSON files in output_dir."""
    out = Path(output_dir)
    out.mkdir(exist_ok=True)

    with open(out / "triage_report.txt", "w", encoding="utf-8") as f:
        f.write(report_text)

    fields = ["filename", "extension", "size", "modified", "sha256", "status", "label", "error"]
    with open(out / "triage_report.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)

    summary = {"files": results, "duplicates": duplicates}
    with open(out / "triage_report.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
            

def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else "samples"
    reference_file = "data/hashes_reference.csv"
    output_dir = "output"

    if not Path(folder).is_dir():
        print(f"Error: '{folder}' is not a folder or does not exist.")
        return

    files = get_files(folder)
    if not files:
        print(f"Error: no files found in '{folder}'.")
        return

    reference = load_reference(reference_file)

    results = []
    for path in files:
        info = get_file_info(path)
        results.append(classify_file(info, reference))

    duplicates = find_duplicates(results)
    report_text = generate_report(results, duplicates, folder)
    print(report_text)

    try:
        save_reports(results, duplicates, report_text, output_dir)
        print(f"Reports saved in '{output_dir}/'.")
    except OSError as e:
        print(f"Error: could not save reports ({e}).")


if __name__ == "__main__":
    main()