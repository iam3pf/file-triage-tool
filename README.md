# File Triage & Hash Analysis Tool

COMP H2702 Scripting for Cybersecurity (Scenario C)

## What it does

This program is used to determine whether a file is known or unknown and also checks for duplicates. This is done by generating a file's SHA-256 hash and comparing it to a list of known reference hashes.

## Setup

Python 3.8+, no additional packages needed.

```bash
git clone https://github.com/iam3pf/file-triage-tool
cd file-triage-tool
```

## How to run

```bash
python file_triage.py
python file_triage.py path/to/folder
```

The first command runs the program with the sample files, the second one can check a custom folder instead. Use python3 instead to run on Mac/Linux based systems.

## Input files

- `samples/` – Sample files to be tested
- `data/hashes_reference.csv` – Known hash references to be compared to

## Output

The program creates 3 output files, a .txt, .csv and .json where the tested files are categorized into three categories:

- known – The file's hash 100% matches a reference hash
- unknown – The file's hash is not present in the reference list
- error – The file is unreadable

## Error handling

If the input folder is not present, the program presents the user with an error stating that the directory does not exist and it does not run. If the reference list is missing, the program still runs, however it shows the user that all the tested files will be labeled as unknown.

## Notes / limitations

A hash does not tell you what the file does. A categorization of known does not mean that a file is safe and likewise a categorization of unknown also does not mean that a file is unsafe. The program only checks exact matches so it is not able to tell if a file is similar.
