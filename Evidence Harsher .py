#!/usr/bin/env python3
import hashlib
import os
import argparse
from datetime import datetime

def calculate_hash(file_path, algorithm='sha256'):
    hash_func = hashlib.new(algorithm)
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def generate_report(target_path, report_path):
    algorithms = ['md5', 'sha1', 'sha256']
    with open(report_path, 'w') as report:
        report.write(f"Kenya Forensics Evidence Hash Report\n")
        report.write(f"Generated: {datetime.now()}\n")
        report.write(f"Target: {target_path}\n\n")
        
        if os.path.isfile(target_path):
            for algo in algorithms:
                h = calculate_hash(target_path, algo)
                report.write(f"{algo.upper()}: {h}\n")
        else:
            for root, _, files in os.walk(target_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    report.write(f"\nFile: {file_path}\n")
                    for algo in algorithms:
                        h = calculate_hash(file_path, algo)
                        report.write(f"{algo.upper()}: {h}\n")
    print(f"✅ Report saved to {report_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kenya Forensics Evidence Hasher — Digital Forensics Tool")
    parser.add_argument("target", help="Path to file or folder")
    parser.add_argument("-o", "--output", default="hash_report.txt", help="Report output file")
    args = parser.parse_args()

    generate_report(args.target, args.output)
