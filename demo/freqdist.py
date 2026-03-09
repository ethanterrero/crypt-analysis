#!/usr/bin/env python3
"""
Byte frequency distribution visualizer.
Shows side-by-side ASCII bar charts for two files to visualize
the chi-squared concept: good ciphertext has a flat, uniform distribution.

Usage: python3 demo/freqdist.py <plaintext_file> <encrypted_file>
"""

"""
Left most column: the byte value itself (0-255) for printable ASCII

For the ciphertext, they just correspond to the raw byte values

The count column represents how many times that byte value appears in the file.

ASCII counts typically cluster. English has consistently some letters that are used more than others. This makes it easy to predict. We want a flatter distribution of ciphertext because it hides those structural patterns in our language.
"""

import sys

BAR_CHAR  = "█"
MAX_WIDTH = 40  # max bar width in characters

def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()

def byte_frequencies(data):
    # count occurrences of each of the 256 possible byte values
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return counts

def make_bar(count, max_count):
    if max_count == 0:
        return ""
    filled = int((count / max_count) * MAX_WIDTH)
    return BAR_CHAR * filled

def print_distribution(file1, file2):
    data1 = read_bytes(file1)
    data2 = read_bytes(file2)

    counts1 = byte_frequencies(data1)
    counts2 = byte_frequencies(data2)

    max1 = max(counts1)
    max2 = max(counts2)

    # compute how many byte values are actually nonzero in each file
    nonzero1 = sum(1 for c in counts1 if c > 0)
    nonzero2 = sum(1 for c in counts2 if c > 0)

    # compute expected count per byte value for a uniform distribution
    expected1 = len(data1) / 256
    expected2 = len(data2) / 256

    print(f"\nByte Frequency Distribution")
    print(f"{'Plaintext: ' + file1:<50}  Encrypted: {file2}")
    print(f"{'Bytes: ' + str(len(data1)) + '  Distinct values: ' + str(nonzero1) + '/256':<50}  "
          f"Bytes: {len(data2)}  Distinct values: {nonzero2}/256")
    print(f"{'Expected per value (uniform): ' + f'{expected1:.1f}':<50}  "
          f"Expected per value (uniform): {expected2:.1f}")
    print("-" * 105)
    print(f"{'Byte':<6} {'Count':<7} {'Distribution (plaintext)':<43}  {'Count':<7} {'Distribution (encrypted)'}")
    print("-" * 105)

    # only print rows where at least one file has a nonzero count
    for i in range(256):
        c1 = counts1[i]
        c2 = counts2[i]
        if c1 == 0 and c2 == 0:
            continue

        bar1 = make_bar(c1, max1)
        bar2 = make_bar(c2, max2)

        print(f"0x{i:02x}   {c1:<7} {bar1:<43}  {c2:<7} {bar2}")

    # chi-squared statistic vs uniform distribution (expected = total_bytes / 256)
    # degrees of freedom = 255, critical value at p=0.05 is ~293.25
    chi_sq1 = sum((counts1[i] - expected1) ** 2 / expected1 for i in range(256)) if expected1 > 0 else 0
    chi_sq2 = sum((counts2[i] - expected2) ** 2 / expected2 for i in range(256)) if expected2 > 0 else 0
    threshold = 293.25

    # summary stats
    print("-" * 105)
    print(f"\nSummary:")
    print(f"  Plaintext  — {nonzero1}/256 distinct byte values used  (uneven = patterns visible)")
    print(f"  Encrypted  — {nonzero2}/256 distinct byte values used  (flat = good, looks random)")
    print(f"\nChi-Squared Test (uniform distribution, 255 degrees of freedom, threshold=293.25 at p=0.05):")
    print(f"  Plaintext  χ² = {chi_sq1:>10.2f}  {'FAIL - non-uniform (expected for plaintext)' if chi_sq1 > threshold else 'PASS - uniform'}")
    print(f"  Encrypted  χ² = {chi_sq2:>10.2f}  {'PASS - looks uniform (good ciphertext)' if chi_sq2 < threshold else 'FAIL - non-uniform (patterns may be present)'}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <plaintext_file> <encrypted_file>")
        sys.exit(1)
    print_distribution(sys.argv[1], sys.argv[2])
