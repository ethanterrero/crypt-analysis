#!/usr/bin/env python3
"""
Compare two encrypted files byte-by-byte and highlight differences in red.
Usage: python3 demo/hexcompare.py <file1> <file2>
"""

"""
hexcompare demo is visually showing that the salt randomizes output between encryptions 

avalanche test is mathematically measuring HOW WELL the cipher diffuses a tiny input change
"""
import sys

# using ANSI escape codes, tells terminal characters to change color
RED   = "\033[31m"
RESET = "\033[0m"

# passing in the encrypted file ending in .enc 
# reads the raw binary contents so hexcompare can run 
def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()

def hexcompare(file1, file2):
    # handles to both files 
    data1 = read_bytes(file1) # original encrypted file
    data2 = read_bytes(file2) # encrypted file after the 1 bit change
    length = max(len(data1), len(data2))

    changed = 0 # compare byte in file1 to file2, if byte1 != byte2, changed++

    total = 0 # count total bytes in the file, gets incremented on every iteration

    print(f"\n{'Offset':<10} {'--- ' + file1:<40} {'--- ' + file2}")
    print("-" * 80)

    for i in range(0, length, 16): # 16 bytes at a time, 16 bytes per row when hexdump is called
        chunk1 = data1[i:i+16] # splicing form i:i+16, reading that chunk
        chunk2 = data2[i:i+16]

        hex1_parts = []
        hex2_parts = []

        for j in range(16):
            b1 = chunk1[j] if j < len(chunk1) else None
            b2 = chunk2[j] if j < len(chunk2) else None

        
            if b1 is None: 
                hex1_parts.append("  ")
            elif b1 != b2: # bytes don't match, append the red text
                hex1_parts.append(f"{RED}{b1:02x}{RESET}")
            else: # bytes do match, just append it normally 
                hex1_parts.append(f"{b1:02x}")

            if b2 is None:
                hex2_parts.append("  ")
            elif b1 != b2: # bytes don't match, append red text
                hex2_parts.append(f"{RED}{b2:02x}{RESET}")
                changed += 1 # increment change here, comparing b1 relative to b2 (AVOID DOUBLE COUNTING)
            else:
                hex2_parts.append(f"{b2:02x}")
            
            # always incrementing the count if not None
            if b1 is not None or b2 is not None:
                total += 1

        # putting hex data into a string to display it 
        # ["a3", "ff", "1b"] -> "a3 ff 1b"
        hex1_str = " ".join(hex1_parts)
        hex2_str = " ".join(hex2_parts)
        print(f"{i:08x}   {hex1_str}   {hex2_str}")

    # 
    pct = (changed / total * 100) if total > 0 else 0
    print(f"\nBytes changed: {changed}/{total} ({pct:.1f}%) — avalanche effect")

if __name__ == "__main__":
    if len(sys.argv) != 3: # error to display how you should run this python file! 
        print(f"Usage: python3 {sys.argv[0]} <file1> <file2>")
        sys.exit(1)
    hexcompare(sys.argv[1], sys.argv[2])
    # sys.argv[0] = "hexcompare.py"
    # sys.argv[1] = "somefile.txt"
    # sys.argv[2] = "somefile.enc"
    # just grabbing the command line input, should look like this if you run it! 
