#!/bin/bash
find "$(dirname "$0")" -type f \( -name "*.enc" -o -name "*.dec" -o -name "*.hash" \) -delete
echo "Cleaned up .enc, .dec, and .hash files from demo/"
