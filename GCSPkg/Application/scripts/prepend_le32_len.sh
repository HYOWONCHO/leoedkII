#!/bin/sh
# prepend_size_le32.sh
# Usage: ./prepend_size_le32.sh <input_file> <output_file>
# Output: [4-byte LE32 size][input_file contents]

set -eu

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <input_file> <output_file>" >&2
  exit 1
fi

in="$1"
out="$2"

if [ ! -f "$in" ]; then
  echo "Error: input file not found: $in" >&2
  exit 1
fi

size=$(stat -c%s "$in")

b0=$((  size        & 0xFF ))
b1=$(( (size >>  8) & 0xFF ))
b2=$(( (size >> 16) & 0xFF ))
b3=$(( (size >> 24) & 0xFF ))

# POSIX-safe: use octal escapes (\ooo), then printf %b to emit binary bytes
hdr=$(printf '\\%03o\\%03o\\%03o\\%03o' "$b0" "$b1" "$b2" "$b3")

{
  printf '%b' "$hdr"
  cat "$in"
} > "$out"
