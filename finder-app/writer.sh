#!/bin/sh

# Check for the correct number of arguments
if [ "$#" -ne 2 ]; then
    echo "Error: Two arguments required. Usage: $0 <writefile> <writestr>"
    exit 1
fi

writefile="$1"
writestr="$2"

# Extract directory path from the full file path
dirpath=$(dirname "$writefile")

# Create directory if it doesn't exist
mkdir -p "$dirpath"
if [ $? -ne 0 ]; then
    echo "Error: Failed to create directory path '$dirpath'"
    exit 1
fi

# Attempt to write to the file
echo "$writestr" > "$writefile"
if [ $? -ne 0 ]; then
    echo "Error: Failed to write to file '$writefile'"
    exit 1
fi

exit 0