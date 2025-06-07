#!/bin/sh

# Check for the correct number of arguments
if [ "$#" -ne 2 ]; then
    echo "Error: Two arguments required. Usage: $0 <filesdir> <searchstr>"
    exit 1
fi

filesdir="$1"
searchstr="$2"

# Check if filesdir is a valid directory
if [ ! -d "$filesdir" ]; then
    echo "Error: Directory '$filesdir' does not exist."
    exit 1
fi

# Count the number of files
num_files=$(find "$filesdir" -type f | wc -l)

# Count the number of matching lines
num_matches=$(grep -r "$searchstr" "$filesdir" 2>/dev/null | wc -l)

# Output the result
echo "The number of files are $num_files and the number of matching lines are $num_matches"

exit 0