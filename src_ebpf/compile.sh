#!/bin/bash
#asdas

# 1. Check for the correct number of arguments (4 are needed for your commands)
if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <source.bpf.c> <output.o> <loader.c> <binary_name>"
    echo "Expected 4 arguments, but got $#"
    exit 1
fi

# Assign arguments to descriptive variables for readability
SOURCE_BPF=$1
OBJECT_FILE=$2
LOADER_SRC=$3
BINARY_OUT=$4

# 2. Compile BPF code
# Added -O2 as it is usually required for BPF verification
clang -O2  -mllvm -bpf-stack-size=16384 -D__TARGET_ARCH_x86  -g -target bpf -c "$SOURCE_BPF" -o "$OBJECT_FILE"

# 3. Check if the object file was NOT produced
if [[ ! -f "$OBJECT_FILE" ]]; then 
    echo "Error: Unable to produce object file '$OBJECT_FILE'"
    exit 1
fi

# 4. Compile the loader/user-space program
# Only runs if the previous step succeeded
gcc "$LOADER_SRC" -lbpf -lelf -o "$BINARY_OUT"

if [[ $? -eq 0 ]]; then
    echo "Successfully built: $BINARY_OUT"
else
    echo "Error: GCC compilation failed"
    exit 1
fi


