#!/bin/bash


echo "Running debug mode"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address" || {
    printf '\033[0;31mCMake configuration failed\033[0m\n'; exit 1; }
cmake --build build -j 20 || {
    # print in red
    printf '\033[0;31mBuild failed\033[0m\n'; exit 1; }

