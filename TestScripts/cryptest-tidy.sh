#!/usr/bin/env bash

for file in $(find . -maxdepth 1 -type f -name '*.cpp'); do
    echo "Tidying $file"
    clang-tidy $file -checks=-clang-analyzer-optin.cplusplus.VirtualCall -- -std=c++03
done
