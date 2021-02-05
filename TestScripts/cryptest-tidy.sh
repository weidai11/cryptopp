#!/usr/bin/env bash

#############################################################################
#
# This script invokes clang-tidy on source files.
#
# Written and placed in public domain by Jeffrey Walton.
#
# Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2)
# licensed under the Boost Software License 1.0, while the individual files
# in the compilation are all public domain.
#
#############################################################################

for file in $(find . -maxdepth 1 -type f -name '*.cpp'); do
    echo "Tidying $file"
    clang-tidy $file -checks=-clang-analyzer-optin.cplusplus.VirtualCall -- -std=c++03
done
