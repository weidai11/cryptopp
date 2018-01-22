#!/usr/bin/env bash

# Use this script to switch back to the previous Crypto++ version before
# building the docs. Before running the script, copy it to the root
# directory. After running this script, you can 'make docs'

sed -i 's|Library 6.1 API|Library 6.0 API|g' cryptlib.h
sed -i 's|= 6.1|= 6.0|g' Doxyfile
sed -i 's|CRYPTOPP_VERSION 610|CRYPTOPP_VERSION 600|g' config.h
