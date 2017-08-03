#!/usr/bin/env bash

# Use this script to switch back to the previous Crypto++ version before
# building the docs. Before running the script, copy it to the root
# directory. After running this script, you can 'make docs'

gsed -i 's|Library 6.0 API|Library 5.6.5 API|g' cryptlib.h
gsed -i 's|= 6.0.0|= 5.6.5|g' Doxyfile
gsed -i 's|CRYPTOPP_VERSION 600|CRYPTOPP_VERSION 565|g' config.h
