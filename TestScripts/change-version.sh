#!/usr/bin/env bash

# Use this script to switch back to the previous Crypto++ version before
# building the docs. Before running the script, copy it to the root
# directory. After running this script, you can 'make docs'

sed 's|Library 8.3 API|Library 8.2 API|g' cryptlib.h > cryptlib.h.new
mv cryptlib.h.new cryptlib.h

sed 's|= 8.3|= 8.2|g' Doxyfile > Doxyfile.new
mv Doxyfile.new Doxyfile

sed 's|CRYPTOPP_MINOR 3|CRYPTOPP_MINOR 2|g' config_ver.h > config_ver.h.new
mv config_ver.h.new config_ver.h

sed 's|CRYPTOPP_VERSION 830|CRYPTOPP_VERSION 820|g' config_ver.h > config_ver.h.new
mv config_ver.h.new config_ver.h
