#!/usr/bin/env bash

# Use this script to switch back to the previous Crypto++ version before
# building the docs. Before running the script, copy it to the root
# directory. After running this script, you can 'make docs'

sed 's|Library 7.1 API|Library 7.0 API|g' cryptlib.h > cryptlib.h.new
mv cryptlib.h.new cryptlib.h

sed 's|= 7.1|= 7.0|g' Doxyfile > Doxyfile.new
mv Doxyfile.new Doxyfile

sed 's|CRYPTOPP_VERSION 710|CRYPTOPP_VERSION 700|g' config.h > config.h.new
mv config.h.new config.h
