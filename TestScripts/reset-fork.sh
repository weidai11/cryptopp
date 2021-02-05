#!/usr/bin/env bash

# Use this script to reset a fork to Wei Dai's master
# https://stackoverflow.com/questions/9646167/clean-up-a-fork-and-restart-it-from-the-upstream
#
# Written and placed in public domain by Jeffrey Walton
#
# Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2)
# licensed under the Boost Software License 1.0, while the individual files
# in the compilation are all public domain.
#

git remote add upstream https://github.com/weidai11/cryptopp 2>/dev/null
git fetch upstream
git checkout master
git reset --hard upstream/master
git push origin master --force
