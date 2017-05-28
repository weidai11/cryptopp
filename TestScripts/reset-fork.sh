#!/usr/bin/env bash

# Use this script to reset a fork to Wei Dai's master
# https://stackoverflow.com/questions/9646167/clean-up-a-fork-and-restart-it-from-the-upstream

git remote add upstream https://github.com/weidai11/cryptopp 2>/dev/null
git fetch upstream
git checkout master
git reset --hard upstream/master
git push origin master --force
