#!/usr/bin/env bash

# Written and placed in public domain by Jeffrey Walton
#
# This script fetches TweetNaCl from Bernstein's site, and then
# prepares it for use in Crypto++ by applying tweetnacl.patch.
# The script should be run from the Crypto++ root directory on a
# Unix machine because of the use of Unix tools like wget.

curl https://tweetnacl.cr.yp.to/20140427/tweetnacl.h > tweetnacl.h
curl https://tweetnacl.cr.yp.to/20140427/tweetnacl.c > tweetnacl.c

# Fix whitespace
sed -e 's/[[:space:]]*$//' tweetnacl.h > tweetnacl.h.fixed
mv tweetnacl.h.fixed tweetnacl.h
sed -e 's/[[:space:]]*$//' tweetnacl.c > tweetnacl.c.fixed
mv tweetnacl.c.fixed tweetnacl.c

if [[ -e "TestScripts/tweetnacl.patch" ]]; then
    cp "TestScripts/tweetnacl.patch" .
fi

if [[ ! -e "tweetnacl.patch" ]]; then
    echo "Cannot find tweetnacl.patch. Please make sure it exists in the root directory."
	echo "It can be created with 'diff -u tweetnacl.c tweetnacl.cpp > tweetnacl.patch'"
	[[ "$0" = "$BASH_SOURCE" ]] && exit 0 || return 0
fi

# Normalize line endings
dos2unix tweetnacl.h tweetnacl.cpp tweetnacl.patch

# Apply patch
patch --unified --binary -p0 < tweetnacl.patch
mv tweetnacl.c tweetnacl.cpp

# Place things where they belong in source control
cp tweetnacl.sh TestScripts/
cp tweetnacl.patch TestScripts/

# Fix whitespace
sed -e 's/[[:space:]]*$//' tweetnacl.h > tweetnacl.h.fixed
mv tweetnacl.h.fixed tweetnacl.h
sed -e 's/[[:space:]]*$//' tweetnacl.cpp > tweetnacl.cpp.fixed
mv tweetnacl.cpp.fixed tweetnacl.cpp

# Convert to MS DOS for source control
unix2dos tweetnacl.h tweetnacl.cpp
