#!/usr/bin/env bash

# make-benchmarks - Scan build submission instructions for Unix and Linux.
#                   Written and placed in public domain by Jeffrey Walton and Uri Blumenthal.
#                   Copyright assigned to Crypto++ project.
#
# The following builds the benchmarks under 5.6.2, 5.6.4 and Master. The results can then be
#  compared to ensure an speed penalty is not inadvertently taken. Crypto++ 5.6.2 is significant
#  because its the last version Wei worked on before turning the library over to the community.

###############################################################################

# Set to suite your taste. Speed is in GiHz

if [[ -z "$CPU_FREQ" ]]; then
	if [[ ! -z "CRYPTOPP_CPU_SPEED" ]]; then
		CPU_FREQ="$CRYPTOPP_CPU_SPEED"
	else
		CPU_FREQ=2.8
	fi
fi

echo "***************************************************"
echo "Using CPU frequency of $CPU_FREQ GiHz."
echo "Please modify this script if its not correct"
echo

###############################################################################

current=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
git fetch --all &>/dev/null &>/dev/null
if [[ "$?" -ne "0" ]]; then
	echo "$PWD does not appear to be a Git repository"
	[[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

###############################################################################
# Try to find a fast option

OPT=

if [[ -z "$OPT" ]]; then
	rm -f "$TMP/adhoc.exe" &>/dev/null
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -O3 adhoc.cpp -o "$TMP/adhoc.exe" &>/dev/null
	if [[ ("$?" -eq "0") ]]; then
		OPT=-O3
	fi
fi

if [[ -z "$OPT" ]]; then
	rm -f "$TMP/adhoc.exe" &>/dev/null
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -xO3 adhoc.cpp -o "$TMP/adhoc.exe" &>/dev/null
	if [[ ("$?" -eq "0") ]]; then
		OPT=-xO3
	fi
fi

if [[ -z "$OPT" ]]; then
	rm -f "$TMP/adhoc.exe" &>/dev/null
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -O2 adhoc.cpp -o "$TMP/adhoc.exe" &>/dev/null
	if [[ ("$?" -eq "0") ]]; then
		OPT=-O2
	fi
fi

if [[ -z "$OPT" ]]; then
	rm -f "$TMP/adhoc.exe" &>/dev/null
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -xO2 adhoc.cpp -o "$TMP/adhoc.exe" &>/dev/null
	if [[ ("$?" -eq "0") ]]; then
		OPT=-xO2
	fi
fi

if [[ -z "$OPT" ]]; then
	rm -f "$TMP/adhoc.exe" &>/dev/null
	"$CXX" -DCRYPTOPP_ADHOC_MAIN -O adhoc.cpp -o "$TMP/adhoc.exe" &>/dev/null
	if [[ ("$?" -eq "0") ]]; then
		OPT=-O
	fi
fi

##################################################################

echo "***************************************************"
echo "**************** Crypto++ 5.6.2 *******************"
echo "***************************************************"
echo

git checkout -f CRYPTOPP_5_6_2 &>/dev/null
if [[ "$?" -ne "0" ]]; then
	echo "git checkout CRYPTOPP_5_6_2 failed"
else
	rm -f *.o benchmarks.html benchmarks-562.html &>/dev/null

	CXXFLAGS="-DNDEBUG $OPT" make
	if [[ "$?" -eq "0" ]]; then
		echo "Running benchmarks for Crypto++ 5.6.2"
		./cryptest.exe b 3 "$CPU_FREQ" > benchmarks-562.html
		if [[ "$?" -ne "0" ]]; then
			rm -rf benchmarks-562.html &>/dev/null
			echo "Failed to create benchmarks for Crypto++ 5.6.2"
		fi
	else
		echo "Failed to make benchmarks for Crypto++ 5.6.2"
	fi
fi

##################################################################

echo "***************************************************"
echo "**************** Crypto++ 5.6.4 *******************"
echo "***************************************************"
echo

git checkout -f CRYPTOPP_5_6_4 &>/dev/null
if [[ "$?" -ne "0" ]]; then
	echo "git checkout CRYPTOPP_5_6_4 failed"
else
	rm -f *.o benchmarks.html benchmarks-564.html &>/dev/null

	CXXFLAGS="-DNDEBUG $OPT" make
	if [[ "$?" -eq "0" ]]; then
		echo "Running benchmarks for Crypto++ 5.6.4"
		./cryptest.exe b 3 "$CPU_FREQ" > benchmarks-564.html
		if [[ "$?" -ne "0" ]]; then
			rm -rf benchmarks-564.html &>/dev/null
			echo "Failed to create benchmarks for Crypto++ 5.6.4"
		fi
	else
		echo "Failed to make benchmarks for Crypto++ 5.6.4"
	fi
fi

##################################################################

echo "***************************************************"
echo "*************** Crypto++ Master *******************"
echo "***************************************************"
echo

git checkout -f master &>/dev/null
if [[ "$?" -ne "0" ]]; then
	echo "git checkout master failed"
else
	rm -f *.o benchmarks.html benchmarks-master.html &>/dev/null

	CXXFLAGS="-DNDEBUG $OPT" make
	if [[ "$?" -eq "0" ]]; then
		echo "Running benchmarks for Crypto++ Master"
		./cryptest.exe b 3 "$CPU_FREQ" > benchmarks-master.html
		if [[ "$?" -ne "0" ]]; then
			rm -rf benchmarks-master.html &>/dev/null
			echo "Failed to create benchmarks for Crypto++ Master"
		fi
	else
		echo "Failed to make benchmarks for Crypto++ Master"
	fi
fi

##################################################################

if [[ ! -z "$current" ]]; then
	git checkout -f "$current"
fi

[[ "$0" = "$BASH_SOURCE" ]] && exit 0 || return 0
