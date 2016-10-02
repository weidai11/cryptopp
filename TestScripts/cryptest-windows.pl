#!/usr/bin/env perl

# cryptest-windows.sh - written and placed in public domain by Jeffrey Walton and Uri Blumenthal.
#                       Thanks to Grant McLean on Stack Overflow for help with Perl and string handling.
#                       Copyright assigned to Crypto++ project.

# This is a test script that can be used on some Windows machines to automate building the
# library and running the self test with various combinations of flags, options, and conditions.
# For more details, see http://cryptopp.com/wiki/cryptest-windows.pl.

# To run the script, copy cryptest-windows.pl from TestScripts to the root and then perform the following:
#     .\cryptest-windows.pl

use strict;
use warnings;

# Clean previous artifacts
system('rmdir.exe', '/q', '/s', "Win32", "x64", "ipch");
system('nmake.exe', '/f', 'cryptest.nmake', 'clean');

# Enable multiple jobs in Nmake
ENV{CL}="/MP";

# Perl and redirection appears hopelessy broke or hopelessly complex. Take your pick.
my $LOG_FILE = "cryptest-result.txt";
system('del.exe', '/q', "$LOG_FILE");

# Choices include SSE2, AVX (VS2013) and AVX2 (VS2015)
my $ARCH = "/arch:AVX";

my $DEBUG_RUNTIME_CXXFLAG = "/MDd";
my $RELEASE_RUNTIME_CXXFLAG = "/MD";

my $BASE_CXXFLAGS = "/nologo /W4 /wd4511 /D_MBCS /Zi /TP /GR /EHsc /MP /fp:precise /FI sdkddkver.h";
my $DEBUG_CXXFLAGS = "$BASE_CXXFLAGS $DEBUG_RUNTIME_CXXFLAG /DDEBUG /D_DEBUG /Oi /Oy- /Od";
my $RELEASE_CXXFLAGS = "$BASE_CXXFLAGS $RELEASE_RUNTIME_CXXFLAG /DNDEBUG /D_NDEBUG /Oi /Oy /O2";

my BASE_LDFLAGS = "";

system('nmake.exe', '/f', 'cryptest.nmake', 'clean');
my $ret = system('nmake.exe', '/f', 'cryptest.nmake', "CXXFLAGS=\"$DEBUG_CXXFLAGS $ARCH\"");
