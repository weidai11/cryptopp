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

my $DEBUG32_CXXFLAGS = "/nologo /DDEBUG";
my $RELEASE32_CXXFLAGS = "/nologo /DNDEBUG";
my $DEBUG64_CXXFLAGS = "/nologo /DDEBUG";
my $RELASE64_CXXFLAGS = "/nologo /DNDEBUG";

system('nmake.exe', '/f', 'cryptest.nmake', 'clean');
system('nmake', '/f', 'cryptest.nmake', "CXXFLAGS=\"$DEBUG32_CXXFLAGS\"");
