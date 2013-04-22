#!/usr/bin/perl

use warnings;
use strict;

use Crypt::PBKDF2MinimalDeps;

unless ((scalar(@ARGV) == 1)) {
    die("Please supply one command-line argument, the password you want to check. Use 's3kr1t_password' for testing.")
}

my $pbkdf2 = Crypt::PBKDF2MinimalDeps->new();

# This value is stored somewhere - probably in your user table in the password field.
# The 'example-password-for-save.pl' file shows you how to create this.
my $expected_hash = '{X-PBKDF2}HMACSHA1:AADqYA:x4nRhpExTQQ=:UTs9szgZXtd5BVlsX5eE5agGuy0=';

if ($pbkdf2->validate($expected_hash, $ARGV[0])) {
    print "Access GRANTED - supplied password matches $expected_hash\n";
} else {
    print "Access DENIED - supplied password does not match $expected_hash\n";
}
