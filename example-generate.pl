#!/usr/bin/perl

use warnings;
use strict;

use Crypt::PBKDF2MinimalDeps;

unless ((scalar(@ARGV) >= 1)) {
    die("Please supply at least one command-line argument, the password that you want to store.")
}

print <<ENDOFTEXT;
Note that subsequent runs will not generate the same output, unless you
provide a salt value. In general, you should not provide a salt value. If you
want to test with different salt values, supply a second option on the command
line.

ENDOFTEXT


my $pbkdf2 = Crypt::PBKDF2MinimalDeps->new(
    # Only HMACSHA1 is supported, so this is no
    # longer an option:
    # hash_class => 'HMACSHA1'

    iterations => 60000,    # Use 60,000 iterations instead of our default of 128,000.
                            # Note that Crypt::PBKDF2 defaults to 1000 iterations, but this is
                            # changed here as per recommendation at https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet )
                        
                            # IF THINGS ARE SLOW, REDUCE THE ITERATIONS AFTER INVESTIGATING BEST PRACTICE YOURSELF.
                            # Note that you should almost certainly never go less than 10,000 in 2013

    output_len => 20,       # Default to 20 characters of output

    salt_len => 8,          # Defaults to 8 (Crypt::PBKDF2 defaults to 4)
);

print "Generating hash\n";
my $hash = $pbkdf2->generate($ARGV[0], $ARGV[1]);
                                            # $random_salt_string may be supplied as second parameter, but we suggest you let
                                            # us create a default one, unless you have a good source of randomness.
                                            #
                                            # Note that we use the default perl random number generator as a source of
                                            # salt, which isn't perfect, but matches Crypt::PBKDF2


print "Hash of '$ARGV[0]' is $hash\n";
