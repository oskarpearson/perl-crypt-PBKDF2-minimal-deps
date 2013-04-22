perl-crypt-PBKDF2-minimal-deps
==============================

This is a partial implementation of Crypt::PBKDF2 with minimal dependencies on
external libraries. It focuses on generating LDAP-like formatted PBKDF2 hashes.

If you're looking at this, I'd suggest you consider using [Crypt::PBKDF2 on
CPAN
instead](http://search.cpan.org/~arodland/Crypt-PBKDF2-0.112020/lib/Crypt/PBKDF2.pm),
unless you can't install the libraries it depends on.

This code is only a partial re-implementation of that module, with it's
numerous dependencies on things like Moose removed. This code was developed as
a way to get PBKDF2 without having to install numerous packages from source on
an old version of Ubuntu.

Note that this code also only supports PBKDF2 strings in LDAP-LIKE base64
syntax.

License and Warranty
====================

See the accompanying LICENSE.md file for terms of use.


Installation
============

Module Dependencies - Digest::HMAC_SHA1
---------------------------------------

This module requires the the Digest::HMAC_SHA1 perl module.

You should be able to use the version shipped as standard with your operating
system, if it's available at all. You shouldn't need to install the latest
version on Cpan, but if you do, see [Digest::HMAC_SHA1 perl
module](http://search.cpan.org/~gaas/Digest-HMAC-1.03/)

If you're using Debian or Ubuntu, you can install this package with `sudo
apt-get install libdigest-hmac-perl`.


Module Dependencies - MIME::Base64
----------------------------------

This package also needs MIME::Base64. On most machines, this comes installed
as part of Perl.

You should be able to use the version shipped as standard with your operating
system. If you need the latest version, see [Mime::Base64 on
CPAN](http://search.cpan.org/~gaas/MIME-Base64-3.13/Base64.pm).


Installing the Library
----------------------

Place the PBKDF2MinimalDeps.pm file in a subdirectory called 'Crypt' somewhere
in your Perl library path.

For example, if I run `perl -V`, part of the output includes the following:

    @INC:
      /etc/perl
      /usr/local/lib/perl/5.14.2
      /usr/local/share/perl/5.14.2
      /usr/lib/perl5
      /usr/share/perl5
      /usr/lib/perl/5.14
      /usr/share/perl/5.14
      /usr/local/lib/site_perl
      .
  
The most common places to install the package are in your source tree, or in
your 'site_perl' directory. With the example output above, I could install the
file at `/usr/local/lib/site_perl/Crypt/PBKDF2MinimalDeps.pm` or in the path
where your source code lives (i.e. in `./Crypt`).


Usage
=====

* See the file 'example-generate.pl' for an example of creating a hash for password storage into your database.

* See the file 'example-validate.pl' for an example of validating a user's password.

* See the help on the [Crypt::PBKDF2](http://search.cpan.org/~arodland/Crypt-PBKDF2-0.101170/) page


Performance
===========
PBKDF2 is *supposed* to run slower and slower as the years go by. You should change
the 'iterations' value based on Moore's law, and based on the specific hardware
that you're working on.

As an indication:

* in 2013
  [LastPass.com](https://helpdesk.lastpass.com/security-options/password-iterations-pbkdf2/)
  uses 5,000 iterations of SHA-256 (we're only using SHA-1 here, so 5,000 is vastly too low for this library).

* Apple DMG files in 2013 use 250,000 rounds of PBKDF2-HMAC-SHA-1 according to
  [this amusing blog
  post](http://blog.whitehatsec.com/cracking-aes-256-dmgs-and-epic-self-pwnage/)


References
===========

General Information
-------------------
* [NIST Recommendation for Password-Based Key Derivation](http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf)

* [Coding Horror Speed Hashing article](http://www.codinghorror.com/blog/2012/04/speed-hashing.html)

* [Use Bcrypt](http://codahale.com/how-to-safely-store-a-password/) In case you want to avoid PBKDF2

* [Don't use Bcrypt](http://www.unlimitednovelty.com/2012/03/dont-use-bcrypt.html)

Technicalities
--------------
* [OWASP Password Storage Cheat Sheet](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet)

* [StackOverflow questions on HMAC SHA256](http://stackoverflow.com/questions/5781753/perl-code-to-generate-secret-key-for-hmac-sha256-signing)

* [Enough With The Rainbow Tables: What You Need To Know About Secure Password Schemes](http://www.securityfocus.com/blogs/262)

* [Bcrypt vs PBKDF2](http://security.stackexchange.com/questions/4781/do-any-security-experts-recommend-bcrypt-for-password-storage)

* [StackOverflow question the number of iterations for PBKDF2](http://security.stackexchange.com/questions/3959/recommended-of-iterations-when-using-pkbdf2-sha256) - note that this is with SHA256
