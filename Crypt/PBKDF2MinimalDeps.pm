package Crypt::PBKDF2MinimalDeps;

=pod

=head1 NAME

Crypt::PBKDF2MinimalDeps - a partial implementation of Crypt::PBKDF2 with minimal dependencies

=head1 VERSION

version 1.0

=head1 SYNOPSIS

    use Crypt::PBKDF2MinimalDeps;

    my $pbkdf2 = Crypt::PBKDF2MinimalDeps->new(
        # Only HMACSHA1 is supported, so this is no
        # longer an option:
        # hash_class => 'HMACSHA1'
        
        iterations => 60000,    # Use 60,000 iterations instead of our default of 128,000.
                                # Note that Crypt::PBKDF2 defaults to 1000 iterations, which is now too
                                # low in 2013.
                                
                                # IF THINGS ARE SLOW, REDUCE THE ITERATIONS AFTER INVESTIGATING BEST PRACTICE YOURSELF.
                                # Note that you should almost certainly never go less than 10,000 in 2013

        output_len => 20,       # Default to 20 characters of output
        
        salt_len => 8,          # Defaults to 8 (Crypt::PBKDF2 defaults to 4)
    );

    my $hash = $pbkdf2->generate("s3kr1t_password");    # $random_salt_string may be supplied as second parameter
    if ($pbkdf2->validate($hash, "s3kr1t_password")) {
        access_granted();
    }


=head1 AUTHOR

Oskar Pearson <oskar@qualica.com>


=head1 COPYRIGHT AND LICENSE

This is free software; you can redistribute it and/or modify it under the same
terms as the Perl 5 programming language system itself.

Portions Copyright Qualica Technologies Pty Ltd 2013

Portions Copyright Anthony Thyssen as per
http://www.ict.griffith.edu.au/anthony/software/pbkdf2.pl, which was based on:

Portions Copyright 2004, 2005, 2006, 2007 Andrew Fresh, All Rights Reserved as
per http://search.cpan.org/~andrew/Palm-Keyring-0.95/lib/Palm/Keyring.pm


I (Oskar Pearson at Qualica) have mostly kept the API the same as
Crypt-PBKDF2, and used parts of that code, which is Copyright (c) 2011 by
Andrew Rodland as perl
http://search.cpan.org/~arodland/Crypt-PBKDF2-0.112020/lib/Crypt/PBKDF2.pm In
certain cases I've tried to use safer defaults (eg many many more iterations)


=head1 NO WARRANTY

This code has no warranty. You are directed towards the Perl license at
http://dev.perl.org/licenses/ - for terms and conditions of use.

=cut

use strict;
use warnings;
use Digest::HMAC_SHA1 qw(hmac_sha1);                # sudo apt-get install libdigest-hmac-perl
use MIME::Base64 ();

use Carp qw(confess);

sub new {
    my ($class,%p) = @_;
    
    if (($p{hash_class}) && ($p{hash_class} ne 'HMACSHA1')) {
        confess("hash_class option is not supported in $class - only 'HMACSHA1' is supported");
    }
    unless (exists($p{output_len}) && defined($p{output_len})) {
        $p{output_len} = 20;
    }

    unless ($p{salt_len}) {
        $p{salt_len} = 8;           # Increased from the default 4 from Crypt::PBKDF2 so that it matches the 64 bits of salt
                                    # the NIST document refers to
    }
    unless (exists($p{iterations}) && defined($p{iterations})) {
        $p{iterations} = 128000;
    }
    
    my $self = bless {map {'_'.$_ => $p{$_}} (keys %p)},$class;
    
    return $self;
}

sub generate {
    my ($self, $password, $salt) = @_;
    unless (defined($salt)) {
        $salt = $self->_random_salt();
    }
    
    my $hash = $self->_pbkdf2(
        $password,
        $salt,
        $self->{_iterations},
        $self->{_output_len},
        \&hmac_sha1
    );
    # {X-PBKDF2}HMACSHA1:AAAQAA:c2EAbHQ=:Vvpqp1VICZ3MN9fwNCXgw38cQrI=
    # {X-PBKDF2} METHOD : ITERATIONS : SALT : HMAC
    
    my $response =
        '{X-PBKDF2}' .
        'HMACSHA1' .
        ':' . $self->_b64_encode_int32( $self->{_iterations} ) .
        ':' . $self->_mime_encode($salt) .
        ':' . $self->_mime_encode($hash);

    return $response;
    
}

sub _mime_encode {
    my ($self, $x) = @_;
    my $response = MIME::Base64::encode( $x );
    chomp($response);
    return $response;
}

sub validate {
    my ($self, $hashed, $password) = @_;
    
    my $info = $self->_decode_string_ldaplike($hashed);
    # algorithm => $algorithm,
    # algorithm_options => $opts,
    # iterations => $self->_b64_decode_int32($iterations),
    # salt => MIME::Base64::decode($salt),
    # hash => MIME::Base64::decode($hash),    
    
    my $class = ref($self);
    my $new_object = $class->new(
        hash_class => 'HMACSHA1',
        iterations => $$info{iterations},
        output_len => length($$info{hash})
    );
    
    my $comparative_hash = $new_object->generate($password, $$info{salt});

    if ($hashed eq $comparative_hash) {
        return 1;
    } else {
        return 0;
    }
}



# Thanks go to http://www.ict.griffith.edu.au/anthony/software/pbkdf2.pl for this method
########################################################################################
sub _pbkdf2($$$$$$)
{
    my ($self, $password, $salt, $iter, $keylen, $prf) = @_;

    my ($k, $t, $u, $ui, $i);
    $t = "";
    for ($k = 1; length($t) <  $keylen; $k++) {
    $u = $ui = &$prf($salt.pack('N', $k), $password);
    for ($i = 1; $i < $iter; $i++) {
        $ui = &$prf($ui, $password);
        $u ^= $ui;
    }
    $t .= $u;
    }
    return substr($t, 0, $keylen);
}
# END OF http://www.ict.griffith.edu.au/anthony/software/pbkdf2.pl methods
########################################################################################


# Thanks go to http://cpansearch.perl.org/src/ARODLAND/Crypt-PBKDF2-0.112020/lib/Crypt/PBKDF2.pm for these methods
##################################################################################################################
sub _b64_encode_int32 {
    my ($self, $value) = @_;
    my $b64 = MIME::Base64::encode(pack("N", $value), "");
    $b64 =~ s/==$//;
    return $b64;
}
sub _b64_decode_int32 {
    my ($self, $b64) = @_;
    $b64 .= "==";
    return unpack "N", MIME::Base64::decode($b64);
}
sub _decode_string_ldaplike {
  my ($self, $hashed) = @_;
  if ($hashed !~ /^\{X-PBKDF2}/i) {
    croak("Unrecognized hash - this library only supports X-PBKDF2");
  }

  if (my ($algo_str, $iterations, $salt, $hash) = $hashed =~
      /^\{X-PBKDF2}([^:]+):([^:]{6}):([^\$]+):(.*)/i) {

        my ($algorithm, $opts) = split /\+/, $algo_str;
        return {
            algorithm => $algorithm,
            algorithm_options => $opts,
            iterations => $self->_b64_decode_int32($iterations),
            salt => MIME::Base64::decode($salt),
            hash => MIME::Base64::decode($hash),
        };
  } else {
    croak("Invalid format");
  }
}
sub _PBKDF2_hex {
  my ($self, $value) = @_;
  return unpack "H*", unpack "A*", $value;
}
sub _random_salt {
    my ($self) = @_;
    my $ret = "";
    for my $n (1 .. $self->{_salt_len}) {
        $ret .= chr(int rand 256);
    }
    return $ret;
}
# END OF http://cpansearch.perl.org/src/ARODLAND/Crypt-PBKDF2-0.112020/lib/Crypt/PBKDF2.pm
##################################################################################################################


1;

__END__
