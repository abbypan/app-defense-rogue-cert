#!/usr/bin/perl
use JSON;
use File::Slurp qw/slurp write_file/;

my ($f) = @ARGV;


my $c = slurp($f);
my @cc = split /\n/, $c;

my $r = {
    attid => 'example', 
    time => '2025-01-10 18:00:00',
    dgstalg => 'SHA256',
    content => [
        {
            dom => \@cc,
            cadom => [ "example.com", "! someother.org", "! globalsign.com", "! letsencrypt.org" ]
        }
    ]
};
my $rc = encode_json $r;

my $dst_f = "$f.json";
write_file($dst_f, $rc);
