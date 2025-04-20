#!/usr/bin/perl
use JSON;
use File::Slurp qw/slurp write_file/;

my ($f) = @ARGV;


my $c = slurp($f);
my @cc = split /\n/, $c;

my @crs;
for my $citem (@cc){
  my $appid = "appid.$citem";

  my $cr = {
      'appid' =>  $appid,
      'data' =>  [ {
              'dom' =>  [ $citem, '*.'.$citem ],
              'cadom' =>  [ 'example.com', '! someother.org' ]
          } ]
  };
  push @crs, $cr;
}


my $r = {
        'attdom' =>  'www.someatt.com',
        'version' =>  'v20250325150000',
        'expire' =>  '2025-04-25 15:00:00',
        'refresh' =>  259200,
        'content' => \@crs, 
};

my $rc = encode_json $r;

my $dst_f = "$f.json";
write_file($dst_f, $rc);
