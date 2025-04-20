#!/usr/bin/perl
use POSIX qw/strftime/;

my $time = strftime("%Y%m%d%H%m%s", localtime);

#system(qq[java -jar target/jmh-benchmarks.jar benchmarkDefault | tee target/default-$t.log]);
#system(qq[java -jar target/jmh-benchmarks.jar benchmarkCTCA | tee target/ctca-$t.log]);

my ($res) = @ARGV;
$res ||= 'fail';

my @ss = (
	[ 'ctcanon.example.com', 'unknown' ],
	[ 'zsttloofgu.nl',  $res ], 
	[ 'wgjixfysn1.life', $res ], 
);

#my @ss = qw/ctcanon.example.com 
# zsttloofgu.nl
# wgjixfysn1.life
# kslbhlyfgamkp.gq
# c0x915.casa
# /;

my @num = qw/10 100 1k/;

my $repeat = 1000;

for my $s (@ss){
	my ($d, $dir) = @$s;
        for my $i ( 1 .. $repeat){

		for my $n (@num){
			print "\r$d,$dir,$t: $i";
			system(qq[java -jar ctca/target/ctca-0.0.1-SNAPSHOT.jar https://$d ctca data/dom_$n.txt.json.sig.cache appid.$d >> log/$dir/ctca-$d-$n-ctca-$time.log]);
			system(qq[java -jar ctca/target/ctca-0.0.1-SNAPSHOT.jar https://$d default  data/dom_$n.txt.json.sig.cache appid.$d >> log/$dir/ctca-$d-$n-default-$time.log]);
			system(qq[java -jar ctca/target/ctca-0.0.1-SNAPSHOT.jar https://$d bypass  data/dom_$n.txt.json.sig.cache appid.$d >> log/$dir/ctca-$d-$n-bypass-$time.log]);
		}
        }
    }
