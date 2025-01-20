#!/usr/bin/perl
use POSIX qw/strftime/;

my $time = strftime("%Y%m%d%H%m%s", localtime);

#system(qq[java -jar target/jmh-benchmarks.jar benchmarkDefault | tee target/default-$t.log]);
#system(qq[java -jar target/jmh-benchmarks.jar benchmarkCTCA | tee target/ctca-$t.log]);

my ($res) = @ARGV;
$res ||= 'succ';

my @ss = qw/ctcanon.example.com 
 mwnwybmalhbwjpzyewypeu.com
 mm9jt.com
 cuuq2.com
 pxne950omdpznp.com
 /;

my @dom = qw/100 1k 1w 5w/;

my $repeat = 1000;


for my $s (@ss){
    for my $d (@dom){
        for my $i ( 1 .. $repeat){

            print "\r$s,$d,$t: $i                                                        ";
            system(qq[java -jar ctca/target/ctca-0.0.1-SNAPSHOT.jar https://$s ctca data/dom_$d.txt.json.sig.cache >> log/$res/ctca-$d-ctca-$time.log]);
            system(qq[java -jar ctca/target/ctca-0.0.1-SNAPSHOT.jar https://$s default >> log/$res/ctca-$d-default-$time.log]);
            system(qq[java -jar ctca/target/ctca-0.0.1-SNAPSHOT.jar https://$s bypass >> log/$res/ctca-$d-bypass-$time.log]);

        }
    }
}
