#!/usr/bin/perl
use File::Slurp qw/slurp write_file/;


my @num = qw/10 100 1k/;
for my $n (@num){
    for my $t (qw/default bypass/){
        system(qq[find . -name '*-$n-$t-*.log' | xargs cat > stat/$t-$n.merge]);
        system(qq[Rscript avg.url.type.R stat/$t-$n.merge]);
        system(qq[Rscript avg.type.R stat/$t-$n.merge]);
    }
}

my @num = qw/10 100 1k/;
for my $n (@num){
    my $t = 'ctca';
    for my $res (qw/succ fail unknown/){
        system(qq[cat $res/*-$n-$t-*.log | grep ',ctca,' > stat/$t-$n.$res.merge]);
        system(qq[Rscript avg.url.type.R stat/$t-$n.$res.merge]);
        system(qq[Rscript avg.type.R stat/$t-$n.$res.merge]);
    }
}

