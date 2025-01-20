#!/usr/bin/perl
use File::Slurp qw/slurp write_file/;

my ($f) = @ARGV;
$f ||= 'avg.all';

#system(q[find succ -name '*-default-*.log' -exec Rscript avg.default.R {} \;]);
#system(q[find succ -name '*-bypass-*.log' -exec Rscript avg.default.R {} \;]);
#system(q[find succ -name '*-ctca-*.log' -exec Rscript avg.ctca.R {} \;]);

#system(q[find fail -name '*-default-*.log' -exec Rscript avg.default.R {} \;]);
#system(q[find fail -name '*-bypass-*.log' -exec Rscript avg.default.R {} \;]);
#system(q[find fail -name '*-ctca-*.log' -exec Rscript avg.ctca.R {} \;]);


my @num = qw/100 1k 1w 5w/;
my @all = (join(",", qw/num type avg median/)."\n");
for my $n (@num){
    system(qq[cat */*-$n-*.stat > $f.$n]);
    system(qq[Rscript avg.all.R $f.$n]);
    my $c = slurp("$f.$n.csv"); 
    my @data = map { "$n,$_\n" } (split /\n/, $c);
    push @all, @data;
}

write_file("$f.csv", @all);
