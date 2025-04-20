#!/usr/bin/perl

#my ($f) = @ARGV;

my @dom = qw/10 100 1k/;

for my $d (@dom){
    my $f = "data/dom_$d.txt";
    system(qq[perl gen_dom_json.pl "$f" "$f.json"]);
    system(qq[python3 gen_crtatt.py "$f.json"]);
    system(qq[kernprof -o "$f.json.sig.verify.lprof" -l verify_crtatt.py "$f.json.sig"]);
    system(qq[python3 -m line_profiler "$f.json.sig.verify.lprof" | tee "$f.json.sig.verify.lprof.txt"]);
    system(qq[python3 -m memory_profiler verify_crtatt.py "$f.json.sig" | tee "$f.json.sig.verify.memory.txt"]);
}
