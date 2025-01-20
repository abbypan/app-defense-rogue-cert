#!/usr/bin/perl

#my ($f) = @ARGV;

my @dom = qw/100 1k 1w 5w/;

for my $d (@dom){
    my $f = "data/dom_$d.txt";
    system(qq[perl gen_dom_json.pl "$f" "$f.json"]);
    system(qq[python gen_crtatt.py "$f.json"]);
    system(qq[kernprof -o "$f.json.sig.verify.lprof" -l verify_crtatt.py "$f.json.sig"]);
    system(qq[python -m line_profiler -rmt "$f.json.sig.verify.lprof" | tee "$f.json.sig.verify.lprof.txt"]);
    system(qq[python -m memory_profiler verify_crtatt.py "$f.json.sig" | tee "$f.json.sig.verify.memory.txt"]);
}
