#!/usr/bin/perl
use strict;
use warnings;

my $dir ="."; 

my @doms = qw/
www.baidu.com
www.alipay.com
/;


system(qq[crip print -f pem -u=https://$_ >$dir/$_.pem]) for @doms;
system(qq[crip print -u=https://$_ >$dir/$_.txt]) for @doms;
