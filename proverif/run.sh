#!/bin/bash    

proverif -lib base.pvl asproc_bgp_hijacking.pv | tee result/asproc_bgp_hijacking.log
proverif -lib base.pvl asproc_dns_hijacking.pv | tee result/asproc_dns_hijacking.log
proverif -lib base.pvl asproc_mitm.pv | tee result/asproc_mitm.log

proverif -lib base.pvl tls_bgp_hijacking.pv | tee result/tls_bgp_hijacking.log
proverif -lib base.pvl tls_dns_hijacking.pv | tee result/tls_dns_hijacking.log
proverif -lib base.pvl tls_mitm.pv | tee result/tls_mitm.log
