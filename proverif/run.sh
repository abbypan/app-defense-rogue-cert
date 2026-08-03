#!/bin/sh
set -eu

proverif -lib base.pvl aspin_bgp_hijacking.pv | tee result/aspin_bgp_hijacking.log
proverif -lib base.pvl aspin_dns_hijacking.pv | tee result/aspin_dns_hijacking.log
proverif -lib base.pvl aspin_mitm.pv | tee result/aspin_mitm.log
proverif -lib base.pvl aspin_cache.pv | tee result/aspin-cache.log

proverif -lib base.pvl tls_bgp_hijacking.pv | tee result/tls_bgp_hijacking.log
proverif -lib base.pvl tls_dns_hijacking.pv | tee result/tls_dns_hijacking.log
proverif -lib base.pvl tls_mitm.pv | tee result/tls_mitm.log

python3 check_consistency.py
