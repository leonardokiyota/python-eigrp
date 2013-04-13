#!/usr/bin/env python

import socket
import sys
sys.path.append("..")

import eigrp

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 88)
hdr = eigrp.RTPHeader2(hdrver=2, opcode=10, flags=0, seq=0, ack=0, rid=0, asn=0)
fields = eigrp.StubFields()
pkt = eigrp.RTPPacket(hdr, fields)
s.sendto(pkt.pack(), ("127.0.0.1", 0))
