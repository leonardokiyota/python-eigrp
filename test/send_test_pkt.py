#!/usr/bin/env python

import socket
import sys
sys.path.append("..")

import eigrp

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 88)
hdr = eigrp.RTPHeader2(hdrver=2, opcode=eigrp.RTPHeader2.OPC_HELLO, flags=0, seq=0, ack=0, rid=0, asn=0)
fields = eigrp.StubFields()
pkt = eigrp.RTPPacket(hdr, fields)
s.sendto(pkt.pack(), ("10.99.1.100", 0))
