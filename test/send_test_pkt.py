#!/usr/bin/env python

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 88)
s.sendto("hi", ("127.0.0.1", 0))
