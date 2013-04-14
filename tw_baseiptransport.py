#!/usr/bin/env python

"""Twisted base class to support arbitrary IP transport protocols."""

# Most of this code was lifted out of Twisted's twisted.internet.udp.Port
# class, with minor modifications to make it work for raw IP sockets instead
# of UDP sockets. Copyright notice and license from Twisted:
#
# Twisted, the Framework of Your Internet
# Copyright (c) 2001-2011 Twisted Matrix Laboratories.
# See LICENSE for details.
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import struct
import socket
from twisted.internet import fdesc, base, udp, main, reactor
from twisted.python import log

from twisted.python.runtime import platformType
if platformType == 'win32':
    from errno import WSAEWOULDBLOCK as EWOULDBLOCK
    from errno import WSAEINTR as EINTR
    from errno import WSAEMSGSIZE as EMSGSIZE
    from errno import WSAECONNREFUSED as ECONNREFUSED
    from errno import WSAECONNRESET
    EAGAIN = EWOULDBLOCK
else:
    from errno import EWOULDBLOCK, EINTR, EMSGSIZE, ECONNREFUSED, EAGAIN

def listenIP(self, port, protocol, interface='', maxPacketSize=8192):
    p = IPTransport(port, protocol, interface, maxPacketSize, self)
    p.startListening()
    return p
reactor.listenIP = listenIP

# Open for suggestions on a name other than IPTransport. The other examples
# I had were UDPPort and TCPPort -- clearly IPPort isn't a better option.
# Maybe IPSocket?
class IPTransport(udp.MulticastMixin, udp.Port):
    """Provides IP services for layer 4 transport protocols.

    Protocols that use IPTransport will receive and send data directly over
    IP. That is, your protocol doesn't have to deal with anything related
    to the IP layer other than to determine which IP address to send data to.
    This is useful as a way to provide userspace support for layer 4 protocols
    that are not implemented in most kernels -- such as OSPF or EIGRP -- within
    the Twisted framework.

    Using IPTransport is pretty much the same as using UDPPort, except
    IPTransport takes care of some other IP-related validation during doRead.
    
    """
    addressFamily = socket.AF_INET
    socketType = socket.SOCK_RAW

    def __init__(self, port, proto, interface='', maxPacketSize=8192,
                 reactor=None):
        base.BasePort.__init__(self, reactor)
        self.port = port
        self.protocol = proto
        self.maxPacketSize = maxPacketSize
        self.interface = interface
        self.setLogStr()
        self._connectedAddr = None

    def createInternetSocket(self):
        s = socket.socket(self.addressFamily, self.socketType, self.port)
        s.setblocking(0)
        fdesc._setCloseOnExec(s.fileno())
        return s

    def doRead(self):
        read = 0
        while read < self.maxThroughput:
            try:
                data, addr = self.socket.recvfrom(self.maxPacketSize)
            except socket.error, se:
                no = se.args[0]
                if no in (EAGAIN, EINTR, EWOULDBLOCK):
                    return
                if (no == ECONNREFUSED) or (platformType == "win32" and no == WSAECONNRESET):
                    if self._connectedAddr:
                        self.protocol.connectionRefused()
                else:
                    raise
            else:
                read += len(data)
                try:
                    # Strip IP header (including IP options) before passing to
                    # transport protocol.
                    if len(data) < 1:
                        log.msg("Received invalid packet with data length less than 1 from host %s." % addr[0])
                        continue
                    iphdrlen = (ord(data[0]) & 0x0f) << 2
                    if iphdrlen < 20:
                        log.msg("Received malformed packet. IP header len too small: %d bytes" % iphdrlen)
                        continue
                    if len(data) <= iphdrlen:
                        log.msg("Received malformed or empty packet from host %s." % addr[0])
                        continue
                    totallen = struct.unpack("H", data[3:5])[0]
                    if len(data) != totallen:
                        log.msg("Received malformed or partial packet from host %s, total length field didn't match received data length." % addr[0])
                        continue
                    self.protocol.datagramReceived(data[iphdrlen:], addr)
                except:
                    log.err()
