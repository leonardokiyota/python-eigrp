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

import binascii
import struct
import socket
import sys
from twisted.internet import fdesc, udp, reactor
from twisted.python import log
from twisted.internet.main import installReactor
import twisted

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

# I wanted to extend reactor to support IPTransport while being as non-invasive
# as possible to the original reactor and using no assumptions about
# what reactor type is installed. So the reactor was imported above, now we
# get its class so it can be extended. Deleting it from sys.modules is
# necessary because the reactor code checks if another reactor is already
# installed and will bomb if so. Twisted uses the same 'del' used below to
# deal with importing 'reactor' twice (see reactor.py). So, doing it this way
# seems to be safe.
reactor_class = type(reactor)
del sys.modules['twisted.internet.reactor']
class ExtendedReactor(reactor_class):
    def listenIP(self, port, protocol, interface='', maxPacketSize=8192, listenMultiple=False):
        p = IPTransport(port, protocol, interface, maxPacketSize, self, listenMultiple)
        p.startListening()
        return p

    def listenNetlink(self, port, protocol, netlinkType, interface=1, maxPacketSize=8192, listenMultiple=False):
        p = NetlinkPort(netlinkType, port, protocol, interface, maxPacketSize, self, listenMultiple)
        p.startListening()
        return p
reactor = ExtendedReactor()
installReactor(reactor)


class NetlinkPort(udp.MulticastPort):
    """A Twisted "Port" class used to communicate with netlink sockets."""

    # TODO handle acks/retransmissions

    addressFamily = socket.AF_NETLINK
    socketType = socket.SOCK_RAW

    NETLINK_ROUTE = 0

    def __init__(self, netlinkType, *args, **kwargs):
        """The netlinkType should be the netlink type, e.g. NETLINK_ROUTE.
        Right now only NETLINK_ROUTE is supported.
        """
        if netlinkType != self.NETLINK_ROUTE:
            raise(ValueError("Netlink type {} not "
                             "supported.".format(netlinkType)))
        self.netlinkType = netlinkType
        udp.MulticastPort.__init__(self, *args, **kwargs)

    def createInternetSocket(self):
        s = socket.socket(self.addressFamily, self.socketType, self.netlinkType)
        s.setblocking(0)
        fdesc._setCloseOnExec(s.fileno())
        if self.listenMultiple:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        return s


# Open for suggestions on a name other than IPTransport. Other similar classes
# in Twisted are UDPPort and TCPPort -- clearly IPPort isn't a better option.
# Maybe IPSocket?
class IPTransport(udp.MulticastPort):
    """Provides IP services for layer 4 transport protocols, including
    multicast functionality.

    Protocols that use IPTransport will receive and send data directly over
    IP. That is, your protocol doesn't have to deal with anything related
    to the IP layer other than to determine which IP address to send data to.
    This is useful as a way to provide userspace support for layer 4 protocols
    that are not implemented in most kernels -- such as OSPF or EIGRP -- within
    the Twisted framework.

    Using IPTransport is pretty much the same as using UDPPort.
    """
    addressFamily = socket.AF_INET
    socketType = socket.SOCK_RAW

    def createInternetSocket(self):
        s = socket.socket(self.addressFamily, self.socketType, self.port)
        s.setblocking(0)
        fdesc._setCloseOnExec(s.fileno())
        if self.listenMultiple:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
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
                    # Possibly all of the validation done here is also done
                    # by the kernel. If that is true for raw sockets on all
                    # OSes that Twisted supports (Windows, Linux, Mac OS X,
                    # FreeBSD), then perhaps these checks could be taken out.
                    # If not, there are other validation checks that can be
                    # performed here.
                    if len(data) < 1:
                        log.err("Received invalid packet with data length less than 1 from host %s." % addr[0])
                        continue
                    iphdrlen = (ord(data[0]) & 0x0f) << 2
                    if iphdrlen < 20:
                        log.err("Received malformed packet. IP header len too small: %d bytes" % iphdrlen)
                        continue
                    if len(data) <= iphdrlen:
                        log.err("Received malformed or empty packet from host %s." % addr[0])
                        continue
                    totallen = struct.unpack(">H", data[2:4])[0]
                    if len(data) != totallen:
                        log.err("Received malformed or partial packet from host %s, total length field didn't match received data length." % addr[0])
                        continue
                    self.protocol.datagramReceived(data[iphdrlen:], addr)
                except:
                    log.err()
