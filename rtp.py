#!/usr/bin/env python
#
# The checksum computation code is from Scapy's utils.py in Python 2.7.
# Copyright notice from Scapy:
#
# """See http://www.secdev.org/projects/scapy for more informations
#    Copyright (C) Philippe Biondi <phil@secdev.org>
#   This program is published under a GPLv2 license"""
#
# (Note that the URL has changed to https://www.secdev.org/scapy/ since
# the above copyright notice was listed.)
#
# For the rest of it:
# Python-EIGRP (http://python-eigrp.googlecode.com)
# Copyright (C) 2013 Patrick F. Allen
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.


"""Reliable Transport Protocol implementation for Twisted."""

import struct
import array
import ipaddr
import copy
import time
import logging
from collections import deque
from twisted.internet import protocol
import logging.config
import binascii

from tw_baseiptransport import reactor
import rtptlv
import util

class ReliableTransportProtocol(protocol.DatagramProtocol):
    """An implementation of the Reliable Transport Protocol and Neighbor
    Discovery/Recovery used with EIGRP."""

    DEFAULT_HT_MULTIPLIER = 3

    def __init__(self, system, logconfig, multicast_ip="224.0.0.10", port=0,
                 kvalues=None, rid=0, asn=0, hello_interval=5, hdrver=2):
        """system - The system interface to use
        logconfig - The logging config file to use
        multicast_ip - The multicast IP to use
        port - The port to use, if applicable
        kvalues - A list of values that must match before establishing a
                  neighbor relationship (when used with EIGRP these are
                  metric weights)
        rid - The router ID
        asn - The autonomous system number
        hello_interval - Hello interval. Also influences neighbor timeout
        hdrver - The version of the RTP header to use
        """
        # XXX Should probably figure out Twisted's log observers and use that.

        self._init_logging(logconfig)
        self._sys = system

        if hdrver == 2:
            self._rtphdr = RTPHeader2
        else:
            raise ValueError("Unsupported header version: {}".format(hdrver))

        self._init_ifaces()
        asn_rid_err_msg = "{} must be a positive number less than 65536."
        if not isinstance(rid, int):
            raise TypeError(asn_rid_err_msg.format("Router ID"))
        if not 0 <= rid < 65536:
            raise ValueError(asn_rid_err_msg.format("Router ID"))
        if not isinstance(asn, int):
            raise TypeError(asn_rid_err_msg.format("AS Number"))
        if not 0 <= asn < 65536:
            raise ValueError(asn_rid_err_msg.format("AS Number"))
        self._rid = rid
        self._asn = asn
        self.__ht_multiplier = self.DEFAULT_HT_MULTIPLIER
        self.__seq = 0
        self._multicast_ip = multicast_ip
        self._port = port

        # Holdtime must fit in a 16 bit field, so the hello interval could
        # in theory be set to a max of 65535/HT_MULTIPLIER. Since this is
        # measured in seconds, in reality it will be set much shorter.
        max_hello_interval = 65535 / self.__ht_multiplier
        if not 1 <= hello_interval <= max_hello_interval:
            raise(ValueError("hello_interval must be between 1 and "
                             "{}".format(max_hello_interval)))

        self.__hello_interval = hello_interval
        self.__holdtime = self.__hello_interval * self.__ht_multiplier

        if not kvalues:
            # Allow kvalues to be effectively ignored if the upper layer
            # protocol doesn't need it.
            self._k1 = 0
            self._k2 = 0
            self._k3 = 0
            self._k4 = 0
            self._k5 = 0
        elif len(kvalues) != 5:
            raise ValueError("Exactly 5 K-values must be present.")
        elif not sum(kvalues):
            raise ValueError("At least one kvalue must be non-zero.")
        else:
            try:
                for k in kvalues:
                    if not 0 <= k <= 255:
                        raise ValueError("Each kvalue must be between 0 and "
                                         "255.")
            except TypeError:
                raise TypeError("kvalues must be an iterable.")
            self._k1 = kvalues[0]
            self._k2 = kvalues[1]
            self._k3 = kvalues[2]
            self._k4 = kvalues[3]
            self._k5 = kvalues[4]

        self._tlvfactory = rtptlv.TLVFactory()
        self._tlvfactory.register_tlvs([rtptlv.TLVParam,
                                        rtptlv.TLVAuth,
                                        rtptlv.TLVSeq,
                                        rtptlv.TLVVersion,
                                        rtptlv.TLVMulticastSeq])
        self.__update_hello_tlvs()
        reactor.callWhenRunning(self.__send_periodic_hello)

    def activate_iface(self, req_iface):
        """Enable EIGRP to send from the specified interface."""
        for iface in self._ifaces:
            if req_iface == iface.logical_iface.ip.ip.exploded:
                iface.activated = True
                self.log.debug("Activated iface {}".format(req_iface))
                return
        raise ValueError("Requested IP %s is unusable. (Is it assigned to this"
                         " machine on a usable interface?)" % req_iface)

    def _init_logging(self, configfile):
        util.create_extended_debug_log_levels()
        logging.config.fileConfig(configfile)
        self.log = logging.getLogger("RTP")
        util.suppress_reactor_not_running()

    def _init_ifaces(self):
        self._ifaces = list()
        for iface in self._sys.logical_ifaces:
            self._ifaces.append(RTPInterface(iface,
                                             self.__send_rtp_multicast,
                                             self._rtphdr))

    def __send_periodic_hello(self):
        self.log.debug2("Sending periodic hello.")
        for iface in self._ifaces:
            if iface.activated:
                self.__send_hello(iface)
        reactor.callLater(self.__hello_interval, self.__send_periodic_hello)

    def __send_hello(self, iface):
        iface.send(self._rtphdr.OPC_HELLO, self.__hello_tlvs, False)

    def __send_init(self, neighbor):
        neighbor.send(self._rtphdr.OPC_UPDATE, [], True,
                      self._rtphdr.FLAG_INIT)

    def __update_hello_tlvs(self):
        """Called to create the hello packet's TLVs that should be sent at
        every hello interval. This should be called at startup and whenever
        the k-values or holdtime changes."""
        # XXX self._new_kvalues should be implemented by subclass if it
        # wants to do something when the kvalues change. When all of the
        # kvalue logic is moved into EIGRP this won't be needed, but for
        # now it is.
        self._new_kvalues()
        self.__hello_tlvs = rtptlv.TLVParam(self._k1,
                                            self._k2,
                                            self._k3,
                                            self._k4,
                                            self._k5,
                                            self.__holdtime)

    def _new_kvalues(self):
        """Override in subclass to be alerted when the kvalues change. This
        won't be needed when the kvalue logic is moved into EIGRP."""
        pass

    def __rtp_found_neighbor(self, neighbor):
        self.log.debug("Neighbor {} UP, iface {}".format(neighbor,
                                                         neighbor.iface))
        self.foundNeighbor(neighbor)

    def __rtp_lost_neighbor(self, neighbor, send_upper):
        """Drop this neighbor. Optionally tell the upper layer the neighbor
        was lost. We don't tell the upper layer that the neighbor was lost if
        we never said the neigbor was UP to begin with."""
        self.log.debug("Neighbor {} DOWN, iface {}".format(neighbor,
                                                           neighbor.iface))
        if send_upper:
            self.log.debug("Notifying upper layer.")
            self.lostNeighbor(neighbor)
        else:
            self.log.debug("Not notifying upper layer.")
        neighbor.iface.del_neighbor(neighbor)

    def __send_explicit_ack(self, neighbor):
        self.log.debug5("Sending explicit ACK.")
        hdr = self._rtphdr(opcode=self._rtphdr.OPC_HELLO, flags=0, seq=0,
                           ack=neighbor.next_ack, rid=self._rid,
                           asn=self._asn)
        msg = RTPPacket(hdr, []).pack()
        self.__send(msg, neighbor.ip.exploded, self._port)

    def __get_input_iface(self, ip):
        """Get the interface on which this IP address should reside
        (according to reverse path lookup, not the kernel's ancillary data).

        Returns (iface, host_local) tuple. host_local is True if the IP
        address is assigned to this device, otherwise False."""
        ip = ipaddr.IPv4Address(ip)
        for iface in self._ifaces:
            if ip in iface.logical_iface.ip:
                return (iface, iface.logical_iface.ip.ip.exploded == \
                        ip.exploded)
        return None, False

    def __add_neighbor(self, addr, iface):
        """Add a neighbor to the list of neighbors.
        Return the new neighbor object, or None on failure."""
        addr = ipaddr.IPv4Address(addr)
        found_iface = False
        for iface in self._ifaces:
            if addr in iface.logical_iface.ip:
                found_iface = True
                break
        if not found_iface:
            self.log.debug("Preventing adjacency with non-link-local "
                           "neighbor.")
            return None
        neighbor = RTPNeighbor(ip=addr,
                               iface=iface,
                               rtphdr=self._rtphdr,
                               log=self.log,
                               dropfunc=self.__rtp_lost_neighbor,
                               make_pkt=self.__make_pkt,
                               sendfunc=self.__send_rtp_unicast,
                               kvalues=[self._k1,
                                        self._k2,
                                        self._k3,
                                        self._k4,
                                        self._k5])
        iface.add_neighbor(neighbor)
        return neighbor

    def __get_seq(self):
        # XXX Deal with sequence number wrapping.
        self.__seq += 1
        return self.__seq

    def __send_rtp_unicast(self, neighbor, pkt):
        """Send an RTP packet as a unicast.
        neighbor - The neighbor to send to
        pkt - The RTP packet to send
        """
        # Note: This doesn't handle sequencing. To send sequenced packets to
        # a neighbor, call RTPNeighbor._pushrtp. That handles the transmission
        # queue.
        self.log.debug5("Sending unicast to {}: {}".format(neighbor.ip, pkt))
        pkt.hdr.ack = neighbor.next_ack
        neighbor.next_ack = 0
        msg = pkt.pack()
        self.__send(msg, neighbor.ip.exploded, self._port)

    def __send_rtp_multicast(self, iface, opcode, tlvs, ack, flags=0):
        """Send an RTP packet as a multicast.
        iface - The interface object to send from
        opcode - The opcode number to use in the RTP header
        tlvs - An iterable of TLVs to send
        ack - If the packet requires an acknowledgment
        """
        pkt = self.__make_pkt(opcode, tlvs, ack, flags)
        self.log.debug5("Sending multicast out iface {}: {}".format(iface, \
                        pkt))
        if ack:
            seq_ips = list()
            for neighbor in iface.get_all_neighbors():
                # If neighbor has a full queue, add it to a seq tlv
                if neighbor.queue_full():
                    seq_ips.append(str(neighbor.ip.packed))
                # We only really need to copy the hdr since the tlvs won't
                # change, but copy the whole thing anyway.
                neighbor.schedule_multicast_retransmission(copy.deepcopy(pkt))
            if seq_ips:
                self.__send_seq_tlv(iface, seq_ips, pkt.hdr.seq)
                pkt.hdr.flags |= self._rtphdr.FLAG_CR
        self.__send(pkt.pack(), self._multicast_ip, self._port,
                    iface.logical_iface.ip)

    def __send(self, msg, ip, port, src=None):
        if src:
            self.transport.setOutgoingInterface(src.ip.exploded)
        self.transport.write(msg, (ip, port))

    def __send_seq_tlv(self, iface, seq_ips, next_seq):
        """Send a sequence TLV listing the given IP addresses, and a next
        multicast sequence TLV listing.

        iface - The interface to send from
        seq_ips - An iterable of packed addresses to be included in the
                  seq TLV listing
        next_seq - The next multicast sequence number
        """
        # Note: In Cisco IOS 12.4 (EIGRP ver 1.2), this is sent along with
        # a parameters TLV (as in a periodic hello). It "should" be ok
        # to not do that.
        tlvs = [ rtptlv.TLVSeq(*seq_ips), \
                 rtptlv.TLVMulticastSeq(next_seq)
               ]
        iface.send(self._rtphdr.OPC_HELLO, tlvs, False)

    def __make_pkt(self, opcode, tlvs, ack, flags=0):
        """Generate an RTP packet.
        opcode - The RTP opcode number
        tlvs - An iterable of TLVs
        ack - If an ack is required for this packet
        """
        if ack:
            seq = self.__get_seq()
        else:
            seq = 0
        hdr = self._rtphdr(opcode=opcode, flags=flags, seq=seq, ack=0,
                           rid=self._rid, asn=self._asn)
        pkt = RTPPacket(hdr, tlvs)
        return pkt

    def _cleanup(self):
        self._sys.cleanup()

    # Twisted-specific methods below, hence the change to camelCase.

    def startProtocol(self):
        for iface in self._ifaces:
            if iface.activated:
                self.transport.joinGroup(self._multicast_ip,
                                         iface.logical_iface.ip.ip.exploded)

    def stopProtocol(self):
        self.log.info("RTP is shutting down.")
        self._cleanup()

    def foundNeighbor(self, neighbor):
        """Called when a neighbor adjacency is established."""
        pass

    def lostNeighbor(self, neighbor):
        """Called when a neighbor has timed out or should otherwise be
        considered unreachable. This is called before removing the neighbor
        from its interface."""
        pass

    def datagramReceived(self, data, addr_and_port):
        # XXX Currently only expecting to ride directly over IP, so we
        # ignore the unused port argument. Should remove this restriction.
        addr = addr_and_port[0]
        port = addr_and_port[1]
        self.log.debug("Receiving datagram from {}:{}.".format(addr, port))
        iface, host_local = self.__get_input_iface(addr)
        if host_local:
            self.log.debug("Ignoring host-local packet.")
            return
        if not iface:
            self.log.warn("Received datagram from non-link-local host: "
                          "{}".format(addr))
        try:
            hdr = self._rtphdr(data[:self._rtphdr.LEN])
        except struct.error:
            bytes_to_print = self._rtphdr.LEN
            self.log.warn("Received malformed datagram from {}. Hexdump of "
                          "first {} bytes: {}".format(addr, bytes_to_print, \
                          binascii.hexlify(data[:bytes_to_print])))
            return

        # RFC 1071:
        # "To check a checksum, the 1's complement sum is computed over the
        # same set of octets, including the checksum field.  If the result
        # is all 1 bits (-0 in 1's complement arithmetic), the check
        # succeeds."
        if RTPPacket.checksum(data) != 0xffff:
            self.log.debug("Dropping packet with bad checksum.")
            return
        if hdr.ver != self._rtphdr.VER:
            self.log.debug("Received incompatible header version "
                           "{} from addr {}.".format(hdr.VER, addr))
            return

        payload = data[self._rtphdr.LEN:]

        # XXX Catch and log exceptions from factory
        tlvs = self._tlvfactory.build_all(payload)

        # Create neighbor if it doesn't exist.
        neighbor = iface.get_neighbor(addr)
        if not neighbor:
            self.log.debug("Packet received from non-neighbor.")
            if hdr.opcode != self._rtphdr.OPC_HELLO:
                self.log.debug("Received unexpected opcode {} from "
                               "non-neighbor.".format(hdr.opcode))
                return
            # If a param TLV isn't present, don't add the neighbor.
            found_param = False
            for tlv in tlvs:
                if isinstance(tlv, rtptlv.TLVParam):
                    found_param = True
            if not found_param:
                self.log.debug("Param TLV not present in initial hello. "
                               "Dropping packet.")
                return
            neighbor = self.__add_neighbor(addr, iface)
            if not neighbor:
                self.log.debug("Failed to add neighbor.")
                return
            self.__send_hello(neighbor.iface)
            self.__send_init(neighbor)

        self.log.debug5("Header: {}".format(hdr))
        for tlv in tlvs:
            self.log.debug5("TLV: {}".format(tlv))

        neighbor_receive_status = neighbor.receive(hdr, tlvs)
        if neighbor_receive_status == neighbor.PROCESS:
            self.log.debug5("Passing packet to upper layer for processing.")
            self.rtpReceived(neighbor, hdr, tlvs)
        elif neighbor_receive_status == neighbor.DROP:
            self.log.debug5("RTP stopped processing for this packet.")
        elif neighbor_receive_status == neighbor.INIT:
            self.initReceived(neighbor)
        elif neighbor_receive_status == neighbor.NEW_ADJACENCY:
            # XXX Probably don't need this, use InitReceived
            self.__rtp_found_neighbor(neighbor)
        else:
            assert False, "Unknown RTP Neighbor receive status: " \
                          "{}".format(neighbor_receive_status)

        # If an ACK is needed and one wasn't sent by RTP.send (i.e. no reply
        # has been sent yet by upper layer), send an explicit ack.
        if neighbor.next_ack:
            self.__send_explicit_ack(neighbor)
            neighbor.next_ack = 0


class RTPPacket(object):

    """A packet used with RTP. Consists of a header plus zero or more
    fields."""

    def __init__(self, hdr, fields):
        self.hdr = hdr
        try:
            iter(fields)
        except TypeError:
            self.fields = [fields]
        else:
            self.fields = fields

    def __str__(self):
        return "RTPPacket(hdr=" + str(self.hdr) + ", fields=" + \
               str(self.fields) + ")"

    def pack(self):
        self.hdr.chksum = 0
        prehdr = self.hdr.pack()
        fields = ""
        for f in self.fields:
            fields += f.pack()
        self.hdr.chksum = self.checksum(prehdr + fields)
        hdr = self.hdr.pack()
        return hdr + fields

    # Checksum functions are from Python2.7's utils.py. Copyright notice from
    # Scapy:
    ## This file is part of Scapy
    ## See http://www.secdev.org/projects/scapy for more informations
    ## Copyright (C) Philippe Biondi <phil@secdev.org>
    ## This program is published under a GPLv2 license
    # (Note that the URL has changed to https://www.secdev.org/scapy/ since
    # the above copyright notice was listed.)
    if struct.pack("H", 1) == "\x00\x01": # big endian
        @staticmethod
        def checksum(pkt):
            if len(pkt) % 2 == 1:
                pkt += "\0"
            s = sum(array.array("H", pkt))
            s = (s >> 16) + (s & 0xffff)
            s += s >> 16
            s = ~s
            return s & 0xffff or 0xffff
    else:
        @staticmethod
        def checksum(pkt):
            if len(pkt) % 2 == 1:
                pkt += "\0"
            s = sum(array.array("H", pkt))
            s = (s >> 16) + (s & 0xffff)
            s += s >> 16
            s = ~s
            return (((s>>8)&0xff)|s<<8) & 0xffff or 0xffff


class RTPHeader2(object):
    """Reliable Transport Protocol Header (header version 2)."""

    FORMAT = ">BBHIIIHH"
    LEN    = struct.calcsize(FORMAT)
    VER    = 2

    OPC_UPDATE   = 1
    OPC_REQUEST  = 2
    OPC_QUERY    = 3
    OPC_REPLY    = 4
    OPC_HELLO    = 5
    OPC_PROBE    = 7
    OPC_SIAQUERY = 10
    OPC_SIAREPLY = 11

    FLAG_INIT = 1
    FLAG_CR   = 2

    def __init__(self, raw=None, opcode=None, flags=None, seq=None, ack=None,
                 rid=None, asn=None):
        if raw and \
           opcode == None and \
           flags  == None and \
           seq    == None and \
           ack    == None and \
           rid    == None and \
           asn    == None:
            self.unpack(raw)
        elif not raw and \
             opcode != None and \
             flags  != None and \
             seq    != None and \
             ack    != None and \
             rid    != None and \
             asn    != None:
            self.opcode = opcode
            self.flags = flags
            self.seq = seq
            self.ack = ack
            self.rid = rid
            self.asn = asn
            self.chksum = 0
            self.ver = self.VER
        else:
            raise(ValueError("Either 'raw' is required, or all other arguments"
                             " are required."))

    def __str__(self):
        return("RTPHeader2(ver={version}, "
                          "opc={opcode}, "
                          "flg={flags}, "
                          "seq={seq}, "
                          "ack={ack}, "
                          "asn={asn}, "
                          "rid={rid})".format(version=self.ver,
                                              opcode=self.opcode,
                                              flags=self.flags,
                                              seq=self.seq,
                                              ack=self.ack,
                                              asn=self.asn,
                                              rid=self.rid))

    def unpack(self, raw):
        """Note that self.ver could be different than self.VER if you use
        this on raw data. If there is ever a new header version, would
        be nice to make a factory like there is for TLVs."""
        self.ver, self.opcode, self.chksum, self.flags, self.seq, \
             self.ack, self.rid, self.asn = struct.unpack(self.FORMAT, raw)

    def pack(self):
        return struct.pack(self.FORMAT, self.VER, self.opcode, self.chksum,
                           self.flags, self.seq, self.ack, self.rid,
                           self.asn)


class RTPNeighbor(object):
    """A neighbor learned via neighbor discovery."""

    # Return codes for receive
    DROP          = 1
    INIT          = 2
    PROCESS       = 3
    NEW_ADJACENCY = 4

    def __init__(self, ip, iface, rtphdr, log, dropfunc,
                 make_pkt, sendfunc, kvalues):
        """
        ip - IP address of this neighbor
        iface - Logical interface this neighbor was heard on
        seq - Current sequence number we have received from this neighbor
        rtphdr - The RTP header class to use
        log - A log function
        dropfunc - The function to call if this neighbor should be dropped
        make_pkt - A function that will generate an RTP packet
        sendfunc - A function to call every time a packet is (re)transmitted
        kvalues - The k-values needed in order to form an adjacency
        """
        self.iface = iface
        self.ip = ipaddr.IPv4Address(ip)
        self._queue = deque()
        self._state_receive = self._pending_receive
        self.last_heard = time.time()
        self._cr_mode = False
        self._rtphdr = rtphdr
        self._dropfunc = dropfunc
        self.log = log
        self._make_pkt = make_pkt
        self._write = sendfunc
        self.update_kvalues(kvalues)

        # waiting_for_reply is a list populated/maintained by the upper layer.
        # Intended use is to track which QUERY TLVs the neighbor has replied
        # to.
        # Example for EIGRP: If we QUERY for 3 networks, all three networks
        # are added to the waiting_for_reply list for each neighbor.
        # When a REPLY is received from the neighbor, every network that
        # was contained in the reply is removed from the waiting_for_reply
        # list.
        # When EIGRP checks if all replies have been received for a network,
        # it checks every neighbor to see if that network exists in this list.
        # If the network exists, then EIGRP is still waiting for a reply.
        self.waiting_for_reply = list()

        # Holdtime will be updated when we process the first TLV param
        self._holdtime = -1

        # This should be updated by the packet that causes us to be
        # initialized. So this event will be rescheduled to the neighbor's real
        # holdtime before control is passed back to Twisted.
        self._drop_event = reactor.callLater(10, self._drop_self)

        # The next ack number we should send to this neighbor. Not the same
        # as seq_to because this will change to 0 after we send an ack.
        self.next_ack = 0

        # XXX Support non-zero port
        self.port = 0

        # XXX Update to a variable retransmit timer
        self._retransmit_timer = .2
        self._max_retransmit_seconds = 5

        # seq_to is the last non-zero sequence number we sent to this neighbor
        self._seq_to = -1

        # seq_from is the last sequence number we received from this neighbor
        self._seq_from = -1

        self._next_multicast_seq = 0

        self._init_ack = 0

    def _drop_self(self):
        # If we're still pending, then the upper layer doesn't know about us,
        # so don't tell them that we were lost.
        if self._state_receive == self._up_receive:
            self._dropfunc(self, send_upper=True)
        elif self._state_receive == self._pending_receive:
            self._dropfunc(self, send_upper=False)

    def update_kvalues(self, kvalues):
        self._k1 = kvalues[0]
        self._k2 = kvalues[1]
        self._k3 = kvalues[2]
        self._k4 = kvalues[3]
        self._k4 = kvalues[3]
        self._k5 = kvalues[4]

    def queue_full(self):
        """Returns True if the transmit queue is full. There is a window of 1,
        so if anything is in the queue it is considered full.
        Otherwise returns False."""
        return len(self._queue) != 0

    def receive(self, hdr, tlvs):
        """Deals with updating last heard time and processing ACKs.
        Sends hdr and tlvs to _pending_receive if in PENDING state, or
        _up_receive when adjacency is fully formed.

        Returns one of:
            RTPNeighbor.PROCESS if the packet should be processed by the upper
                                layer (as far as RTP is concerned)
            RTPNeighbor.DROP if the packet should be dropped
            RTPNeighbor.INIT if this neighbor needs to be initialized
            RTPNeighbor.NEW_ADJACENCY if the neighbor transitioned to UP"""
        self.next_ack = hdr.seq

        # If we're not in CR mode, drop CR-enabled packets.
        # If we are in CR mode, only accept CR-enabled packets if the RTP
        # sequence number is what we were expecting.
        if hdr.flags & self._rtphdr.FLAG_CR:
            if not self._cr_mode:
                self.log.debug5("CR flag set and we are not in CR mode. "
                                "Drop packet.")
                return self.DROP
            elif hdr.seq == self._next_multicast_seq:
                self._cr_mode = False
                self._next_multicast_seq = 0
            else:
                # CR mode is set but packet didn't have the sequence number
                # that we saw in the Next Multicast Seq TLV. Either the
                # remote router is misbehaving or possibly we're receiving
                # copies of an old packet (L2 loop?).
                self.log.debug("Unexpected multicast sequence number received "
                               "in CR mode. Got {}, expected {}."
                               "".format(hdr.seq, self._next_multicast_seq))
                return self.DROP

        # This will cause last_heard to be updated when we receive
        # an ACK in addition to when we receive a periodic hello. In reality
        # that's probably fine, but maybe not technically expected behavior
        # per the spec.
        if hdr.opcode == self._rtphdr.OPC_HELLO:
            if not self._handle_hello_tlvs(hdr, tlvs):
                return self.DROP
        return self._state_receive(hdr, tlvs)

    def _handle_hello_tlvs(self, hdr, tlvs):
        """Handle TLVs that are contained within a hello packet.
        Return True if the packet should be processed further, otherwise
        return False."""
        # XXX We should let the upper layer parse this stuff that isn't RTP-
        # specific like the Parameter TLV. For neighbor formation, it would
        # be nice to provide a way for RTP to send non-RTP TLVs that are
        # received in a hello packet to the upper layer and let the upper
        # layer tell us if we should form a neighbor or not. This would be
        # good because:
        # 1. Upper layer may want to send something other than the Param
        #    TLV. (For example, Cisco boxes send a Version TLV so they know
        #    what EIGRP features they can use.)
        # 2. Since the Param TLV doesn't always make sense for an upper layer,
        #    it would be nice to not send it in the packet unless it's needed.
        for tlv in tlvs:
            if tlv.type == rtptlv.TLVSeq.TYPE:
                self._handle_hello_seq_tlv(hdr, tlv)
            elif tlv.type == rtptlv.TLVMulticastSeq.TYPE:
                self._handle_hello_multicastseq_tlv(hdr, tlv)
            elif tlv.type == rtptlv.TLVParam.TYPE:
                if self._handle_hello_param_tlv(hdr, tlv) == False:
                    return False
        return True

    def _handle_hello_param_tlv(self, hdr, tlv):
        """Checks advertised kvalues against our own.
        Returns True if we should continue processing, otherwise returns
        False."""
        if self._holdtime != tlv.param.holdtime:
            self._update_holdtime(tlv.param.holdtime)
        if tlv.param.k1 != self._k1 or \
           tlv.param.k2 != self._k2 or \
           tlv.param.k3 != self._k3 or \
           tlv.param.k4 != self._k4 or \
           tlv.param.k5 != self._k5:
            self.log.debug("Kvalue mismatch between potential "
                           "neighbor. Neighbor kvalues: {}, {}, {}, "
                           "{}, {}".format(tlv.param.k1, tlv.param.k2, \
                           tlv.param.k3, tlv.param.k4, tlv.param.k5))
            return False
        self._update_last_heard()
        return True

    def _update_holdtime(self, holdtime):
        self.log.debug5("Changing holdtime for neighbor {} to "
                        "{}".format(self, holdtime))
        self._holdtime = holdtime

    def _handle_hello_seq_tlv(self, hdr, tlv):
        for addr in tlv.seq.addrs:
            if self.iface.logical_iface.ip.packed == addr:
                self._cr_mode = False
                return
        self._cr_mode = True

    def _handle_hello_multicastseq_tlv(self, hdr, tlv):
        self._next_multicast_seq = tlv.multicastseq.seq

    def _update_last_heard(self):
        self.last_heard = time.time()
        self._drop_event.reset(self._holdtime)

    def _pending_receive(self, hdr, tlvs):
        """Receive function that is used when the adjacency is PENDING."""
        # Look for an ACK to our INIT packet to transition to UP.
        if hdr.opcode == self._rtphdr.OPC_HELLO and \
           not hdr.ack:
            self.log.debug5("Hello received. Do init.")
            return self.INIT
        # Don't process packets that are not HELLO or ACK.
        if not hdr.ack:
            return self.DROP
        curmsg = self._peekrtp()
        if not curmsg:
            # We got an ACK but we weren't waiting for an ACK.
            # We should still let the upper layer process the packet.
            self.log.debug("Received spurious ACK from neighbor {}. "
                           "Header: {}".format(self, hdr))
            return self.DROP
        if hdr.ack == curmsg.hdr.seq:
            self.log.debug5("Received ACK {} for INIT pkt {}. Bringing "
                            "adjacency up".format(hdr.ack, self._peekrtp()))
            self._poprtp()
            self._retransmit_event.cancel()

            # We shouldn't have anything queued up while PENDING
            assert not self._peekrtp(), "Packet was queued in PENDING state"
            self._state_receive = self._up_receive
            return self.NEW_ADJACENCY
        self.log.debug5("Expected ACK for {}, but got "
                        "{}.".format(curmsg.hdr.seq, hdr.ack))
        return self.DROP

    def _handle_ack(self, hdr):
        if not hdr.ack:
            return self.PROCESS
        curmsg = self._peekrtp()
        if not curmsg:
            # We got an ACK but we weren't waiting for an ACK.
            # We should still let the upper layer process the packet.
            self.log.debug("Received spurious ACK from neighbor {}. "
                           "Header: {}".format(self, hdr))
            return self.PROCESS
        if hdr.ack == curmsg.hdr.seq:
            self.log.debug5("Received ACK {} for pkt {}"
                            "".format(hdr.ack, self._peekrtp()))
            self._poprtp()
            self._retransmit_event.cancel()
            if self._peekrtp():
                self._retransmit(time.time())
        else:
            # We should still process the packet in this case.
            self.log.debug5("Expected ACK for {}, but got "
                            "{}.".format(curmsg.hdr.seq, hdr.ack))
        return self.PROCESS

    def _up_receive(self, hdr, tlvs):
        """Receive function that is used when the adjacency is UP."""
        # In the UP state, request that an ACK be sent for any sequenced
        # packet that we receive.
        # If self.next_ack is 0, then we won't send an ack (see how RTP.receive
        # handles it), so it's ok if hdr.seq is 0 here.
        self.next_ack = hdr.seq
        if hdr.seq and \
           hdr.seq == self._seq_from:
            # We already received this packet, but our ack was dropped. Ack
            # but don't process. In some unexpected mode of operation,
            # it's possible that we could receive SEQ x from this neighbor,
            # then the neighbor rapidly increments its global SEQ number
            # by talking to some other neighbor. When it sends us
            # its next sequenced packet it has wrapped back to SEQ x
            # and we drop and ack the packet. That would be wrong to do.
            # Seems extremely unlikely for EIGRP, but could be more likely for
            # other protocols built on RTP.
            self.log.debug5("Received dupe packet, seq {}".format(hdr.seq))
            return self.DROP
        self._seq_from = hdr.seq
        return self._handle_ack(hdr)

    def schedule_multicast_retransmission(self, pkt):
        """Schedule the retransmission of a multicast packet as a unicast."""
        # Note: This is basically self._pushrtp except if the queue is empty
        # we don't send a unicast immediately. This is because we've already
        # sent the packet as a multicast in the caller.
        # XXX For this reason, perhaps pushrtp can be refactored so that it
        # does not need to call write() either - then we could just call
        # pushrtp here. The caller would always call write.
        if not self._peekrtp():
            self._seq_to = pkt.hdr.seq
            self._retransmit_event = reactor.callLater(self._retransmit_timer,
                                                 self._retransmit, time.time())
        self._queue.appendleft(pkt)

    def send(self, opcode, tlvs, ack, flags=0):
        """Wrapper for ReliableTransportProtocol.__send_rtp_unicast.
        opcode - The RTP opcode number to use
        tlvs - An iterable of TLVs to send
        ack - If the packet requires an ack or not

        Note that if you are using RTP for sequencing and acknowledgements,
        ack needs to be set to True. If ack is set to False, RTP does not
        set ack/seq values in the RTP header, which means this packet
        effectively behaves like UDP.
        """
        # XXX I've looked at this before, but it would be really nice to make
        # the _write function (__send_rtp_unicast) responsible for calling
        # _make_pkt so that (a) I don't need to pass in a _make_pkt function,
        # and (b) so that RTPNeighbor behaves the same as RTPInterface when
        # sending a packet. I remember having a reason that I didn't do it that
        # way, perhaps something to do with needing ack to be set beforehand,
        # but I don't recall why now.
        #
        # If the usage must be different, it should be called out and
        # documented better because it is potentially confusing.
        pkt = self._make_pkt(opcode, tlvs, ack, flags)
        if not ack:
            # If an ack is not required, just send the packet.
            # Note that we pass in "self" as the neighbor argument.
            self._write(neighbor=self,
                        pkt=pkt)
        else:
            self._pushrtp(pkt)

    def _poprtp(self):
        """Pop an RTP packet off of the transmission queue and return it,
        or return None if there are no messages enqueued."""
        try:
            return self._queue.pop()
        except IndexError:
            return None

    def _pushrtp(self, pkt):
        """Push an RTP packet onto the transmission queue. This should only
        be used for packets that require an acknowledgement."""
        if not self._peekrtp():
            self._seq_to = pkt.hdr.seq
            # Note that we pass in "self" as the neighbor argument.
            self._write(neighbor=self,
                        pkt=pkt)
            self._retransmit_event = reactor.callLater(self._retransmit_timer,
                                                self._retransmit, time.time())
        self._queue.appendleft(pkt)

    def _retransmit(self, init_time, first_call=True):
        """Retransmit the current RTP packet.
        init_time - The time this was first called
        first_call - If this is the first time this function was called for
                     the current packet. (Should always be True when called
                     by anything other than this function.)
        """
        if not first_call:
            self.log.debug("Retransmitting: {}".format(self._peekrtp()))
        self._write(self, self._peekrtp())

        # If the next retransmit attempt will not exceed the max retrans time,
        # then schedule another retransmission.
        if init_time + self._max_retransmit_seconds > \
                       time.time() + self._retransmit_timer:
            self._retransmit_event = reactor.callLater(self._retransmit_timer,
                                                       self._retransmit,
                                                       init_time,
                                                       False)
        else:
            # I think we should drop the neighbor if we can't transmit to it.
            # DUAL won't operate correctly if RTP drops a sequenced
            # message.
            self.log.debug("Retransmit timer exceeded, dropping neighbor.")
            self._drop_event.cancel()
            self._drop_self()

    def _peekrtp(self):
        """Return the next RTP packet in the transmission queue without
        removing it, or None if the queue is empty."""
        # We append to the left side and pop from the right side.
        try:
            return self._queue[-1]
        except IndexError:
            return None


class RTPInterface(object):

    """An RTP logical interface."""

    def __init__(self, logical_iface, writefunc, rtphdr):
        """
        logical_iface - The logical interface to use
        writefunc - The function to use when sending packets from this
                    interface
        """
        self._neighbors = dict()
        self.logical_iface = logical_iface
        self._write = writefunc
        self._rtphdr = rtphdr
        self.activated = False

    def get_all_neighbors(self):
        return self._neighbors.values()

    def __str__(self):
        return self.logical_iface.ip.ip.exploded + " (" + \
               self.logical_iface.phy_iface.name + ")"

    def add_neighbor(self, neighbor):
        """Add neighbor object to this interface."""
        self._neighbors[neighbor.ip.exploded] = neighbor

    def get_neighbor(self, ip):
        """Get neighbor with the IP address 'ip'."""
        try:
            return self._neighbors[ip]
        except KeyError:
            return None

    def del_neighbor(self, neighbor):
        """Remove neighbor from this interface."""
        self._neighbors.pop(neighbor.ip.exploded, None)

    def send(self, opcode, tlvs, ack, flags=0):
        """Send an RTP multicast from this interface.
        opcode - The opcode number to use in the RTP header
        tlvs - An iterable of TLVs to send
        ack - The packet requires an acknowledgment. If True, retransmissions
              will be queued for all neighbors on this interface.
        """
        # Check if self.activated?
        # Stats (multicast packets sent)?
        # Call _send_rtp_multicast. Note that we pass in 'self' as the iface
        # argument.
        self._write(iface=self,
                    opcode=opcode,
                    tlvs=tlvs,
                    ack=ack,
                    flags=flags)
