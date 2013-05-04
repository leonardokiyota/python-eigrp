#!/usr/bin/env python

"""Reliable Transport Protocol implementation for Twisted."""

import struct
import ipaddr
from heapq import heappush, heappop

from twisted.internet import fdesc, base, udp, main, reactor
from twisted.python import log
from twisted.internet.main import installReactor

import tlv

DEFAULT_HT_MULTIPLIER = 3

class ReliableTransportProtocol(protocol.DatagramProtocol):
    """An implementation of the Reliable Transport Protocol and Neighbor
    Discovery/Recovery used with EIGRP."""

    def __init__(self, logger, tlvclasses=None, kvalues=None, rid=0, asn=0,
                 hello_interval=5, hdrver=2):
        """logger -- The log object to use
        tlvclasses -- An iterable of TLV classes that the upper layer protocol
                      wishes to receive.
        kvalues -- A list of values that must match before establishing a
                   neighbor relationship (when used with EIGRP these are
                   metric weights).
        rid -- The router ID.
        asn -- The autonomous system number.
        hello_interval -- Hello interval. Also influences neighbor timeout.
        hdrver -- The version of the RTP header to use.
        """
        # XXX Should probably figure out Twisted's log observers and use that.
        asn_rid_err_msg = "%s must be a positive number less than 65536."
        if not isinstance(rid, int):
            raise(TypeError(asn_rid_err_msg % "Router ID"))
        if not (0 <= rid < 65536):
            raise(ValueError(asn_rid_err_msg % "Router ID"))
        if not isinstance(asn, int):
            raise(TypeError(asn_rid_err_msg % "AS Number"))
        if not (0 <= asn < 65536):
            raise(ValueError(asn_rid_err_msg % "AS Number"))
        self._rid = rid
        self._asn = asn
        self._ht_multiplier = self.DEFAULT_HT_MULTIPLIER
        self.log = logger

        # Holdtime must fit in a 16 bit field, so the hello interval could
        # in theory be set to a max of 65535/HT_MULTIPLIER. Since this is
        # measured in seconds, in reality it will be set much shorter.
        max_hello_interval = 65535 / self._ht_multiplier
        if not (1 <= hello_interval <= max_hello_interval):
            raise(ValueError("hello_interval must be between 1 and %d" % \
                             max_hello_interval))

        self._hello_interval = hello_interval
        self._holdtime = self._hello_interval * self._ht_multiplier

        if not kvalues:
            # Allow kvalues to be effectively ignored if the upper layer
            # protocol doesn't need it.
            self._k1 = 0
            self._k2 = 0
            self._k3 = 0
            self._k4 = 0
            self._k5 = 0
        elif len(kvalues) != 5:
            raise(ValueError("Exactly 5 K-values must be present."))
        elif not sum(kvalues):
            raise(ValueError("At least one kvalue must be non-zero."))
        else:
            try:
                for k in kvalues:
                    if not (0 <= k <= 255):
                        raise(ValueError("Each kvalue must be between 0 and "
                                         "255."))
            except TypeError:
                raise(TypeError("kvalues must be an iterable."))
            self._k1 = kvalues[0]
            self._k2 = kvalues[1]
            self._k3 = kvalues[2]
            self._k4 = kvalues[3]
            self._k5 = kvalues[4]

        if hdrver == 2:
            self._rtphdr = RTPHeader2
        else:
            raise(ValueError("Unsupported header version: %d" % hdrver))

        self._rtp_tlvs = [ tlv.TLVParam,        \
                           tlv.TLVAuth,         \
                           tlv.TLVSeq,          \
                           tlv.TLVVersion,      \
                           tlv.TLVMulticastSeq, \
                         ]

        self._tlvfactory = tlv.TLVFactory()
        self._tlvfactory.register_tlvs(self._rtp_tlvs)

        if tlvclasses:
            self._tlvfactory.register_tlvs(tlvclasses)
            self._upperlayer_tlvs = dict()
            for tlv in tlvclasses:
                if tlv in self._upperlayer_tlvs:
                    raise(ValueError("TLV type %d already registered." % \
                                     tlv.TYPE))
                self._upperlayer_tlvs[tlv.TYPE] = tlv

        

    def datagramReceived(self, data, addr_and_port):
        # XXX Currently only expecting to ride directly over IP, so we
        # ignore the unused port argument. We may not always be used directly
        # over IP.
        addr = addr_and_port[0]
        try:    
            hdr = self._rtphdr(data[:self._rtphdr.LEN])
        except struct.error:
            bytes_to_print = self._rtphdr.LEN
            self.log.warn("Received malformed datagram from %s. Hexdump of "
                          "first %d bytes: %s" % (addr, bytes_to_print, \
                          binascii.hexlify(data[:bytes_to_print])))
            return
        observed_chksum = hdr.chksum
        hdr.chksum = 0
        payload = data[self._rtphdr.LEN:]
        real_chksum = RTPPacket.calc_chksum(hdr.pack() + payload)
        if real_chksum != observed_chksum:
            self.log.debug("Bad checksum: expected 0x%x, was 0x%x" % \
                           (addr, real_chksum, real_chksum))
            return
        if hdr.ver != self._rtphdr.VER:
            self.log.warn("Received incompatible header version %d from "
                          "host %s" % (hdr.hdrver, addr))
            return

        # Build TLVs and handle RTP-related messages. Pass to upper layer
        # protocol if the opcode is not specific to RTP.
        tlvs = self._tlvfactory.build_all(payload)
        try:
            handler = self._op_handlers[hdr.opcode]
            handler(addr, hdr, tlvs)
        except KeyError:
            neighbor = self._get_neighbor(addr, hdr)
            if not neighbor:
                self.log.info("Received unexpected opcode %d from " \
                              "non-neighbor %s" % hdr.opcode, addr)
                return
            self.rtpReceived(neighbor, tlvs)
        # Pass desired TLVs to the upper layer. Note that upper layers
        # can request TLVs that are also processed by RTP if they
        # really want to.
        for tlv in tlvs:
            if tlv.TYPE in self_upperlayer_tlvs:
                
            try:
                self.tlvReceived(neighbor, self._upperlayer_tlvs[tlv.TYPE])
            except KeyError:
                self.log.info("Received unhandled TLV type %d from %s." % \
                              (tlv.TYPE, addr))


class RTPPacket(object):
    def __init__(self, hdr, fields):
        self.hdr = hdr
        try:
            iter(fields)
        except TypeError:
            self.fields = [fields]
        else:
            self.fields = fields

    def pack(self):
        self.hdr.chksum = 0
        prehdr = self.hdr.pack()
        fields = ""
        for f in self.fields:
            fields += f.pack()
        self.hdr.chksum = self.calc_chksum(prehdr + fields)
        hdr = self.hdr.pack()
        return hdr + fields

    # Checksum related functions are from:
    # http://stackoverflow.com/questions/1767910/checksum-udp-calculation-python
    @staticmethod
    def calc_chksum(data):
        """Get one's complement of the one's complement sum of data.
        Returns the 16 bit checksum.
        """
        data = map(lambda x: ord(x), data)
        data = struct.pack("%dB" % len(data), *data)
        s = 0
        for i in range(0, len(data), 2):
            w = ord(data[i]) + (ord(data[i+1]) << 8)
            s = RTPPacket.carry_around_add(s, w)
        return ~s & 0xffff

    @staticmethod
    def carry_around_add(a, b):
        c = a + b
        return (c & 0xffff) + (c >> 16)


class RTPHeader2(object):
    """Reliable Transport Protocol Header (header version 2)."""

    FORMAT = ">BBHIIIHH"
    LEN    = struct.calcsize(FORMAT)
    VER    = 2

    OPC_UPDATE   = 1
    OPC_REQUEST  = 2
    OPC_QUERY    = 3  # Should this be 4? RFC says 4 but might be a typo.
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
    """A router learned via neighbor discovery."""

    STATE_PENDING = 1
    STATE_UP      = 2

    def __init__(self, ip, iface, seq, holdtime):
        self.iface = iface
        self.holdtime = holdtime
        self.ip = ipaddr.IPv4Address(ip)
        self.seq = seq
        self.ack = 0
        self.reply_pending = False
        self._queue = list()
        self.state = self.STATE_PENDING
        self.last_heard = time.time()

    def popmsg(self):
        """Pop an RTP message off of the transmission queue."""
        try:
            return heappop(self._queue)
        except IndexError:
            return None

    def pushmsg(self, msg):
        """Push an RTP message onto the transmission queue."""
        return heappush(self._queue, msg)

    def peekmsg(self, msg):
        """Return the RTP message that will be popped on the next popmsg
        call."""
        try:
            return self._queue[0]
        except IndexError:
            return None
