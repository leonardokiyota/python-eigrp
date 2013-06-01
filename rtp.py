#!/usr/bin/env python

"""Reliable Transport Protocol implementation for Twisted."""

import struct
import ipaddr
from heapq import heappush, heappop
from twisted.internet import fdesc, base, udp, main, reactor
from twisted.python import log
from twisted.internet.main import installReactor
import copy
import time

import sysiface
import tlv

DEFAULT_HT_MULTIPLIER = 3

class ReliableTransportProtocol(protocol.DatagramProtocol):
    """An implementation of the Reliable Transport Protocol and Neighbor
    Discovery/Recovery used with EIGRP."""

    def __init__(self, logger, multicast_ip, port=0, tlvclasses=None,
                 kvalues=None, rid=0, asn=0, hello_interval=5, hdrver=2):
        """logger -- The log object to use
        multicast_ip -- The multicast IP to ues
        port -- The port to use, if applicable
        tlvclasses -- An iterable of TLV classes that the upper layer protocol
                      wishes to use. These will be registered with RTP's
                      TLV factory
        kvalues -- A list of values that must match before establishing a
                   neighbor relationship (when used with EIGRP these are
                   metric weights)
        rid -- The router ID
        asn -- The autonomous system number
        hello_interval -- Hello interval. Also influences neighbor timeout
        hdrver -- The version of the RTP header to use
        """
        # XXX Should probably figure out Twisted's log observers and use that.

        self.__sys = sysiface.system
        self.__init_ifaces()
        asn_rid_err_msg = "{} must be a positive number less than 65536."
        if not isinstance(rid, int):
            raise(TypeError(asn_rid_err_msg.format("Router ID")))
        if not (0 <= rid < 65536):
            raise(ValueError(asn_rid_err_msg.format("Router ID")))
        if not isinstance(asn, int):
            raise(TypeError(asn_rid_err_msg.format("AS Number")))
        if not (0 <= asn < 65536):
            raise(ValueError(asn_rid_err_msg.format("AS Number")))
        self.__rid = rid
        self.__asn = asn
        self._ht_multiplier = rtp.DEFAULT_HT_MULTIPLIER
        self.log = logger
        self.__seq = 1
        self.__multicast_ip = multicast_ip
        self.__port = port

        # Holdtime must fit in a 16 bit field, so the hello interval could
        # in theory be set to a max of 65535/HT_MULTIPLIER. Since this is
        # measured in seconds, in reality it will be set much shorter.
        max_hello_interval = 65535 / self._ht_multiplier
        if not (1 <= hello_interval <= max_hello_interval):
            raise(ValueError("hello_interval must be between 1 and "
                             "{}".format(max_hello_interval)))

        self.__hello_interval = hello_interval
        self.__holdtime = self._hello_interval * self._ht_multiplier

        if not kvalues:
            # Allow kvalues to be effectively ignored if the upper layer
            # protocol doesn't need it.
            self.__k1 = 0
            self.__k2 = 0
            self.__k3 = 0
            self.__k4 = 0
            self.__k5 = 0
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
            self.__k1 = kvalues[0]
            self.__k2 = kvalues[1]
            self.__k3 = kvalues[2]
            self.__k4 = kvalues[3]
            self.__k5 = kvalues[4]

        if hdrver == 2:
            self.__rtphdr = RTPHeader2
        else:
            raise(ValueError("Unsupported header version: {}".format(hdrver)))

        self.__tlvfactory = tlv.TLVFactory()
        self.__tlvfactory.register_tlvs([tlv.TLVParam,        \
                                         tlv.TLVAuth,         \
                                         tlv.TLVSeq,          \
                                         tlv.TLVVersion,      \
                                         tlv.TLVMulticastSeq, \
                                        ])
        if tlvclasses:
            self.__tlvfactory.register_tlvs(tlvclasses)
        self.__update_hello_tlvs()
        reactor.callWhenRunning(self.__send_periodic_hello)

    def __init_ifaces(self):
        self.__ifaces = list()
        for iface in self.__sys.logical_ifaces:
            self.__ifaces.append(rtpiface.RTPInterface(iface,
                                      self.__send_rtp_multicast,
                                      self.__rtphdr))

    def __send_periodic_hello(self):
        self.log.debug2("Sending periodic hello.")
        for iface in self.__sys.logical_ifaces:
            if iface.activated:
                self.__send_hello(iface)
        reactor.callLater(self.__hello_interval, self.__send_periodic_hello)

    def __send_hello(self, iface):
        iface.send(self.__rtphdr.OPC_HELLO, self.__hello_tlvs, False)

    def __send_init(self, neighbor):
        pkt = self.__make_pkt(self.__rtphdr.OPC_UPDATE, [], True,
                              self.__rtphdr.FLAG_INIT)
        self.__send_rtp_unicast(neighbor, pkt)

    def __update_hello_tlvs(self):
        """Called to create the hello packet's TLVs that should be sent at
        every hello interval. This should be called at startup and whenever
        the k-values or holdtime changes."""
        self.__hello_tlvs = TLVParam(self.__k1,
                                     self.__k2,
                                     self.__k3,
                                     self.__k4,
                                     self.__k5,
                                     self.__holdtime)

    def foundNeighbor(self, neighbor):
        """Called when a neighbor adjacency is established."""
        pass

    def lostNeighbor(self, neighbor):
        """Called when a neighbor has timed out or should otherwise be
        considered unreachable. This is called before removing the neighbor
        from its interface."""
        pass

    def __rtp_found_neighbor(self, neighbor):
        self.log.debug("Found neighbor {}, iface {}".format(neighbor,
                       neighbor.iface))
        self.foundNeighbor(neighbor)

    def __rtp_lost_neighbor(self, neighbor):
        self.log.debug("Lost neighbor {}, iface {}".format(neighbor,
                       neighbor.iface))
        self.lostNeighbor(neighbor)
        neighbor.iface.del_neighbor(neighbor)

    def datagramReceived(self, data, addr_and_port):
        # XXX Currently only expecting to ride directly over IP, so we
        # ignore the unused port argument. Should remove this restriction.
        addr = addr_and_port[0]
        port = addr_and_port[1]

        input_iface = self.__get_input_iface(addr)
        if not input_iface:
            self.log.warn("Received datagram from non-link-local host: "
                          "{}".format(addr))
        try:
            hdr = self.__rtphdr(data[:self.__rtphdr.LEN])
        except struct.error:
            bytes_to_print = self.__rtphdr.LEN
            self.log.warn("Received malformed datagram from {}. Hexdump of "
                          "first {} bytes: {}".format((addr, bytes_to_print, \
                          binascii.hexlify(data[:bytes_to_print]))))
            return
        observed_chksum = hdr.chksum
        hdr.chksum = 0
        payload = data[self.__rtphdr.LEN:]
        real_chksum = RTPPacket.calc_chksum(hdr.pack() + payload)
        if real_chksum != observed_chksum:
            self.log.debug("Bad checksum: expected 0x%x, was 0x%x" % \
                           (addr, real_chksum, real_chksum))
            return
        if hdr.ver != self.__rtphdr.VER:
            self.log.debug("Received incompatible header version "
                           "{}.".format(hdr.hdrver, addr))
            return

        # XXX Catch and log exceptions from factory
        tlvs = self.__tlvfactory.build_all(payload)

        # Handle RTP-related messages. Look in header for ACKs.
        neighbor = self.__get_neighbor(iface, addr)
        if not neighbor:
            if hdr.opcode != self.__rtphdr.OPC_HELLO:
                self.log.debug("Received unexpected opcode {} from "
                               "non-neighbor.".format(hdr.opcode))
                return
            neighbor = self.__add_neighbor(addr, port, iface, hdr)
            if not neighbor:
                self.log.debug("Failed to add neighbor.")
                return

        neighbor_receive_status = neighbor.receive(hdr, tlvs)
        if neighbor_receive_status == neighbor.PROCESS:
            self.log.debug5("Passing packet to upper layer for processing.")
            self.rtpReceived(neighbor, hdr, tlvs)
        elif neighbor_receive_status == neighbor.DROP:
            self.log.debug5("RTP stopped processing for this packet.")
        elif neighbor_receive_status == neighbor.INIT:
            self.__send_hello(neighbor.iface)
            self.__send_init(neighbor)
        elif neighbor_receive_status == neighbor.NEW_ADJACENCY:
            self.__rtp_found_neighbor(neighbor)
        else:
            raise(AssertionFailure("Unknown RTP Neighbor receive status: "
                                   "{}".format(neighbor_receive_status)))

        # If an ACK is needed and one wasn't sent by RTP.send (i.e. no reply
        # has been sent yet by upper layer), send an explicit ack.
        if neighbor.next_ack:
            self.__send_explicit_ack(neighbor)

    def __send_explicit_ack(self, neighbor):
        hdr = self.__rtphdr(opcode=self.__rtphdr.OPC_HELLO, flags=0, seq=0,
                           ack=neighbor.next_ack, rid=self.__rid,
                           asn=self.__asn)
        msg = RTPPacket(hdr, []).pack()
        neighbor.next_ack = 0
        self.__send(msg, neighbor.logical_iface.ip.ip, self.__port)

    def __get_input_iface(self, ip):
        for iface in self.__ifaces:
            if ip in iface.logical_iface.ip:
                return iface
        return None

    def __add_neighbor(self, addr, port, iface, hdr):
        """Add a neighbor to the list of neighbors.
        Return the new neighbor object, or None on failure."""
        addr = ipaddr.IPv4Address(addr)
        found_iface = False
        for iface in self.__ifaces:
            if addr in iface.logical_iface.ip:
                found_iface = True
                break
        if not found_iface:
            self.log.debug("Preventing adjacency with non-link-local "
                           "neighbor.")
            return None
        neighbor = RTPNeighbor(addr,
                               iface,
                               hdr.seq,
                               hdr.holdtime,
                               self.__rtphdr,
                               self.log,
                               self.__rtp_lost_neighbor,
                               self.__make_pkt,
                               self.__send_rtp_unicast,
                               [self.__k1,
                                self.__k2,
                                self.__k3,
                                self.__k4,
                                self.__k5])
        iface.neighbors.append(neighbor)
        return neighbor

    def __get_seq(self):
        self.__seq += 1
        return self.__seq

    def __send_rtp_unicast(self, neighbor, pkt):
        """Send an RTP packet as a unicast.
        neighbor -- The neighbor to send to
        pkt -- The RTP packet to send
        """
        self.log.debug5("Sending unicast to {}: {}".format(neighbor, pkt))
        pkt.hdr.ack = neighbor.next_ack
        neighbor.next_ack = 0
        msg = pkt.pack()
        self.__send(msg, neighbor.ip.ip, self.__port)

    def __send_rtp_multicast(self, iface, opcode, tlvs, ack):
        """Send an RTP packet as a multicast.
        iface -- The interface object to send from
        opcode -- The opcode number to use in the RTP header
        tlvs -- An iterable of TLVs to send
        ack -- If the packet requires an acknowledgment
        """
        pkt = self.__make_pkt(opcode, tlvs, ack)
        self.log.debug5("Sending multicast out iface {}: {}".format(iface, \
                        pkt))
        if ack:
            seq_ips = list()
            for neighbor in iface.neighbors:
                # If neighbor has a full queue, add it to a seq tlv
                if neighbor.queue_full():
                    seq_ips.append(str(neighbor.ip.packed))
                # We only really need to copy the hdr since the tlvs won't
                # change.
                neighbor.schedule_multicast_retransmission(copy.deepcopy(pkt))
            if seq_ips:
                self.__send_seq_tlv(iface, seq_ips, pkt.hdr.seq)
                hdr.flags |= self.__rtphdr.FLAG_CR
        self.__send(pkt.pack(), self.__multicast_ip, self.__port,
                    iface.logical_iface.ip)

    def __send(self, msg, ip, port, src=None):
        if src:
            self.setOutgoingInterface(src)
        self.transport.write(msg, (ip, port))

    def __send_seq_tlv(self, iface, seq_ips, next_seq):
        """Send a sequence TLV listing the given IP addresses, and a next
        multicast sequence TLV listing.

        iface -- The interface to send from
        seq_ips -- An iterable of packed addresses to be included in the
                   seq TLV listing
        next_seq -- The next multicast sequence number
        """
        # Note: In Cisco IOS 12.4 (EIGRP ver 1.2), this is sent along with
        # a parameters TLV (as in a periodic hello). It "should" be ok
        # to not do that.
        tlvs = [ tlv.TLVSeq(*seq_ips), \
                 tlv.TLVMulticastSeq(next_seq)
               ]
        iface.send(self.__rtphdr.OPC_HELLO, tlvs, False)

    def __make_pkt(self, opcode, tlvs, ack, flags=0):
        """Generate an RTP packet.
        opcode -- The RTP opcode number
        tlvs -- An iterable of TLVs
        ack -- If an ack is required for this packet
        """
        if ack:
            seq = self.__get_seq()
        else:
            seq = 0
        hdr = self.__rtphdr(opcode=opcode, flags=flags, seq=seq, ack=0,
                           rid=self.__rid, asn=self.__asn)
        pkt = RTPPacket(hdr, tlvs)
        return pkt


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

    def __init__(self, ip, iface, seq, holdtime, rtphdr, log, dropfunc,
                 make_pkt, sendfunc, kvalues):
        """
        ip -- IP address of this neighbor
        iface -- Logical interface this neighbor was heard on
        seq -- Current sequence number we have received from this neighbor
        holdtime -- The neighbor's holdtime (may be different than local RTP's)
        rtphdr -- The RTP header class to use
        log -- A log function
        dropfunc -- The function to call if this neighbor should be dropped
        make_pkt -- A function that will generate an RTP packet
        sendfunc -- A function to call every time a packet is (re)transmitted
        kvalues -- The k-values needed in order to form an adjacency
        """
        self.iface = iface
        self.holdtime = holdtime
        self.ip = ipaddr.IPv4Address(ip)
        self._queue = list()
        self._state = self.STATE_UP
        self._state_receive = self._pending_receive
        self.last_heard = time.time()
        self._cr_mode = False
        self._rtphdr = rtphdr
        self._dropfunc = dropfunc
        self._drop_event = reactor.callLater(self.holdtime, self._dropfunc,
                                             self)
        self.log = log
        self._make_pkt = make_pkt
        self._write = sendfunc
        self.update_kvalues(kvalues)

        # The next ack number we should send to this neighbor. Not the same
        # as seq_to because this will change to 0 after we send an ack.
        self.next_ack = 0

        # XXX Support non-zero port
        self.port = 0

        # XXX Update to a variable retransmit timer
        self._retransmit_timer = .2
        self._max_retransmit_seconds = 5

        # seq_to is the last non-zero sequence number we sent to this neighbor
        self.seq_to = 0

        # seq_from is the last sequence number we received from this neighbor
        self.seq_from = seq

        self._next_multicast_seq = 0

    def update_kvalues(self, kvalues):
        self._k1 = kvalues[0]
        self._k2 = kvalues[1]
        self._k3 = kvalues[2]
        self._k4 = kvalues[3]
        self._k4 = kvalues[3]
        self._k5 = kvalues[4]

    def queue_full(self):
        """Returns True if the transmit queue is full, otherwise returns
        False."""
        return len(self._queue) != 0

    def receive(self, hdr, tlvs):
        """Deals with updating last heard time and processing ACKs.
        Sends to PENDING or 

        Returns one of:
            RTPNeighbor.PROCESS if the packet should be processed by the upper
                                layer (as far as RTP is concerned)
            RTPNeighbor.DROP if the packet should be dropped
            RTPNeighbor.INIT if this neighbor needs to be initialized
            RTPNeighbor.NEW_ADJACENCY if the neighbor transitioned to UP"""
        # If we're not in CR mode, drop CR-enabled packets.
        # If we are in CR mode, only accept CR-enabled packets if the RTP
        # sequence number is what we were expecting.
        if (hdr.flags & self._rtphdr.FLAG_CR):
            if not self._cr_mode:
                self.log.debug5("CR flag set and we are not in CR mode. "
                                "Drop packet.")
                return self.DROP
            elif hdr.seq == self._next_multicast_seq:
                self._cr_mode = False
                self._next_multicast_seq = 0

        # This will cause last_heard to be updated when we receive
        # an ACK in addition to when we receive a periodic hello. In reality
        # that's probably fine, but maybe not technically expected behavior
        # per the spec.
        if hdr.opcode == self._rtphdr.OPC_HELLO:
            if self._handle_hello_tlvs(hdr, tlvs) == False:
                return self.DROP
        return self._state_receive(hdr, tlvs)

    def _handle_hello_tlvs(self, hdr, tlvs):
        """Handle TLVs that are contained within a hello packet.
        Return True if the packet should be processed further, otherwise
        return False."""
        for tlv in tlvs:
            if tlv.type == tlv.TLVSeq.TYPE:
                self._handle_hello_seq_tlv(hdr, tlv)
            elif tlv.type == tlv.TLVMulticastSeq.TYPE:
                self._handle_hello_multicastseq_tlv(hdr, tlv)
            elif tlv.type == tlv.TLVParam.TYPE:
                if self._handle_hello_param_tlv(hdr, tlv) == False:
                    return False
        return True

    def _handle_hello_param_tlv(self, hdr, tlv):
        """Checks advertised kvalues against our own.
        Returns True if we should continue processing, otherwise returns
        False."""
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

    def _handle_hello_seq_tlv(self, hdr, tlv):
        for addr in tlv.seq.addrs:
            for iface in sys.logical_ifaces:
                if iface.ip.packed == addr:
                    self._cr_mode = False

        self._cr_mode = True

    def _handle_hello_multicastseq_tlv(hdr, tlv):
        self._next_multicast_seq = tlv.multicastseq.seq

    def _update_last_heard(self):
        self.last_heard = time.time()
        self._drop_event = self._drop_event.reset(self.holdtime)

    def _pending_receive(self, hdr, tlvs):
        # Look for an update packet with init flag set to transition to UP.
        if hdr.opcode == self._rtphdr.OPC_HELLO:
            self.log.debug5("Hello received. Do init.")
            return self.INIT
        elif hdr.opcode == self._rtphdr.OPC_UPDATE:
            if hdr.flags & self._rtphdr.FLAG_INIT:
                self.log.debug5("Init received. Bringing adjacency up.")
                self._state = self.STATE_UP
                self._state_receive = self._up_receive
                self.next_ack = hdr.seq
                return self.NEW_ADJACENCY
        return self.DROP

    def _up_receive(self, hdr, tlvs):
        # In the UP state, request an ACK for anything that we receive.
        # If hdr.seq was 0, then we won't send an ack (see how RTP.receive
        # handles it).
        self.next_ack = hdr.seq
        if hdr.seq == self._seq_from:
            # We already received this packet, but our ack was dropped. Ack
            # but don't process.
            self.log.debug5("Received dupe packet, seq {}".format(hdr.seq))
            return self.DROP
        self._seq_from = hdr.seq
        if hdr.ack:
            if hdr.ack == self.peekrtp().hdr.seq:
                self._poprtp()
                self._retransmit_event.cancel()
                nextmsg = self.peekrtp()
                if nextmsg:
                    self._retransmit(time.time())

        # XXX This assumes that there is not a case where a neighbor will send
        # us an ack that is not for the last message that we sent. Obviously
        # this can be done with a packet crafter, if nothing else, so we
        # should think of the correct behavior here. (Just drop it?
        # Re-send current msg? We don't have older messages anymore.) Currently
        # we just ignore that an ack was sent if it's not for the current
        # packet on the queue.

        return self.PROCESS

    def schedule_multicast_retransmission(self, pkt):
        """Schedule the retransmission of a multicast packet as a unicast."""
        self._pushrtp(pkt)

    def send(self, opcode, tlvs, ack):
        """Wrapper for ReliableTransportProtocol.__send_rtp_unicast.
        opcode -- The RTP opcode number to use
        tlvs -- An iterable of TLVs to send
        ack -- If the packet requires an ack or not

        Note that if you are using RTP for sequencing and acknowledgements,
        ack needs to be set to True. If ack is set to False, RTP does not
        set ack/seq values in the RTP header, which means this packet
        effectively behaves like UDP.
        """
        pkt = self._make_pkt(opcode, tlvs, ack)
        if not ack:
            self._write(self, pkt)
        else:
            self._pushrtp(pkt)

    def _poprtp(self):
        """Pop an RTP packet off of the transmission queue and return it,
        or return None if there are no messages enqueued."""
        try:
            return heappop(self._queue)
        except IndexError:
            return None

    def _pushrtp(self, pkt):
        """Push an RTP packet onto the transmission queue. This should only
        be used for packets that require an acknowledgement."""
        if not self.peekrtp():
            self._seq_to = self._peekrtp().hdr.seq
            self._retransmit_event = reactor.callLater(self._retransmit_timer,
                                                self._retransmit, time.time())
        heappush(self._queue, pkt)

    def _retransmit(self, init_time):
        """Retransmit the current RTP packet.
        init_time -- The time this was first called
        """
        self._write(self, self._peekrtp())

        # If the next retransmit attempt will not exceed the max retrans time,
        # then schedule another retransmission.
        if init_time + self._max_retransmit_seconds < \
                       time.time() + self._retransmit_timer:
            self._retransmit_event = reactor.callLater(self._retransmit_timer,
                                                self._retransmit, init_time)
        else:
            # XXX Shouldn't we drop the neighbor here? DUAL at least won't
            # operate correctly if RTP simply drops sequenced messages. 
            pass

    def _peekrtp(self):
        """Return the next RTP packet in the transmission queue without
        removing it, or None if the queue is empty."""
        try:
            return self._queue[0]
        except IndexError:
            return None


class RTPInterface(object):

    """An RTP logical interface."""

    def __init__(self, logical_iface, writefunc, rtphdr):
        """
        logical_iface -- The logical interface to use
        writefunc -- The function to use when sending packets from this
                     interface
        """
        self._neighbors = dict()
        self.logical_iface = logical_iface
        self._write = writefunc
        self._rtphdr = rtphdr

    def add_neighbor(self, neighbor):
        """Add neighbor object to this interface."""
        self._neighbors[neighbor.logical_iface.ip] = neighbor

    def get_neighbor(self, ip):
        """Get neighbor with the IP address 'ip'."""
        try:
            return self._neighbors[ip]
        except KeyError:
            return None

    def del_neighbor(self, ip):
        """Remove neighbor with IP 'ip' from this interface."""
        self._neighbors.pop(ip, None)

    def send(self, opcode, tlvs, ack):
        """Send an RTP multicast from this interface.
        opcode -- The opcode number to use in the RTP header
        tlvs -- An iterable of TLVs to send
        ack -- The packet requires an acknowledgment. If True, retransmissions
               will be queued for all neighbors on this interface.
        """
        # Check if self.activated?
        # Stats (multicast packets sent)?
        self._write(self, opcode, tlvs, ack)
