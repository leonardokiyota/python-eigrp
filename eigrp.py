#!/usr/bin/env python

"""A Python implementation of EIGRP based on Cisco's draft informational RFC
located here: http://www.ietf.org/id/draft-savage-eigrp-00.txt"""

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

import sys
import optparse
import logging
import logging.config
import functools
import struct
import binascii
import time
import ipaddr
from twisted.internet import protocol, base
from twisted.python import log

import sysiface
import util
from tw_baseiptransport import reactor
from tlv import TLVFactory, TLVParam
import rtp

class EIGRP(rtp.ReliableTransportProtocol):

    DEFAULT_K_VALUES = [ 1, 74, 1, 0, 0 ]
    MC_IP = "224.0.0.10"

    def __init__(self, rid, asn, routes, import_routes, requested_ifaces,
                 log_config, admin_port, kvalues=None, hello_interval=5,
                 hdrver=2):
        """An EIGRP implementation based on Cisco's draft informational RFC
        located here:

        http://www.ietf.org/id/draft-savage-eigrp-00.txt

        rid -- The router ID to use
        asn -- The autonomous system number
        routes -- Iterable of routes to import
        import_routes -- Import routes from the kernel (True or False)
        requested_ifaces -- Iterable of IP addresses to send from
        log_config -- Configuration filename
        admin_port -- The TCP port to bind to the administrative interface
                      (not implemented)
        kvalues -- Iterable of K-value weights. Indexes are mapped to K1
                    through K5 (index 0 -> K1). If None, use defaults.
        hello_interval -- The hello interval. Also influences holdtime.
        hdrver -- Version of the RTP header to use. Only 2 is supported.
        """
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

        # Holdtime must fit in a 16 bit field, so the hello interval could
        # in theory be set to a max of 65535/HT_MULTIPLIER. Since this is
        # measured in seconds, in reality it will be set much shorter.
        max_hello_interval = 65535 / self._ht_multiplier
        if not (1 <= hello_interval <= max_hello_interval):
            raise(ValueError("hello_interval must be between 1 and %d" % \
                             max_hello_interval))

        self._hello_interval = hello_interval
        self._holdtime = self._hello_interval * self._ht_multiplier

        if not kvalues or \
           len(kvalues) != 5:
            raise(ValueError("Exactly 5 K-values must be present."))
        try:
            for k in kvalues:
                if not (0 <= k <= 255):
                    raise(ValueError("Each kvalue must be between 0 and 255."))
        except TypeError:
            raise(TypeError("kvalues must be an iterable."))
        if not sum(kvalues):
            raise(ValueError("At least one kvalue must be non-zero."))
        self._k1 = kvalues[0]
        self._k2 = kvalues[1]
        self._k3 = kvalues[2]
        self._k4 = kvalues[3]
        self._k5 = kvalues[4]

        if hdrver == 2:
            self._rtphdr = RTPHeader2
        else:
            raise(ValueError("Unsupported header version: %d" % hdrver))

        self._init_logging(log_config)
        if sys.platform == "linux2":
            self._sys = sysiface.LinuxSystem(log_config=log_config)
        elif sys.platform == "win":
            self._sys = sysiface.WindowsSystem(log_config=log_config)
        else:
            raise(NotSupported("No support for current OS."))
        self._register_op_handlers()
        self._build_hello_pkt()
        for iface in requested_ifaces:
            self.activate_iface(iface)
        self._fieldfactory = TLVFactory()
        self._neighbors = list()
        self._seq = 1
        self._crmode = False
        reactor.callWhenRunning(self._send_periodic_hello)
        #eigrpadmin.run(self, port=admin_port)

    def activate_iface(self, req_iface):
        """Enable EIGRP to send from the specified interface."""
        for sys_iface in self._sys.logical_ifaces:
            if req_iface == sys_iface.ip.ip.exploded:
                sys_iface.activated = True
                return
        raise(ValueError("Requested IP %s is unusable. (Is it assigned to this"
                         " machine on a usable interface?)" % req_iface))

    def _init_logging(self, log_config):
        # debug1 is less verbose, debug5 is more verbose.
        for (level, name) in [ (10, "DEBUG1"),
                               (9,  "DEBUG2"),
                               (8,  "DEBUG3"),
                               (7,  "DEBUG4"),
                               (6,  "DEBUG5"),
                             ]:
            util.create_new_log_level(level, name)

        logging.config.fileConfig(log_config, disable_existing_loggers=True)
        self.log = logging.getLogger("EIGRP")
        suppress_reactor_not_running = functools.partial(util.suppress_reactor_not_running, logfunc=self.log.debug)
        log.addObserver(suppress_reactor_not_running)

    def _build_hello_pkt(self):
        """Called to create the hello packet that should be sent at every
        hello interval. This should be called at startup and whenever the
        k-values or holdtime changes."""
        hdr = self._rtphdr(opcode=self._rtphdr.OPC_HELLO, flags=0,
                           seq=0, ack=0, rid=self._rid,
                           asn=self._asn)
        fields = TLVParam(self._k1,
                          self._k2,
                          self._k3,
                          self._k4,
                          self._k5,
                          self._holdtime)
        self._hello_pkt = RTPPacket(hdr, fields).pack()

    def _send_periodic_hello(self):
        self.log.debug2("Sending periodic hello.")
        for iface in self._sys.logical_ifaces:
            if iface.activated:
                self._write(self._hello_pkt, self.MC_IP, iface.ip.ip.exploded)
        reactor.callLater(self._hello_interval, self._send_periodic_hello)

    def _write(self, msg, dst, src=None):
        self.log.debug5("Writing packet to %s, iface %s." % (dst, \
                        src or "unspecified"))
        if src:
            self.transport.setOutgoingInterface(src)
        self.transport.write(msg, (dst, 0))

    def _register_op_handlers(self):
        self._op_handlers = dict()
        self._op_handlers[self._rtphdr.OPC_UPDATE] = self._eigrp_op_handler_update
        self._op_handlers[self._rtphdr.OPC_REQUEST] = self._eigrp_op_handler_request
        self._op_handlers[self._rtphdr.OPC_QUERY] = self._eigrp_op_handler_query
        self._op_handlers[self._rtphdr.OPC_REPLY] = self._eigrp_op_handler_reply
        self._op_handlers[self._rtphdr.OPC_HELLO] = self._eigrp_op_handler_hello
        self._op_handlers[self._rtphdr.OPC_SIAQUERY] = self._eigrp_op_handler_siaquery
        self._op_handlers[self._rtphdr.OPC_SIAREPLY] = self._eigrp_op_handler_siareply

    def _eigrp_op_handler_update(self, addr, hdr, tlvs):
        self.log.debug("Processing UPDATE")

    def _eigrp_op_handler_request(self, addr, hdr, tlvs):
        self.log.debug("Processing REQUEST")

    def _eigrp_op_handler_query(self, addr, hdr, tlvs):
        self.log.debug("Processing QUERY")

    def _eigrp_op_handler_reply(self, addr, hdr, tlvs):
        self.log.debug("Processing REPLY")

    def _eigrp_op_handler_hello(self, addr, hdr, tlvs):
        # XXX Handle a neighbor that changes k-values or holdtime while in
        # PENDING or UP state
        self.log.debug("Processing HELLO")
        for tlv in tlvs:
            self.log.debug5(tlv)
            if tlv.type == TLVParam.TYPE:
                if tlv.param.k1 != self._k1 or \
                   tlv.param.k2 != self._k2 or \
                   tlv.param.k3 != self._k3 or \
                   tlv.param.k4 != self._k4 or \
                   tlv.param.k5 != self._k5:
                    self.log.debug("Parameter mismatch between potential "
                                   "neighbor at %s." % (addr))
        neighbor = self._get_neighbor(addr)
        if not neighbor:
            # XXX Get actual incoming interface
            self._add_neighbor(addr, "IFACE", hdr.seq, tlv.param.holdtime)
            self.log.debug("New pending neighbor: %s" % addr)
        else:
            neighbor.last_heard = time.time()

    def _get_neighbor(self, ip):
        for neighbor in self._neighbors:
            if neighbor.ip.exploded == ip:
                return neighbor
        return None

    def _add_neighbor(self, addr, iface, seq, holdtime):
        neighbor = RTPNeighbor(addr, iface, seq, holdtime)
        self._neighbors.append(neighbor)
        self._send_update(neighbor)

        if len(self._neighbors) == 1:
            nextcall = neighbor.holdtime + 1
            self._next_holdtime_check = time.time() + nextcall
            self.log.debug("Checking neighbor holdtimes in %d second(s)." % \
                           nextcall)
            reactor.callLater(nextcall, self._check_neighbor_holdtimes)
        else:
            if time.time() + neighbor.holdtime + 1 >= \
                                                self._next_holdtime_check:
                return

            # New neighbor has a shorter holdtime than the wait until we
            # were going to check holdtimes again. Check holdtimes sooner.
            # If we don't do this and our first neighbor sends us a packet
            # with a huge holdtime, then if we get a new neighbor we wouldn't
            # check the new neighbor's holdtime until the huge holdtime
            # expires.
            for call in reactor.getDelayedCalls():
                if call.func == self._check_neighbor_holdtimes:
                    nextcall = neighbor.holdtime + 1
                    self._next_holdtime_check = time.time() + nextcall
                    call.reset(nextcall)
                    self.log.debug("Neighbor caused a change in the holdtime "
                                   "check timer. Checking neighbor holdtimes "
                                   "again in %d second(s)." % nextcall)

    def _send_update(self, neighbor, init=False):
        """Send an update packet. Used after discovering a new neighbor."""
        hdr = self._rtphdr(opcode=self._rtphdr.OPC_UPDATE,
                           flags=self._rtphdr.FLAG_INIT,
                           seq=self._seq,
                           ack=0,
                           rid=self._rid,
                           asn=self._asn)
        tlvs = [] # XXX
        pkt = RTPPacket(hdr, tlvs)
        neighbor.pushmsg(pkt)

    def _check_neighbor_holdtimes(self):
        self.log.debug("Checking neighbor holdtimes.")
        nextcall = sys.maxint
        now = time.time()
        for neighbor in self._neighbors[:]:
            expiration = (neighbor.last_heard + neighbor.holdtime) - now
            if expiration < 1:
                self._del_neighbor(neighbor)
            elif expiration < nextcall:
                nextcall = expiration + 1
        if not len(self._neighbors):
            self.log.debug("No more neighbors.")
            assert(nextcall == sys.maxint)
        else:
            self.log.debug("Checking neighbor holdtimes again in %d"
                           " second(s)." % nextcall)
            self._next_holdtime_check = now + nextcall
            reactor.callLater(nextcall, self._check_neighbor_holdtimes)

    def _del_neighbor(self, neighbor):
        # XXX Delete routes etc.
        self.log.debug("Deleting neighbor: %s" % neighbor)
        self._neighbors.remove(neighbor)

    def _eigrp_op_handler_siaquery(self, addr, hdr, data):
        self.log.debug("Processing SIAQUERY")

    def _eigrp_op_handler_siareply(self, addr, hdr, data):
        self.log.debug("Processing SIAREPLY")

    def run(self):
        # XXX Binds to 0.0.0.0. Would be nice to only bind to active
        # interfaces, though this is only a problem if someone sends a unicast
        # to an interface we didn't intend to listen on. 
        # We don't join the multicast group on non-active
        # interfaces, so we shouldn't form adjacencies on non-active
        # interfaces. This is good.
        reactor.listenIP(88, self)
        self.log.info("EIGRP is starting up...")
        reactor.run()

    def _cleanup(self):
        # XXX Add cleanup for routes when we have any to remove
        self.log.info("Cleaning up.")
        self._sys.cleanup()

    def _rtp_receive(self, addr, hdr):
        """Process the reliable packet.
        Returns True if processing should continue on the packet,
        otherwise returns False."""
        neighbor = self._get_neighbor(addr)
        if not neighbor:
            if hdr.opcode != self._rtphdr.OPC_HELLO:
                self.log.debug("Received non-hello packet from non-neighbor."
                               " Opcode: %d" % (addr, hdr.opcode))
                return False
            else:
                return True
        if hdr.flags & self._rtphdr.FLAG_CR:
            if not self._crmode:
                self.log.debug5("CR flag on packet but we are not in CR mode.")
                return False
            else:
                self.log.debug5("CR flag on packet and we are in CR mode.")
        if not hdr.seq:
            # Packet was not reliably transmitted
            return True
        if hdr.seq == neighbor.seq:
            self.log.debug5("Received duplicate sequence number.")
            # Already received this packet, discard and send an ack
            self._send_ack(addr, hdr.seq)
            return False

        # XXX Deal with sequence number wrapping, skip 0
        if hdr.seq != neighbor.seq + 1:
            # Out of order packet
            self.log.debug5("Neighbor sent SEQ %d, expected %d." % \
                           (hdr.seq, neighbor.seq))
            return False
        # Send ack for received packet and allow processing
        self._send_ack(addr, hdr.seq)
        neighbor.seq = hdr.seq
        return True

    def _send_ack(self, addr, ack):
        hdr = self._rtphdr(opcode=self._rtphdr.OPC_HELLO, flags=0, seq=0,
                           ack=ack, rid=self._rid, asn=self._asn)
        pkt = RTPPacket(hdr, []).pack()
        self._write(pkt, addr)

    def startProtocol(self):
        for iface in self._sys.logical_ifaces:
            if iface.activated:
                self.transport.joinGroup(self.MC_IP, iface.ip.ip.exploded)

    def stopProtocol(self):
        self.log.info("EIGRP is shutting down.")
        self._cleanup()

    def foundNeighbor(self, neighbor):
        pass

    def lostNeighbor(self, neighbor):
        pass

    def rtpReceived(self, neighbor, hdr, tlvs):
        addr = addr_and_zero[0]
        self.log.debug5("Received datagram from %s" % addr)
        host_local = False
        for local_iface in self._sys.logical_ifaces:
            if local_iface.ip.ip.exploded == addr:
                host_local = True
                break
        if host_local:
            self.log.debug5("Ignoring message from local system.")
            return

        self.log.debug("Processing datagram from %s" % addr)
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
            self.log.debug("Bad checksum: expected 0x%x, was 0x%x" % (addr, real_chksum, real_chksum))
            return
        if hdr.ver != self._rtphdr.VER:
            self.log.warn("Received incompatible header version %d from "
                          "host %s" % (hdr.hdrver, addr))
            return

        tlvs = self._fieldfactory.build_all(payload)
        if not self._rtp_receive(addr, hdr):
            self.log.debug5("RTP rejected packet.")
            return
        else:
            self.log.debug5("RTP accepted packet for processing.")
 
        try:
            handler = self._op_handlers[hdr.opcode]
        except KeyError:
            self.log.info("Received invalid/unhandled opcode %d from %s" % \
                          (hdr.opcode, addr))
            return
        handler(addr, hdr, tlvs)
        self.log.debug("Finished handling opcode.")


class EIGRPException(Exception):
    def __init__(self, msg=""):
       self.msg = msg


class NotSupported(EIGRPException):
    def __init__(self, *args, **kwargs):
        super(EIGRPException, self).__thisclass__.__init__(self, *args, **kwargs)


class FormatException(EIGRPException):
    def __init__(self, *args, **kwargs):
        super(EIGRPException, self).__thisclass__.__init__(self, *args, **kwargs)


def parse_args(argv):
    op = optparse.OptionParser()
    op.add_option("-R", "--router-id", default=1, type="int",
                  help="The router ID to use")
    op.add_option("-A", "--as-number", default=1, type="int",
                  help="The autonomous system number to use")
    op.add_option("-P", "--admin-port", default=1520, type="int",
                  help="Admin telnet interface port number to use (1520)")
    op.add_option("-i", "--interface", type="str", action="append",
                  help="An interface IP to use for EIGRP."
                       "Can specify -i multiple times.")
    op.add_option("-I", "--import-routes", default=False, action="store_true",
                  help="Import local routes from the kernel upon startup.")
    op.add_option("-r", "--route", type="str", action="append",
                  help="A route to import, in CIDR notation. "
                        "Can specify -r multiple times.")
    op.add_option("-l", "--log-config", default="logging.conf",
                  help="The logging configuration file "
                        "(default logging.conf).")
    op.add_option("-k", "--kvalues", type="str", default="1,74,1,0,0",
                  help="Use non-default K-values (metric coefficients).")
    op.add_option("-t", "--hello-interval", type="int", default=5,
                  help="Use non-default hello timer. Hold time is 3 times the"
                  " value given here. 5 sec by default.")
    options, arguments = op.parse_args(argv)

    if not options.interface:
        op.error("At least one interface IP is required (-i).")

    # Turn kvalues into a list
    options.kvalues = options.kvalues.split(",")
    if len(options.kvalues) != 5:
        op.error("Five k-values must be present in a comma separated list "
                 "(e.g. 1,74,1,0,0).")
    try:
        for index, k in enumerate(options.kvalues[:]):
            options.kvalues[index] = int(k)
    except ValueError:
        op.error("Kvalues must be integers.")
    if len(arguments) > 1:
        op.error("Unexpected non-option argument(s): '" + \
                 " ".join(arguments[1:]) + "'")

    return options, arguments

def main(argv):
    if not (0x02070000 < sys.hexversion < 0x02080000):
        sys.stderr.write("Python 2.7 is required. Exiting.\n")
        return 1

    if not util.is_admin():
        sys.stderr.write("Must be root/admin. Exiting.\n")
        return 1

    options, arguments = parse_args(argv)
    eigrpserv = EIGRP(options.router_id, options.as_number, options.route, options.import_routes, options.interface, options.log_config, options.admin_port, options.kvalues, options.hello_interval)
    eigrpserv.run()

if __name__ == "__main__":
    main(sys.argv)
