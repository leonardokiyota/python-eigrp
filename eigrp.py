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
from twisted.internet import protocol
from twisted.internet import base
from twisted.python import log

import rtp
import sysiface
import util
from tw_baseiptransport import reactor
from tlv import TLVFactory
from tlv import TLVParam

class TopologyEntry(object):
    """A topology entry contains the FSM object used for a given prefix,
    plus all neighbors that have advertised this prefix. The prefix
    itself is expected to be stored as the key in the dictionary for which
    this object is a value. Example usage:
    - For initialization example, see eigrp._init_routes

    - Neighbor lookup:
        # Neighbor lookup.
        try:
            neighbor_info = topology[prefix].get_neighbor(neighbor)
        except KeyError:
            print("Neighbor not found.")
            return
        print(neighbor_info.neighbor)
        print(neighbor_info.reported_distance)
        print(neighbor_info.reply_flag)
    """

    def __init__(self, fsm):
        """fsm - a DualFsm object"""
        self.fsm = fsm
        self.neighbors = dict()

    def add_neighbor(self, neighbor, reported_distance):
        self.neighbors[neighbor] = ToplogyNeighborInfo(neighbor,
                                                       reported_distance)

    def get_neighbor(self, neighbor):
        return self.neighbors[neighbor]


class TopologyNeighborInfo(object):
    def __init__(self, neighbor, reported_distance):
        """neighbor - an RTPNeighbor instance (None for "locally" known routes)
        reported_distance - the distance advertised by the neighbor
        """
        # Note that the interface on which a neighbor was observed is stored
        # within the RTPNeighbor instance.
        self.neighbor          = neighbor
        self.reported_distance = reported_distance
        self.reply_flag        = True


class EIGRP(rtp.ReliableTransportProtocol):

    DEFAULT_KVALUES = [ 1, 0, 1, 0, 0 ]

    def __init__(self, requested_ifaces, routes=[], import_routes=False,
                 admin_port=None, *args, **kwargs):
        """An EIGRP implementation based on Cisco's draft informational RFC
        located here:

        http://www.ietf.org/id/draft-savage-eigrp-01.txt

        requested_ifaces -- Iterable of IP addresses to send from
        routes -- Iterable of routes to import
        import_routes -- Import routes from the kernel (True or False)
        log_config -- Configuration filename
        admin_port -- The TCP port to bind to the administrative interface
                      (not implemented)
        """
        rtp.ReliableTransportProtocol.__init__(self, *args, **kwargs)
        # XXX Should probably move all kvalue stuff out of RTP and into EIGRP then allow a way to add
        # arbitrary data to RTP's HELLO messages (along with verification functions for neighbor
        # formation). Not all upper layers to RTP need kvalues. Until then, this works.
        if self._k1 == 0 and \
           self._k2 == 0 and \
           self._k3 == 0 and \
           self._k4 == 0 and \
           self._k5 == 0:
            self._k1 = self.DEFAULT_KVALUES[0]
            self._k2 = self.DEFAULT_KVALUES[1]
            self._k3 = self.DEFAULT_KVALUES[2]
            self._k4 = self.DEFAULT_KVALUES[3]
            self._k5 = self.DEFAULT_KVALUES[4]

        self._topology = dict()
        self._register_op_handlers()
        for iface in requested_ifaces:
            self.activate_iface(iface)
        self._init_routes(import_routes, routes)
        #eigrpadmin.run(self, port=admin_port)

    def _init_routes(self, import_routes, requested_routes):
        routes = list()
        if import_routes:
            # XXX
            # imported_routes = ...
            # routes += imported_routes
            pass

        routes += requested_routes

        for route in routes:
            if not type(route) == ipaddr.IPv4Network:
                raise TypeError("Routes are expected to be of type "
                                "ipaddr.IPv4Network")
            if not route in self._topology:
                fsm = dualfsm.DualFsm()
                self._topology[route] = ToplogyEntry(fsm)
            # Local routes use None as the neighbor and 0 as the RD.
            self._topology[route].add_neighbor(neighbor=None,
                                               reported_distance=0)

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
        """RTP deals with HELLOs, nothing to do here."""
        pass

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
