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
import ipaddr
from twisted.python import log

import dualfsm
import rtp
import rtptlv
import util
import sysiface
from tw_baseiptransport import reactor

class TopologyTable(object):
    """A container for TopologyEntry instances."""

    def __init__(self):
        self._topology = dict()

    # XXX Doesn't seem very useful to have this.
#    def update_prefix(self, prefix, neighbor, reported_distance):
#        """Update information about a neighbor for the given prefix in the
#        topology table."""
#        if not type(prefix) == ipaddr.IPv4Network:
#            raise TypeError("prefixes are expected to be of type "
#                            "ipaddr.IPv4Network")
#        if not prefix in self._topology:
#            fsm = dualfsm.DualFsm()
#            self._topology[prefix] = TopologyEntry(fsm)
#        self._topology[prefix].update_neighbor(neighbor, reported_distance)

    def del_prefix(self, prefix, neighbor):
        pass

    def get_prefix(self, prefix):
        pass


class TopologyEntry(object):
    """A topology entry contains the FSM object used for a given prefix,
    plus all neighbors that have advertised this prefix. The prefix
    itself is expected to be stored as the key in the dictionary for which
    this object is a value. Example usage:
    - For initialization example, see TopologyTable.update_prefix

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

    NO_SUCCESSOR   = 1
    SELF_SUCCESSOR = 2  # Local router is the successor

    def __init__(self, prefix):
        """prefix -- this network's network address and mask. This is
        just for informational/debugging purposes; it not used to identify the
        TopologyEntry.
        The prefix assigned to the ToplogyEntry is identified by the key used
        in the TopologyTable to access this entry."""
        self.prefix = prefix
        self.fsm = dualfsm.DualFsm()
        self._neighbors = dict()
        self.successor = NO_SUCCESSOR

    def add_neighbor(self, neighbor_info):
        """Add a neighbor to the topology entry.
        neighbor_info -- a TopologyNeighborInfo instance"""
        if neighbor_info.neighbor in self._neighbors:
            raise(ValueError("Neighbor already exists."))
        self._neighbors[neighbor_info.neighbor] = neighbor_info

    def get_neighbor(self, neighbor):
        """Get the TopologyNeighborInfo entry for this prefix given an
        RTPNeighbor instance."""
        return self._neighbors[neighbor]

#    def update_neighbor(self, neighbor, reported_distance):
#        """Add a new neighbor for this prefix, or update an existing
#        neighbor's reported distance.
#        Take the appropriate action in the fsm.
#        Returns the fsm's return value."""
#        if not neighbor in self._neighbors:
#            self._neighbors[neighbor] = ToplogyNeighborInfo(neighbor,
#                                                           reported_distance)
#        # XXX Check if reported distance decreased etc, call into fsm as
#        # necessary.

    def all_replies_received(self):
        """Checks if replies from all fully-formed neighbors have been
        received. We do not expect a reply from any neighbor who was not fully
        formed at the time of sending the query."""
        # See section 5.3.5 of the Feb 2013 RFC (Query packets during neighbor
        # formation.
        # Question: we don't expect a reply from any neighbor who was not
        # fully formed at the time of sending the query, or from any neighbor
        # who was not fully formed at the time of checking if all replies were
        # received?
        #
        # If you weren't fully formed when the query was sent we shouldn't
        # expect a response, so we definitely need to check for that case.
        #
        # XXX Sounds like we need to track the reply status flag in the
        # neighbor rather than in the t_entry, because if a neighbor exists
        # and isn't known to have a route for the prefix in the t_entry we
        # still expect a reply from it.
        #
        # What if we have multiple queries out at once? RFC probably talks about
        # that, mentioned something about being able to have multiple QRY
        # packets out at once.
        #
        pass


class TopologyNeighborInfo(object):
    def __init__(self, neighbor, reported_distance):
        """neighbor -- an RTPNeighbor instance (None for locally-known routes)
        reported_distance -- the metric advertised by the neighbor
              (composite metric class such as rtptlv.ValueClassicMetric, not
              an integer)
        """
        # Note that the interface on which a neighbor was observed is stored
        # within the RTPNeighbor instance.
        self.neighbor          = neighbor
        self.reported_distance = reported_distance
        self.reply_flag        = True


class EIGRP(rtp.ReliableTransportProtocol):

    DEFAULT_KVALUES = [ 1, 0, 1, 0, 0 ]
    MC_IP = "224.0.0.10"

    def __init__(self, requested_ifaces, routes=None, import_routes=False,
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
        # XXX Should probably move all kvalue stuff out of RTP and into EIGRP
        # then allow a way to add arbitrary data to RTP's HELLO messages
        # (along with verification functions for neighbor formation). Not all
        # upper layers to RTP need kvalues. Until then, this works.
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

        self._topology = TopologyTable()
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

        if requested_routes:
            routes += requested_routes
        for route in routes:
            # Local routes use None as the neighbor and 0 as the RD.
            # TODO
            #self._topology.add_route(prefix=route,
            #                         neighbor=None,
            #                         reported_distance=0)
            pass

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

    def _eigrp_op_handler_update(self, neighbor, hdr, tlvs):
        self.log.debug("Processing UPDATE")
        qry_tlvs = list()
        for tlv in tlvs:
            if tlv.type == rtptlv.TLVInternal4.TYPE:
                qry_tlv = self._op_update_handler_tlvinternal4(neighbor,
                                                               hdr,
                                                               tlv)
                if qry_tlv:
                    qry_tlvs.append(qry_tlv)
            else:
                self.log.debug("Unexpected TLV type in UPDATE: {}".format(tlv))
                return

        # Send a query if necessary.
        if qry_tlvs:
            self._send(dests=self._get_active_ifaces(),
                       opcode=rtp.OPC_QUERY,
                       tlvs=qry_tlvs,
                       ack=True)

    def _op_update_handler_tlvinternal4(self, neighbor, hdr, tlv):
        """Handle an IPv4 Internal TLV within an UPDATE packet."""
        # XXX hdr unused.
        prefix = ipaddr.IPv4Network("%s/%d" % (tlv.dest.exploded, tlv.plen))

        # All zeroes means use the source address of the incoming packet.
        if tlv.nexthop.ip.exploded == "0.0.0.0":
            nexthop = neighbor.ip.exploded
        else:
            nexthop = tlv.nexthop.ip.exploded

        try:
            t_entry = self._topology[prefix]
        except KeyError:
            # New prefix.
            self._topology[prefix] = TopologyEntry(prefix=prefix)
            t_entry = self._topology[prefix]
            t_entry. TopologyNeighborInfo(neighbor, tlv.metric)

            if not tlv.reachable():
                return

            # Update the TLV with metric info from the nexthop interface, then
            # send UPDATE an packet out of all active ifaces with this route.
            # Use the prefix for routing.
            tlv.metric.bw   += neighbor.iface.phy_iface.get_bandwidth()
            tlv.metric.dly  += neighbor.iface.phy_iface.get_delay()
            tlv.metric.load += neighbor.iface.phy_iface.get_load()
            tlv.metric.rel  += neighbor.iface.phy_iface.get_reliability()
            tlv.metric.hops += 1
            if neighbor.iface.phy_iface.get_mtu() < tlv.metric.mtu:
                tlv.metric.mtu = neighbor.iface.phy_iface.get_mtu

            self._send(dests=self._get_active_ifaces(),
                       opcode=rtp.OPC_UPDATE,
                       tlvs=tlv,
                       ack=True)
            return

        # Prefix is already in topology table. Pass to FSM.
        # XXX TODO for PDM architecture: assumes IPv4.
        if tlv.nexthop.ip.exploded == "0.0.0.0":
            # All zeroes means use the source address of the incoming packet.
            nexthop = neighbor.ip.exploded
        else:
            nexthop = tlv.nexthop.ip.exploded

        actions = t_entry.fsm.handle_update(neighbor,
                                            nexthop,
                                            tlv.metric,
                                            t_entry)
        for action, data in actions:
            if action == dualfsm.NO_OP:
                continue
            elif action == dualfsm.INSTALL_SUCCESSOR:
                # Install route in routing table.
                successor = data
                self.log.debug("Installing new successor for prefix {}: "
                               "{}".format(prefix.exploded, successor))

                # XXX I need access to the specific fields that make up the
                # metric inside the RTPInterface class so that the tlv fields
                # can be updated before I advertise the route in an update
                # packet below.
                #
                # This means the tlv.metric.compute_metric logic should
                # probably be moved out of tlv.metric into eigrp.py, and
                # then eigrp will grab info from RTPInterface and TLV in order
                # to compute the "total_metric" variable which is passed into
                # the RIB, and it will also be able to "add up" the new metric
                # to place into the TLV before we send an UPDATE.
                total_metric = tlv.metric.compute_metric() + \
                               successor.neighbor.iface.metric
                self._sys.install_route(net=prefix.ip.exploded,
                                        preflen=prefix.prefixlen,
                                        metric=total_metric,
                                        nexthop=nexthop)
                # XXX Send update to all active ifaces with new metric
                pass
            elif action == dualfsm.STOP_USING_ROUTE:
                # Stop using route for routing.
                pass
            elif action == dualfsm.SEND_QUERY:
                # Include this TLV in a QUERY packet.
                # Reuse this TLV instead of creating another one. Change
                # the metric's delay field to indicate an unreachable prefix.
                self.log.debug("Including prefix {} in QUERY "
                               "packet".format(prefix.exploded))
                tlv.metric.dly = tlv.metric.METRIC_UNREACHABLE
                return tlv
            else:
                assert False, "Unknown action returned by fsm: " \
                       "{}".format(action)
        return

    def _eigrp_op_handler_request(self, neighbor, hdr, tlvs):
        self.log.debug("Processing REQUEST")

    def _eigrp_op_handler_query(self, neighbor, hdr, tlvs):
        self.log.debug("Processing QUERY")

    def _eigrp_op_handler_reply(self, neighbor, hdr, tlvs):
        self.log.debug("Processing REPLY")

    def _eigrp_op_handler_hello(self, neighbor, hdr, tlvs):
        """RTP deals with HELLOs, nothing to do here."""
        pass

    def _send(self, dsts, opcode, tlvs, ack, flags=0):
        """Send a packet to one or more neighbors or interfaces.

        dsts -- an iterable of RTPInterface or RTPNeighbor objects
        tlvs -- an iterable of TLVs to include in the packet
        init -- if True, the INIT flag will be set in the RTP header
        """
        for dst in dsts:
            dst.send(opcode=opcode,
                     tlvs=tlvs,
                     ack=ack,
                     flags=flags)

    def _eigrp_op_handler_siaquery(self, neighbor, hdr, data):
        self.log.debug("Processing SIAQUERY")

    def _eigrp_op_handler_siareply(self, neighbor, hdr, data):
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
        for iface in self._ifaces:
            if iface.activated:
                self.transport.joinGroup(self._multicast_ip,
                                         iface.logical_iface.ip.ip.exploded)

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
                          (hdr.opcode, neighbor))
            return
        handler(neighbor, hdr, tlvs)
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

    # The requested iface argument expects IP addresses ("logical" interfaces),
    # not interface names like "eth0". Throw error if invalid IP address is
    # used. XXX Will need to be updated for IPv6.
    for iface in options.interface:
        try:
            ipaddr.IPv4Address(iface)
        except ipaddr.AddressValueError:
            op.error("-i argument requires an interface IP address argument")

    return options, arguments

def main(argv):
    if not 0x02070000 < sys.hexversion < 0x02080000:
        sys.stderr.write("Python 2.7 is required. Exiting.\n")
        return 1

    if not util.is_admin():
        sys.stderr.write("Must be root/admin. Exiting.\n")
        return 1

    options, arguments = parse_args(argv)
    system = sysiface.SystemFactory().build()
    eigrpserv = EIGRP(requested_ifaces=options.interface,
                      routes=options.route,
                      import_routes=options.import_routes,
                      port=options.admin_port,
                      kvalues=options.kvalues,
                      hello_interval=options.hello_interval,
                      system=system,
                      logconfig=options.log_config,
                      rid=options.router_id,
                      asn=options.as_number,
                     )
    eigrpserv.run()

if __name__ == "__main__":
    main(sys.argv)
