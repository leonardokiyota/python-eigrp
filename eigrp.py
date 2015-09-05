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
import copy
import netlink_listener
from twisted.python import log

import dualfsm
import rtp
import rtptlv
import util
import sysiface
from tw_baseiptransport import reactor

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

    def __init__(self, prefix, get_kvalues):
        """prefix -- this network's network address and mask. This is
        just for informational/debugging purposes; it not used to identify the
        TopologyEntry.
        The prefix assigned to the ToplogyEntry is identified by the key used
        in the TopologyTable to access this entry."""
        self.prefix = prefix
        self.fsm = dualfsm.DualFsm(self._get_kvalues)
        self.neighbors = dict()
        self.successor = self.NO_SUCCESSOR
        self._feasible_successors = list()
        self._get_kvalues = get_kvalues

    def add_neighbor(self, neighbor_info):
        """Add a neighbor to the topology entry.
        neighbor_info -- a TopologyNeighborInfo instance"""
        if neighbor_info.neighbor in self.neighbors:
            raise(ValueError("Neighbor already exists."))
        self.neighbors[neighbor_info.neighbor] = neighbor_info

    def get_neighbor(self, neighbor):
        """Get the TopologyNeighborInfo entry for this prefix given an
        RTPNeighbor instance."""
        return self.neighbors[neighbor]

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
        # formation).
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
        for neighbor in self.neighbors.itervalues():
            if self.prefix in neighbor.waiting_for_replies:
                return False
        return True

    def get_all_feasible_successors(self):
        """Compute a list of all possible feasible successors based on the
        current successor."""
        feasible_successors = list()
        if self.successor == self.SELF_SUCCESSOR:
            return
        feasible_distance = self.successor.full_distance.compute_metric(*self._get_kvalues())
        for n_entry in self.neighbors:
            if n_entry.metric.compute_metric(*self._get_kvalues()) < \
               feasible_distance:
                feasible_successors.append(n_entry)
        return feasible_successors

    def get_feasible_successor(self):
        """Return the best feasible successor for this route if any exist,
        otherwise return None."""
        if not entries:
            return None
        return min(entries, key=self._get_min_metric)

    def _get_min_metric(self, n_entry):
        return n_entry.full_distance.compute_metric()


class TopologyNeighborInfo(object):
    def __init__(self, neighbor, reported_distance, get_kvalues):
        """neighbor -- an RTPNeighbor instance or None for the local router
        reported_distance -- the metric advertised by the neighbor
              (composite metric class such as rtptlv.ValueClassicMetric, not
              an integer)
        get_kvalues -- a function to retrieve the current K-values"""
        # Note that the interface on which a neighbor was observed is stored
        # within the RTPNeighbor instance.
        self.neighbor          = neighbor
        self.reported_distance = reported_distance
        self.reply_flag        = True
        self.full_distance     = copy.deepcopy(reported_distance)
        self._get_kvalues      = get_kvalues

        # neighbor is None when it refers to the local router, in which
        # case both the full distance and the reported distance are
        # effectively 0. For anything else, the full distance is the reported
        # distance plus the interface cost.
        if self.neighbor:
            self._update_full_distance()

    def _update_full_distance(self):
        self.full_distance.update_for_iface(self.neighbor.iface)
        self.full_distance.compute_metric(*get_kvalues())

    @property
    def reported_distance(self):
        return self._reported_distance

    @reported_distance.setter
    def reported_distance(self, val):
        self._reported_distance = val
        self._update_full_distance()


class EIGRP(rtp.ReliableTransportProtocol):
    """An EIGRP implementation based on Cisco's draft informational RFC
    located here:
 
    http://www.ietf.org/id/draft-savage-eigrp-01.txt"""

    DEFAULT_KVALUES = [ 1, 0, 1, 0, 0 ]
    MC_IP = "224.0.0.10"

    def __init__(self, requested_ifaces, routes=None, import_routes=False,
                 admin_port=None, *args, **kwargs):
        """
        requested_ifaces -- Iterable of IP addresses to send from
        routes -- Iterable of routes to import
        import_routes -- Import routes from the kernel (True or False)
        log_config -- Configuration filename
        admin_port -- The TCP port to bind to the administrative interface
                      (not implemented)
        """
        self._topology = dict()
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

        self._register_op_handlers()
        for iface in requested_ifaces:
            self.activate_iface(iface)
        self._init_routes(import_routes, routes)
        if sys.platform == "linux2":
            self_iface_event_listener = netlink_listener.LinuxIfaceEventListener(self._link_up, self._link_down)
        else:
            self.log.info("Currently no iface event listener for Windows.")
        #eigrpadmin.run(self, port=admin_port)

    def _link_up(self, ifname):
        # XXX TODO
        self.log.info("Link up: {}".format(ifname))

    def _link_down(self, ifname):
        # XXX TODO
        self.log.info("Link down: {}".format(ifname))

    def _new_kvalues(self):
        """Clear any precomputed metrics in the topology table to force
        the use of the new kvalues."""
        self.log.debug("KValues changed, clearing precomputed metrics.")
        for prefix, t_entry in self._topology.iteritems():
            for neighbor in t_entry.neighbors:
                neighbor.reported_distance.clear_saved_metric()
                neighbor.full_distance.clear_saved_metric()

    def _get_kvalues(self):
        return self._k1, self._k2, self._k3, self._k4, self._k5

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
        self.log.debug5("Writing packet to {}, iface {}.".format(dst, \
                        src or "unspecified"))
        if src:
            self.transport.setOutgoingInterface(src)
        self.transport.write(msg, (dst, 0))

    def _register_op_handlers(self):
        self._op_handlers = dict()
        self._op_handlers[self._rtphdr.OPC_UPDATE] = self._eigrp_op_handler_update
        self._op_handlers[self._rtphdr.OPC_QUERY] = self._eigrp_op_handler_query
        self._op_handlers[self._rtphdr.OPC_REPLY] = self._eigrp_op_handler_reply
        self._op_handlers[self._rtphdr.OPC_HELLO] = self._eigrp_op_handler_hello
        self._op_handlers[self._rtphdr.OPC_SIAQUERY] = self._eigrp_op_handler_siaquery
        self._op_handlers[self._rtphdr.OPC_SIAREPLY] = self._eigrp_op_handler_siareply

    def _eigrp_op_handler_update(self, neighbor, hdr, tlvs):
        self.log.debug("Processing UPDATE")
        query_tlvs = list()
        update_tlvs = list()
        for tlv in tlvs:
            if tlv.type == rtptlv.TLVInternal4.TYPE:
                self._op_update_handler_tlvinternal4(neighbor,
                                                     hdr,
                                                     tlv,
                                                     query_tlvs,
                                                     update_tlvs)
            else:
                self.log.debug("Unexpected TLV type: {}".format(tlv))
                return

        # Send UPDATE and/or QUERY if necessary.
        if update_tlvs:
            self._send(dests=self._get_active_ifaces(),
                       opcode=rtp.OPC_UPDATE,
                       tlvs=update_tlvs,
                       ack=True)
        if query_tlvs:
            self._send(dests=self._get_active_ifaces(),
                       opcode=rtp.OPC_QUERY,
                       tlvs=query_tlvs,
                       ack=True)

    def _op_update_handler_tlvinternal4(self, neighbor, hdr, tlv, query_tlvs,
                                        update_tlvs):
        """Handle an IPv4 Internal TLV within an UPDATE packet.
        neighbor -- RTP neighbor that sent the update
        hdr -- the RTP header
        tlv -- the IPv4 Internal Route TLV
        query_tlvs -- a list that this function will append TLVs to be
                      included in a QUERY packet
        update_tlvs -- a list that this function will append TLVs to be
                       included in an UPDATE packet"""
        # XXX hdr unused.
        prefix = ipaddr.IPv4Network("{}/{}".format(tlv.dest.exploded,
                                                   tlv.plen))

        # All zeroes means use the source address of the incoming packet.
        if tlv.nexthop.ip.exploded == "0.0.0.0":
            nexthop = neighbor.ip.exploded
        else:
            nexthop = tlv.nexthop.ip.exploded

        try:
            t_entry = self._topology[prefix]
        except KeyError:
            # New prefix.
            self._topology[prefix] = TopologyEntry(prefix,
                                                   self._get_kvalues)
            t_entry = self._topology[prefix]

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
                # Use this neighbor as the successor.
                successor = data
                self.log.debug("Installing new successor for prefix {}: "
                               "{}".format(prefix.exploded, successor))
                t_entry.successor = t_entry.get_neighbor(neighbor)
                tlv.update_for_iface(neighbor.iface)
                total_metric = tlv.metric.compute_metric(self._k1,
                                                         self._k2,
                                                         self._k3,
                                                         self._k4,
                                                         self._k5)
                tlv.nexthop.ip = ipaddr.IPv4Address("0.0.0.0")
                try:
                    # Uninstall route to old nexthop, if one existed.
                    # XXX Should know in advance whether this is required or
                    # not.
                    self._sys.uninstall_route(net=prefix.network.exploded,
                                              plen=prefix.prefixlen)
                except ValueError:
                    pass
                self._sys.install_route(net=prefix.network.exploded,
                                        plen=prefix.prefixlen,
                                        metric=total_metric,
                                        nexthop=nexthop)
                update_tlvs.append(tlv)
            elif action == dualfsm.UNINSTALL_SUCCESSOR:
                # XXX Stop using route for routing.
                pass
            elif action == dualfsm.SEND_QUERY:
                # Include this TLV in a QUERY packet.
                # Reuse this TLV instead of creating another one. Change
                # the metric's delay field to indicate an unreachable prefix.
                self.log.debug("Including prefix {} in QUERY "
                               "packet".format(prefix.exploded))
                tlv.metric.dly = tlv.metric.METRIC_UNREACHABLE
                query_tlvs.append(tlv)
            else:
                assert False, "Unknown action returned by fsm: " \
                       "{}".format(action)
        return

    def _eigrp_op_handler_query(self, neighbor, hdr, tlvs):
        self.log.debug("Processing QUERY")
        query_tlvs = list()
        for tlv in tlvs:
            if tlv.type == rtptlv.TLVInternal4.TYPE:
                self._op_query_handler_tlvinternal4(neighbor,
                                                    hdr,
                                                    tlv,
                                                    query_tlvs)
            else:
                self.log.debug("Unexpected TLV type: {}".format(tlv))
                return

        # Send QUERY if necessary.
        if query_tlvs:
            self._send(dests=self._get_active_ifaces(),
                       opcode=rtp.OPC_QUERY,
                       tlvs=query_tlvs,
                       ack=True)

    def _op_query_handler_tlvinternal4(self, neighbor, hdr, tlv, query_tlvs):
        """Handle an IPv4 Internal TLV within a QUERY packet.
        neighbor -- RTP neighbor that sent the update
        hdr -- the RTP header
        tlv -- the IPv4 Internal Route TLV
        query_tlvs -- a list that this function will append TLVs to be
                      included in a QUERY packet"""
        # XXX hdr unused.
        # Other verbiage from the RFC:
        # A REPLY packet will be sent in response to a QUERY or SIA-QUERY
        # packet, if the router believes it has an alternate feasible
        # successor. The REPLY packet will include a TLV for each destination
        # and the associated vectorized metric in its own topology table.
        prefix = ipaddr.IPv4Network("{}/{}".format(tlv.dest.exploded,
                                                   tlv.plen))

        try:
            t_entry = self._topology[prefix]
        except KeyError:
            # New prefix. From RFC rev 3:
            # When a query is received for a route that doesn't
            # exist in our topology table, a reply with infinite metric is
            # sent and an entry in the topology table is added with the metric
            # in the QUERY if the metric is not an infinite value.
            # TODO: Have fsm send a reply w/ INF metric and add entry in
            # topology table if tlv.metric is not INF.
            self._topology[prefix] = TopologyEntry(prefix,
                                                   self._get_kvalues)
            t_entry = self._topology[prefix]

        actions = t_entry.handle_query(neighbor, nexthop, t_entry)

        for action, data in actions:
            if action == dualfsm.NO_OP:
                continue
            elif action == dualfsm.INSTALL_SUCCESSOR:
                # XXX Try to be able to do the same thing that the other
                # TLV handling functions do so we can move this logic into
                # a shared function.
                pass
            elif action == dualfsm.SEND_QUERY:
                pass
            elif action == dualfsm.SEND_REPLY:
                pass
            else:
                assert False, "Unknown action returned by fsm: " \
                       "{}".format(action)

    def _eigrp_op_handler_reply(self, neighbor, hdr, tlvs):
        self.log.debug("Processing REPLY")
        query_tlvs = list()
        for tlv in tlvs:
            if tlv.type == rtptlv.TLVInternal4.TYPE:
                self._op_reply_handler_tlvinternal4(neighbor,
                                                    hdr,
                                                    tlv)
            else:
                self.log.debug("Unexpected TLV type: {}".format(tlv))
                return

    def _op_reply_handler_tlvinternal4(self, neighbor, hdr, tlv):
        """Handle an IPv4 Internal TLV within a QUERY packet.
        neighbor -- RTP neighbor that sent the update
        hdr -- the RTP header
        tlv -- the IPv4 Internal Route TLV"""
        # XXX hdr unused.
        prefix = ipaddr.IPv4Network("{}/{}".format(tlv.dest.exploded,
                                                   tlv.plen))
        try:
            t_entry = self._topology[prefix]
        except KeyError:
            # XXX
            # New prefix, shouldn't normally happen... but what do
            # we do if it does?  Let's just ignore it.
            self.log.warn("Ignoring TLV in REPLY that contains unknown "
                          "prefix: {},".format(prefix))
            return

        actions = t_entry.handle_reply(neighbor, nexthop, t_entry)

        for action, data in actions:
            if action == dualfsm.NO_OP:
                continue
            elif action == dualfsm.INSTALL_SUCCESSOR:
                # XXX Try to be able to do the same thing that the other
                # TLV handling functions do so we can move this logic into
                # a shared function.
                pass
            elif action == dualfsm.SEND_QUERY:
                pass
            elif action == dualfsm.SEND_REPLY:
                pass
            else:
                assert False, "Unknown action returned by fsm: " \
                       "{}".format(action)

    def _eigrp_op_handler_hello(self, neighbor, hdr, tlvs):
        """RTP deals with HELLOs, nothing to do here."""
        pass

    def _send(self, dsts, opcode, tlvs, ack, flags=0):
        """Send a packet to one or more neighbors or interfaces. This is the
        function that EIGRP should use to pass data into RTP.

        dsts -- an iterable of RTPInterface or RTPNeighbor objects
        opcode -- The value to place in the RTP header's opcode field. Should
                  be one of the self._rtphdr.OPC_* values.
        tlvs -- an iterable of TLVs to include in the packet
        ack -- if True, require an ACK for this packet
        flags -- The value to place in the RTP header's flags field. Should be
                 one of the self._rtphdr.FLAG_* values.
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
            self.log.info("Received invalid/unhandled opcode {} from "
                          "{}".format(hdr.opcode, neighbor))
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
