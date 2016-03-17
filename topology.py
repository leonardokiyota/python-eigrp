# Python-EIGRP (http://python-eigrp.googlecode.com)
# Copyright (C) 2016 Patrick F. Allen
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

import copy

import dualfsm

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
        """prefix - this network's network address and mask. This is
        just for informational/debugging purposes; it not used to identify the
        TopologyEntry.
        The prefix assigned to the ToplogyEntry is identified by the key used
        in the TopologyTable to access this entry."""
        self.prefix               = prefix
        self.fsm                  = dualfsm.DualFsm(get_kvalues)
        self.neighbors            = dict()
        self.successor            = self.NO_SUCCESSOR
        self._feasible_successors = list()
        self._get_kvalues         = get_kvalues
        self.feasible_distance    = None

    def add_neighbor(self, neighbor_info):
        """Add a neighbor to the topology entry.
        neighbor_info - a TopologyNeighborInfo instance"""
        if neighbor_info.neighbor in self.neighbors:
            raise(ValueError("Neighbor already exists."))
        self.neighbors[neighbor_info.neighbor] = neighbor_info

    def get_neighbor(self, neighbor):
        """Get the TopologyNeighborInfo entry for this prefix given an
        RTPNeighbor instance."""
        return self.neighbors[neighbor]

    def update_neighbor(self, neighbor, reported_distance):
        """Update neighbor's reported distance and add/remove to/from
        list of feasible successors if necessary."""
        if not self.feasible_distance:
            return
        if reported_distance <= self.feasible_distance:
            self.feasible_successors.append(neighbor)
        elif reported_distance > self.feasible_distance:
            if neighbor in self.feasible_successors:
                self.feasible_successors.remove(neighbor)

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
        for n_info in self.neighbors.itervalues():
            if n_info.waiting_for_reply:
                return False
        return True

    def compute_feasible_successors(self):
        """Compute a list of all possible feasible successors based on the
        current successor."""
        self.feasible_successors = list()
        if self.successor == self.SELF_SUCCESSOR:
            # XXX ?
            return
        self.feasible_distance = self.successor.full_distance.compute_metric(*self._get_kvalues())
        for n_entry in self.neighbors:
            if n_entry.metric.compute_metric(*self._get_kvalues()) < \
               feasible_distance:
                feasible_successors.append(n_entry)

    def get_feasible_successor(self):
        """Return the best feasible successor for this route if any exist,
        otherwise return None."""
        # XXX Need a better function name; this is used when no FSes currently
        # exist. See draft 4, page 15 for possible nomenclature.
        # "recalculate_successor()"? calculate_new_successor()?
        # XXX Or - this could be used to hide the complexity of only
        # performing recalculations when no FSes exist. This function
        # can figure out if there is an FS, if so return that. If not,
        # choose a new successor by performing a full recalculation.
        if not self.neighbors:
            return None
        min(self.neighbors, key=self._get_min_metric)

    def _get_min_metric(self, n_entry):
        return n_entry.full_distance.compute_metric()


class TopologyNeighborInfo(object):
    def __init__(self, neighbor, reported_distance, get_kvalues):
        """neighbor - an RTPNeighbor instance or None for the local router
        reported_distance - the metric advertised by the neighbor
              (composite metric class such as rtptlv.ValueClassicMetric, not
              an integer)
        get_kvalues - a function to retrieve the current K-values"""
        # Note that the interface on which a neighbor was observed is stored
        # within the RTPNeighbor instance.
        self.neighbor          = neighbor
        self._get_kvalues      = get_kvalues
        self.reported_distance = reported_distance

        # waiting_for_reply should be init'd to False in normal cases.
        # XXX Need to verify the behavior when a neighbor comes up while a
        # query is out.
        self.waiting_for_reply = False

    @property
    def reported_distance(self):
        return self._reported_distance

    @reported_distance.setter
    def reported_distance(self, val):
        self._reported_distance = val
        self.full_distance = copy.deepcopy(self._reported_distance)
        self.full_distance.update_for_iface(self.neighbor.iface)
