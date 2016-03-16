#!/usr/bin/env python

"""The DUAL finite state machine."""

# Get fysom using "pip install fysom"
try:
    from fysom import Fysom
except ImportError:
    print("fysom module is not installed. Install with 'pip install fysom'")

from topology import TopologyNeighborInfo

# Actions that the FSM can request of EIGRP.
# The current idea is that the FSM returns a list of dicts containing actions
# that eigrp should perform based on the fsm's processing.
# Each requested action will be a dict of the form: {action: '...', data: '...'}
# The data key will contain action-dependent data. For example, if the action
# requires that a metric be updated, the data will contain the new metric.
NO_OP                  = 1
INSTALL_SUCCESSOR      = 2
UNINSTALL_SUCCESSOR    = 3
MODIFY_SUCCESSOR_ROUTE = 4
SEND_QUERY             = 5
SEND_REPLY             = 6

# Not in love with having to ask for a message to be logged, but I like
# it better than using a log object for now.
LOG_MSG                = 7

class DualFsm(object):

    # Input events. See section 3.5, Dual FSM, in the RFC.
    DUAL_EVENTS = [ {'name': 'IE1',  'src': 'Passive', 'dst': 'Passive'},
                    {'name': 'IE2',  'src': 'Passive', 'dst': 'Passive'},
                    {'name': 'IE3',  'src': 'Passive', 'dst': 'Active3'},
                    {'name': 'IE4',  'src': 'Passive', 'dst': 'Active1'},
                    {'name': 'IE5',  'src': 'Active0', 'dst': 'Active2'},
                    {'name': 'IE6',  'src': 'Active0', 'dst': 'Active0'},
                    {'name': 'IE7',  'src': 'Active0', 'dst': 'Active0'},
                    {'name': 'IE8',  'src': 'Active0', 'dst': 'Active0'},
                    {'name': 'IE6',  'src': 'Active1', 'dst': 'Active1'},
                    {'name': 'IE7',  'src': 'Active1', 'dst': 'Active1'},
                    {'name': 'IE8',  'src': 'Active1', 'dst': 'Active1'},
                    {'name': 'IE6',  'src': 'Active2', 'dst': 'Active2'},
                    {'name': 'IE7',  'src': 'Active2', 'dst': 'Active2'},
                    {'name': 'IE8',  'src': 'Active2', 'dst': 'Active2'},
                    {'name': 'IE6',  'src': 'Active3', 'dst': 'Active3'},
                    {'name': 'IE7',  'src': 'Active3', 'dst': 'Active3'},
                    {'name': 'IE8',  'src': 'Active3', 'dst': 'Active3'},
                    {'name': 'IE9',  'src': 'Active1', 'dst': 'Active0'},
                    {'name': 'IE10', 'src': 'Active3', 'dst': 'Active2'},
                    {'name': 'IE11', 'src': 'Active0', 'dst': 'Active1'},
                    {'name': 'IE12', 'src': 'Active2', 'dst': 'Active3'},
                    {'name': 'IE13', 'src': 'Active3', 'dst': 'Passive'},
                    {'name': 'IE14', 'src': 'Active0', 'dst': 'Passive'},
                    {'name': 'IE15', 'src': 'Active1', 'dst': 'Passive'},
                    {'name': 'IE16', 'src': 'Active2', 'dst': 'Passive'},
                  ]

    def __init__(self, get_kvalues):
        """get_kvalues - a function to retrieve the current K-values"""
        callbacks = { 'onPassive': self._enter_passive,
                      'onActive0': self._enter_active0,
                      'onActive1': self._enter_active1,
                      'onActive2': self._enter_active2,
                      'onActive3': self._enter_active3,
                    }
        self._states = { 'passive': _state_passive,
                         'active0': _state_active0,
                         'active1': _state_active1,
                         'active2': _state_active2,
                         'active3': _state_active3,
                       }
        self._state = self._states['passive']
        self.fsm = Fysom({'initial' : 'Passive',
                          'events'  : self.DUAL_EVENTS
                         })
        self._get_kvalues = get_kvalues

    def _enter_passive(self, e):
        self._state = self._states['passive']

    def _enter_active0(self, e):
        self._state = self._states['active0']

    def _enter_active1(self, e):
        self._state = self._states['active1']

    def _enter_active2(self, e):
        self._state = self._states['active2']

    def _enter_active3(self, e):
        self._state = self._states['active3']

    def handle_update(self, neighbor, nexthop, metric, t_entry, get_kvalues):
        return self._state.handle_update(neighbor,
                                         nexthop,
                                         metric,
                                         t_entry,
                                         get_kvalues)

    def handle_reply(self, neighbor, nexthop, t_entry):
        self._state.handle_reply(neighbor,
                                 nexthop,
                                 t_entry)

    def handle_query(self, neighbor, nexthop, metric, t_entry, get_kvalues):
        self._state.handle_query(neighbor,
                                 nexthop,
                                 metric,
                                 t_entry,
                                 get_kvalues)

    def handle_link_down(self, linkmsg):
        self._state.handle_link_down(linkmsg)

    def handle_link_metric_change(self, linkmsg):
        self._state.handle_link_metric_change(linkmsg)


class DualState(object):
    pass


class StatePassive(DualState):
    def handle_update(self, neighbor, nexthop, metric, t_entry, get_kvalues):
        # XXX nexthop is unused here. Do we need to pass it in?
        # (What about for other states that handle updates?)

        # IE2 and IE4, for update pkts.
        #
        # Pseudo code:
        #
        # If the update came from the successor:
        #    If the metric is the same as the installed metric:
        #        Return (do nothing)
        #    Else:
        #        # Came from successor and metric is different
        #        If successor is no longer reachable:
        #            If there is a feasible successor:
        #                # IE2, stay in Passive
        #                Install feasible successor
        #                Send an update packet with the new metric
        #            Else:
        #                # No route to dest. IE4, go to Active.
        #                # XXX Send QRY to all neighbors on all ifaces,
        #                # Set REPLY status flag to 1 because we're waiting
        #                # for responses. Where do we want to do this?
        #                # Stop using route for routing.
        #            Endif
        #        Else:
        #            # Successor is still reachable and metric changed
        #            Send an update packet with the new metric
        #        Endif
        # Else:
        #    # Update came from non-neighbor
        #    Change the neighbor's metric information

        # If sending neighbor was not already associated with this
        # prefix, add it to the topology entry.
        try:
            neighbor_entry = t_entry.get_neighbor(neighbor)
        except KeyError:
            t_entry.add_neighbor(TopologyNeighborInfo(neighbor,
                                                      tlv.metric,
                                                      get_kvalues))
            neighbor_entry = t_entry.get_neighbor(neighbor)
        t_entry.update_neighbor(neighbor_entry, tlv.metric)
        successor_entry = t_entry.successor

        if successor_entry == neighbor_entry:
            # QRY came from current successor
            kvalues = get_kvalues()
            if successor_entry.reported_distance.compute_metric(*kvalues) == \
                                metric.compute_metric(*kvalues):
                # If metric hasn't changed, do nothing
                return list((NO_OP, None))
            else:
                # Came from successor and metric is different
                if not metric.reachable():
                    # Unreachable via successor. Use a feasible successor if
                    # available.
                    # XXX TODO implement this, and be aware if it returns
                    # neighbor or neighbor_info. Going to end up needing both
                    # before we return: neighbor for INSTALL_SUCCESSOR and
                    # neighbor info for set_successor
                    fs = t_entry.get_feasible_successor()
                    if fs:
                        # Install FS and send update with new metric.
                        return list((INSTALL_SUCCESSOR, fs.neighbor))
                    else:
                        # No known route to dest. IE4, go to Active.
                        t_entry.fsm.fsm.IE4()

                        # Send QRY to all neighbors for this prefix.
                        actions = list()
                        actions.append((SEND_QUERY, tlv))

                        # Stop using route for routing.
                        # XXX Believe we should keep the successor listed as
                        # t_entry.successor until we get a new successor
                        # or we find that no good successors exist. We
                        # need a reference to the "previous successor"
                        # in handle_link_down, at least.
                        actions.append((UNINSTALL_SUCCESSOR, None))

                        # Set reply flag for all neighbors for this prefix
                        for n_info in t_entry.neighbors:
                            n_info.waiting_for_reply = True
                else:
                    # Successor is still reachable but metric changed.
                    # Update the metric for this neighbor in topology entry
                    # and routing table.
                    # Send an update packet with the new metric.
                    # XXX Implement the SET_METRIC and SEND_UPDATE in caller.
                    # Can probably make set_metric more generic to handle
                    # updating routes in general, Then other return values
                    # can use this as well.
                    # SEND_UPDATE could be used above as well so sending
                    # an update isn't implied when using INSTALL_SUCCESSOR.
                    # Not sure if that is useful for now, depends if anything
                    # else in the fsm installs a successor without sending
                    # an update... which doesn't sound likely.
                    successor_entry.reported_distance = tlv.metric
                    successor_entry.update_full_distance()
                    actions = list()
                    actions.append((SET_METRIC, tlv))
                    actions.append((SEND_UPDATE, tlv))
                    return actions
        else:
            # Update came from non-successor. Update its information in the
            # topology entry.
            # If there is no successor currently and the prefix is reachable
            # via this neighbor, use this neighbor as the successor.
            if successor_entry == t_entry.NO_SUCCESSOR:
                if not metric.reachable():
                    return list((NO_OP, None))
                return list((INSTALL_SUCCESSOR, neighbor))
        return list((NO_OP, None))

    def handle_reply(self, neighbor, nexthop, t_entry):
        # We shouldn't normally receive a REPLY in Passive state, and there
        # is no reason we would need to parse it here. Just ignore it.
        return list((NO_OP, None))

    def handle_query(self, neighbor, nexthop, metric, t_entry, get_kvalues):
        # IE1 and IE3
        #
        # If query came from successor:
        #    If we have a feasible successor:
        #        # XXX I think we send a reply to successor w/ our route info,
        #        # but try to check in the RFC or Doyle on that.
        #    Else:
        #        # IE3, no feasible successor
        #        Transition to Active3 state
        #        Send query to all neighbors on all interfaces
        #        Set reply status flag to 1
        #    Endif
        # Else:
        #    # Query did not come from successor
        #    # IE1
        #    Send reply to src with our route info
        if t_entry.successor == neighbor:
            fs = t_entry.get_feasible_successor()
            if fs:
                # XXX What should the actions list look like for this?
                # Just pass up the FS I think - we already know the tlv
                # in the caller, so we can fill out the reply correctly I
                # think.
                return list((SEND_REPLY, fs))
            else:
                t_entry.fsm.fsm.IE3()
                actions = list()
                actions.append((SEND_QUERY, tlv))

                # Stop using route for routing.
                actions.append((UNINSTALL_SUCCESSOR, None))

                # Set reply flag for all neighbors for this prefix
                for n_info in t_entry.neighbors:
                    n_info.waiting_for_reply = True
        else:
            # Query did not come from successor, reply with our route info
            # XXX What should the actions list look like for this?
            # Just pass up the successor I think - we already know the tlv
            # in the caller, so we can fill out the reply correctly I
            # think.
            t_entry.fsm.fsm.IE1()
            return list((SEND_REPLY, successor))

    def handle_link_down(self, linkmsg):
        # IE2 and IE4 for link down changes. Snipped from handle_update,
        # so this can be consolidated in a shared function.
        #
        #        If successor is no longer reachable:
        #            If there is a feasible successor:
        #                # IE2, stay in Passive
        #                Install feasible successor
        #                Send an update packet with the new metric
        #            Else:
        #                # No route to dest. IE4, go to Active.
        #                # XXX Send QRY to all neighbors on all ifaces,
        #                # For all neighbors, set REPLY status flag to 1
        #                # because we're waiting
        #                # for responses. Where do we want to do this?
        #                # Stop using route for routing.
        #                # XXX What if we have no other neighbors? Currently
        #                # we'll never determine that we can stop waiting
        #                # for replies, since none will ever come, and
        #                # that determination only happens when we recv a
        #                # reply.
        #            Endif
        #        Endif
        pass

    def handle_link_metric_change(self, linkmsg):
        # XXX Would be handled similarly to handle_link_down
        pass


class BaseActive(DualState):

    def _handle_query_from_successor(self, neighbor, nexthop, metric, t_entry, get_kvalues):
        """Must override in subclass.
        This function is called when we have received
        all replies and thus should transition back to passive. This function
        should handle responding to the old successor if necessary then
        sending the correct input event to transition back to passive."""
        assert False

    def _handle_query_from_successor(self, neighbor, nexthop, metric, t_entry, get_kvalues):
        """Must override in subclass.
        This function is called when we have received a query about a network
        from a neighbor which is our current successor for that network."""
        assert False

    def handle_update(self, neighbor, nexthop, metric, t_entry, get_kvalues):
        # XXX Nexthop unused. Do we need to pass it in?
        # If update indicates a metric change:
        #     IE7. Record the metric information.
        # Endif
        if t_entry.get_neighbor(neighbor).reported_distance != metric:
            t_entry.fsm.fsm.IE7()
            t_entry.get_neighbor(neighbor).reported_distance = metric
        return list((NO_OP, None))

    def handle_reply(self, neighbor, nexthop, t_entry):
        # IE8 for REPLYs. Clear REPLY flag for this neighbor.
        # If all neighbors have replied:
        #    IE13/14/15/16. Call self._received_last_reply
        # Endif

        # TODO: What about the part where we determine if we learned of a new
        # FS? I don't actually see this detailed in the RFC (rev 1). Maybe
        # it's in a newer rev.
        #
        # Should be able to base our processing here off of the QUERY handling
        # code. We know what to expect here based on what gets filled in during
        # query processing.
        # We need to record the reply info somewhere, presumably the topology
        # entry, while we wait for all replies.
        # Presumably we check if the tlv's metric is reachable or not and
        # either add a new successor here or don't.
        t_entry.fsm.fsm.IE8()
        n_info = t_entry.get_neighbor(neighbor)
        n_info.waiting_for_reply = False
        if t_entry.all_replies_received():
            return self._received_last_reply(neighbor, nexthop, t_entry)
        return list((self.NO_OP, None))

    def handle_query(self, neighbor, nexthop, metric, t_entry, get_kvalues):
        # If sender is the successor:
        #     # XXX This can happen in Active0 or Active1 (it's IE5). Should
        #     # pass in another handler function like _received_last_reply
        #     # that other states can use to act here. Active2 and 3 should
        #     # log/ignore it, Active0 and 1 should call IE5 (and also do
        #     # something?).
        # Else:
        #     # Sender is not the successor
        #     IE6. Send a REPLY.
        #          Rev5 seems to clarify that the receiver of the query
        #          records the cost, not the sender.
        # Endif
        if neighbor == t_entry.successor:
            # XXX What args do I need?
            return self._handle_query_from_successor(neighbor, nexthop, metric, t_entry, get_kvalues)
        else:
            t_entry.fsm.fsm.IE6()
            return list((SEND_REPLY, successor))

    def handle_link_metric_change(self, linkmsg):
        pass


class StateActive0(BaseActive):

    # We can have IEs: 5,6,7,8,9,11

    # XXX Handle IE 5 and 6 in BaseActive. See BaseActive.handle_query

    def _received_last_reply(self, neighbor, nexthop, t_entry):
        # "need not send a REPLY to the old successor"
        # IE14. Transition to passive.
        t_entry.fsm.fsm.IE14()
        fs = t_entry.get_feasible_successor()
        if fs:
            return list((INSTALL_SUCCESSOR, fs.neighbor))
        else:
            # XXX Still no feasible successor, what else should I do here?
            return list((NO_OP, None))

    def _handle_query_from_successor(neighbor, nexthop, metric, t_entry, get_kvalues):
        # IE5. There is no special handling mentioned in Rev5 other than
        # to set the query origin flag to 3 (i.e. transition to Active3).
        t_entry.fsm.fsm.IE5()

    def handle_link_down(self, linkmsg):
        # The relevant link has already failed in Active3 or Passive in order
        # to get to Active2, so it can't fail again.
        # (What about if link is flapping, i.e. goes down and then back up and
        # down again? How do we handle the link going up?
        # Two cases to worry about:
        # 1. The link that failed is the network that we're 'active' for.
        # 2. The link that failed connects to a neighbor that advertised a
        #    route for which we're now in 'active'.
        # In case 1:
        #    ?
        # In case 2:
        #    We'd establish an adjacency with the neighbor, then get an
        #    UPDATE for the active network. This is handled in
        #    BaseActive.handle_update as IE7. We record the updated metric
        #    info as part of IE7 and do nothing further at that time.
        pass

    def handle_link_metric_change(self, linkmsg):
        # XXX
        # If link cost to successor increased:
        #   If last REPLY was received from all neighbors:
        #     If there is no feasible successor:
        #       IE11.
        #       Route stays in active. Transition to Active1.
        #       Send QUERY to all neighbors.
        #       (Set QUERY origin flag to 1.)
        pass


class StateActive1(BaseActive):

    # We can have IEs: 5,6,7,8,9,15

    def _received_last_reply(self, neighbor, nexthop, t_entry):
        # IE15.
        # All replies received.
        #
        # Either the router originated the query, or the FC was not satisfied
        # with the replies received in ACTIVE state.
        # Use minimum of all reported metrics as the new FD.
        # IE15 - Transition to passive. (I take it we're installing the
        # neighbor with the best metric as the new successor?)
        # If there was a QUERY from the old successor:
        #     Send reply to old successor (See note below)
        #
        # I don't believe there is a case where we can be in this function
        # and have received a query from the old successor. The point of
        # Active1, as I understand it, is that we haven't received a query
        # from the successor. So I don't think the last 'if' statement
        # logic is necessary, we shouldn't have to ever send a reply.
        # May be wrong.
        fs = t_entry.get_feasible_successor()
        if fs:
            return list((INSTALL_SUCCESSOR, fs.neighbor))
        else:
            # No FS... anything else I need to do here?
            return list((NO_OP, None))

    def _handle_query_from_successor(neighbor, nexthop, metric, t_entry,
                                     get_kvalues):
        # IE5. There is no special handling mentioned in Rev5 other than
        # to set the query origin flag to 3 (i.e. transition to Active3).
        t_entry.fsm.fsm.IE5()

    def handle_link_down(self, rtpiface, t_entry):
        # XXX Need to look at this again, just trying to work out roughly what
        # this function should look like.
        #
        # The relevant link has already failed in Active3 or Passive in order
        # to get to Active2, so it can't fail again.
        # (What about if link is flapping, i.e. goes down and then back up and
        # down again?)
        # If the failed link was between the router and its successor:
        #       Treat it as if a REPLY was received from successor
        #       # XXX I think this means we need to call handle_reply so we're not waiting for successor any more
        #       If local router already sent a QUERY:
        #           IE9. Transition to Active2 ("set QUERY origin flag...")
        if t_entry.successor == t_entry.SELF_SUCCESSOR:
            return list((NO_OP, None))

        if t_entry.successor.iface == rtpiface:
            # Note: This will cause IE8 to trigger, which is fine except
            # it might be confusing to see.
            # If this is the last reply we needed, then _received_last_reply
            # would normally transition to passive.
            # 
            self.handle_reply(successor, None, t_entry)

            # "When this occurs after the router originates a query..."
            # This should always be true for us; we queried as soon as
            # we were aware of successor's route loss. Only case where
            # this wouldn't make sense is if we only had to query our
            # successor. Since the link just failed, we might not
            # really need to bother going to IE9 here - but maybe we do.
            # 
            t_entry.fsm.fsm.IE9()


class StateActive2(BaseActive):

    # We can have IEs: 6,7,8,12,16

    def _received_last_reply(self, neighbor, nexthop, t_entry):
        # If there is a feasible successor:
        #     IE16. Transition to passive.
        #     (Presumably install FS as successor and use it for routing)
        # Else:
        #     IE12. Transition to Active3.
        #     Send QUERY to all neighbors
        # Endif
        fs = t_entry.get_feasible_successor()
        if fs:
            t_entry.fsm.fsm.IE16()
            return list((INSTALL_SUCCESSOR, fs))
        else:
            t_entry.fsm.fsm.IE12()
            return list((SEND_QUERY, t_entry))

    def _handle_query_from_successor(neighbor, nexthop, metric, t_entry, get_kvalues):
        # Shouldn't happen in Active2 or Active3. Could log or just ignore.
        return list((LOG_MSG, "Received unexpected query from successor in Active2"))

    def handle_link_down(self, linkmsg):
        # The relevant link has already failed in Active3 or Passive in order
        # to get to Active2, so it can't fail again.
        # (What about if link is flapping, i.e. goes down and then back up and
        # down again?)
        pass


class StateActive3(BaseActive):

    # We can have IEs: 6,7,8,10,13

    def _received_last_reply(self, neighbor, nexthop, t_entry):
        # Send reply to old successor
        # IE13. Transition to passive
        # XXX RFC's description of IE13/14/15 doesn't include text saying to
        # install a new route... but since we're transitioning to passive
        # I think we need to do that, if we have a valid route.

        # XXX Some of this is probably wrong.
        t_entry.fsm.fsm.IE13()
        fs = t_entry.get_feasible_successor()
        actions = list()
        if fs:
            # Install FS and send update with new metric.
            actions.append((INSTALL_SUCCESSOR, fs.neighbor))
        else:
            # XXX No feasible successors, what do I do?
            pass
        # XXX t_entry.successor should be the old successor until the new
        # successor is installed in the caller, so I should be able to use this
        # to send a reply to the old successor.
        actions.append((SEND_REPLY, t_entry.successor))
        return actions

    def _handle_query_from_successor(neighbor, nexthop, metric, t_entry,
                                     get_kvalues):
        # Shouldn't happen in Active2 or Active3. Could log or just ignore.
        return list((LOG_MSG, "Received unexpected query from successor in Active2"))

    def handle_link_down(self, linkmsg):
        # For all neighbors attached to this interface:
        #     IE8. Clear neighbor REPLY flag.
        #     If neighbor is successor:
        #         IE10. Transition to Active2 (set QUERY origin flag)
        #     Endif
        # Endfor
        #
        # XXX IE10 and IE13 can happen simultaneously, i.e. a link goes down
        # and that means we've received all replies from all neighbors.
        # Do we go to Active2 or Passive state?
        # We should end up in Passive, but we might hit Active2 first
        # depending on the function logic.
        pass


# FSM states. Shared by all DualFsm objects.
_state_passive = StatePassive()
_state_active0 = StateActive0()
_state_active1 = StateActive1()
_state_active2 = StateActive2()
_state_active3 = StateActive3()
