#!/usr/bin/env python

from fysom import Fysom

class DualFsm(object):

    # Input events. See RFC pages 11-12.
    IE1_NAME  = 'IE1'
    IE2_NAME  = 'IE2'
    IE3_NAME  = 'IE3'
    IE4_NAME  = 'IE4'
    IE5_NAME  = 'IE5'
    IE6_NAME  = 'IE6'
    IE7_NAME  = 'IE7'
    IE8_NAME  = 'IE8'
    IE9_NAME  = 'IE9'
    IE10_NAME = 'IE10'
    IE11_NAME = 'IE11'
    IE12_NAME = 'IE12'
    IE13_NAME = 'IE13'
    IE14_NAME = 'IE14'
    IE15_NAME = 'IE15'
    IE16_NAME = 'IE16'
    
    DUAL_EVENTS = [ {'name': IE1_NAME,  'src': 'Passive', 'dst': 'Passive'},
                    {'name': IE2_NAME,  'src': 'Passive', 'dst': 'Passive'},
                    {'name': IE3_NAME,  'src': 'Passive', 'dst': 'Active3'},
                    {'name': IE4_NAME,  'src': 'Passive', 'dst': 'Active1'},
                    {'name': IE5_NAME,  'src': 'Active0', 'dst': 'Active2'},
                    {'name': IE6_NAME,  'src': 'Active0', 'dst': 'Active0'},
                    {'name': IE7_NAME,  'src': 'Active0', 'dst': 'Active0'},
                    {'name': IE8_NAME,  'src': 'Active0', 'dst': 'Active0'},
                    {'name': IE6_NAME,  'src': 'Active1', 'dst': 'Active1'},
                    {'name': IE7_NAME,  'src': 'Active1', 'dst': 'Active1'},
                    {'name': IE8_NAME,  'src': 'Active1', 'dst': 'Active1'},
                    {'name': IE6_NAME,  'src': 'Active2', 'dst': 'Active2'},
                    {'name': IE7_NAME,  'src': 'Active2', 'dst': 'Active2'},
                    {'name': IE8_NAME,  'src': 'Active2', 'dst': 'Active2'},
                    {'name': IE6_NAME,  'src': 'Active3', 'dst': 'Active3'},
                    {'name': IE7_NAME,  'src': 'Active3', 'dst': 'Active3'},
                    {'name': IE8_NAME,  'src': 'Active3', 'dst': 'Active3'},
                    {'name': IE9_NAME,  'src': 'Active1', 'dst': 'Active0'},
                    {'name': IE10_NAME, 'src': 'Active3', 'dst': 'Active2'},
                    {'name': IE11_NAME, 'src': 'Active0', 'dst': 'Active1'},
                    {'name': IE12_NAME, 'src': 'Active2', 'dst': 'Active3'},
                    {'name': IE13_NAME, 'src': 'Active3', 'dst': 'Passive'},
                    {'name': IE14_NAME, 'src': 'Active0', 'dst': 'Passive'},
                    {'name': IE15_NAME, 'src': 'Active1', 'dst': 'Passive'},
                    {'name': IE16_NAME, 'src': 'Active2', 'dst': 'Passive'},
                  ]

    def __init__(self):
        callbacks = { 'onPassive': self._enter_passive,
                      'onActive0': self._enter_active0,
                      'onActive1': self._enter_active1,
                      'onActive2': self._enter_active2,
                      'onActive3': self._enter_active3,
                    }
        # XXX Do I need 5 state objects in each FSM (i.e. for each route)
        # or can I have 5 shared state objects that all fsms use?
        self._states = { 'passive': StatePassive(),
                         'active0': StateActive0(),
                         'active1': StateActive1(),
                         'active2': StateActive2(),
                         'active3': StateActive3(),
                       }
        self._state = self._states['passive']
        self._fsm = Fysom({'initial' : 'Passive',
                           'events'  : self.DUAL_EVENTS
                          })
                          
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

    def handle_update(self, update):
        self._state.handle_update(update)

    def handle_reply(self, reply):
        self._state.handle_reply(reply)

    def handle_query(self, query):
        self._state.handle_query(query)

    def handle_link_down(self, linkmsg):
        self._state.handle_link_down(linkmsg)

    def handle_link_metric_change(self, linkmsg):
        self._state.handle_link_metric_change(linkmsg)


class DualState(object):
    pass


class StatePassive(DualState):
    def handle_update(self, update):
        # IE2 and IE4, for update pkts.
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
        pass

    def handle_reply(self, reply):
        pass

    def handle_query(self, neighbor, query):
        # IE1 and IE3
        #
        # If query came from successor:
        #    If we have a feasible successor:
        #        # XXX
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
        pass

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
        #            Endif
        #        Endif
        pass

    def handle_link_metric_change(self, linkmsg):
        # XXX Would be handled similarly to handle_link_down
        pass


class BaseActive(DualState):

    def __init__(self, *args, **kwargs):
        DualState.__init__(self, *args, **kwargs)
        self._received_last_reply = received_last_reply

    def _received_last_reply(self):
        """Must override in subclass.
        This function is called when we have received
        all replies and thus should transition back to passive. This function
        should handle responding to the old successor if necessary then
        sending the correct input event to transition back to passive."""
        assert(False)

    def handle_update(self, update):
        # If update indicates a metric change:
        #     IE7. Record the metric information.
        # Endif

    def handle_reply(self, reply):
        # IE8 for REPLYs. Clear REPLY flag for this neighbor.
        # If all neighbors have replied:
        #    IE13/14/15/16. Call self._received_last_reply
        # Endif
        pass

    def handle_query(self, query, neighbor):
        # If sender is the successor:
        #     # XXX This can happen in Active0 or Active1 (it's IE5). Should
        #     # pass in another handler function like _received_last_reply
        #     # that other states can use to act here. Active2 and 3 should
        #     # log/ignore it, Active0 and 1 should call IE5 (and also do
        #     # something?).
        # Else:
        #     # Sender is not the successor
        #     IE6. Send a REPLY. # Record the cost that I send... where and why?
        # Endif

    def handle_link_metric_change(self, linkmsg):
        pass


class StateActive1(BaseActive):

    # We can have IEs: 5,6,7,8,9,15

    def _received_last_reply(self):
        # If link to old successor still exists:
        #     Send reply to old successor.
        # Endif
        # IE15. Transition to passive.
        pass

    def handle_link_down(self, linkmsg):
        # The relevant link has already failed in Active3 or Passive in order
        # to get to Active2, so it can't fail again.
        # (What about if link is flapping, i.e. goes down and then back up and
        # down again?)
        pass

class StateActive2(BaseActive):

    # We can have IEs: 6,7,8,12,16

    def _received_last_reply(self):
        # If there is a feasible successor:
        #     IE16. Transition to passive.
        # Else:
        #     IE12. Transition to Active3.
        # Endif
        pass

    def handle_link_down(self, linkmsg):
        # The relevant link has already failed in Active3 or Passive in order
        # to get to Active2, so it can't fail again.
        # (What about if link is flapping, i.e. goes down and then back up and
        # down again?)
        pass


class StateActive2(BaseActive):

    # We can have IEs: 6,7,8,12,16

    def _received_last_reply(self):
        # If there is a feasible successor:
        #     IE16. Transition to passive.
        # Else:
        #     IE12. Transition to Active3.
        # Endif
        pass

    def handle_link_down(self, linkmsg):
        # The relevant link has already failed in Active3 or Passive in order
        # to get to Active2, so it can't fail again.
        # (What about if link is flapping, i.e. goes down and then back up and
        # down again?)
        pass


class StateActive3(BaseActive):

    # We can have IEs: 6,7,8,10,13

    def _received_last_reply(self):
        # Send reply to old successor
        # IE13. Transition to passive
        pass

    def handle_link_down(self, linkmsg):
        # For all neighbors attached to this interface:
        #     If neighbor is successor:
        #         IE10. Clear QUERY origin flag
        #         IE10. Set TRANSITION flag. (See below.)
        #     Else:
        #         # Neighbor not successor:
        #         IE8. Clear neighbor REPLY flag.
        #     Endif
        # Endfor
        #
        # XXX IE10 and IE13 can happen simultaneously, i.e. a link goes down
        # and that means we've received all replies from all neighbors.
        # Do we go to Active2 or Passive state?
        #
        # If TRANSITION flag was set above:
        #     IE10. Transition to Active2 state
        # Endif
        #
        # If all neighbors have replied:
        #    IE13. Send a REPLY to the old successor
        #    IE13. Transition to Passive state
        # Endif
        pass
