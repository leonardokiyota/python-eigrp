"""This modifies some of the rtp classes to call 'before' and 'after'
functions for each function, if defined. This is used to test some of the
functionality in RTP that is not easily tested otherwise."""

import inspect
import sys
sys.path.append("..")

import rtp
import sysiface

class ControlledRTP(rtp.ReliableTransportProtocol):
    def before_ReliableTransportProtocol__send_explicit_ack(self, neighbor):
        pass

    def after_ReliableTransportProtocol__send_explicit_ack(self, neighbor):
        pass


class HookedFunction(object):

    """A function that has a before and after call."""

    def __init__(self, real, before, after):
        self.real = real
        self.before = before
        self.after = after

    def __call__(self, *args, **kwargs):
        self.before(*args, **kwargs)
        self.real(*args, **kwargs)
        self.after(*args, **kwargs)


def make_hooks(cls):
    """If there is a 'before' or 'after' function defined for a function in
    the given class, then call the before function first, then the real
    function, and lastly the after function."""
    for objname, obj in inspect.getmembers(cls):
        if not inspect.isroutine(obj):
            continue

        try:
            before_func = getattr(cls, "before" + objname)
        except AttributeError:
            before_func = None
        try:
            after_func = getattr(cls, "after" + objname)
        except AttributeError:
            after_func = None

        # If neither before or after functions are given, skip.
        if not before_func and \
           not after_func:
            continue

        # If only one function is used, make a stub function for the other.
        if not before_func:
            before_func = lambda: None
        if not after_func:
            after_func = lambda: None

        # Set the original real function to use the hooked function
        setattr(cls, objname, HookedFunction(obj, before_func, after_func))

if __name__ == "__main__":
    system = sysiface.SystemFactory(0, 0).build()
    controlled_rtp = ControlledRTP(system, "../logging.conf")
    make_hooks(controlled_rtp)
