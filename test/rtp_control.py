"""This modifies some of the rtp classes to call 'before' and 'after'
functions for each function, if defined. This is used to test some of the
functionality in RTP that is not easily tested otherwise."""

import inspect
import sys
sys.path.append("..")

import rtp
import sysiface

class ExampleControlledRTP(rtp.ReliableTransportProtocol):

    """Example RTP class with hooked functions."""

    def before_ReliableTransportProtocol__send_explicit_ack(self, neighbor):
        pass


class HookedFunction(object):

    """A function that has one function called before it, and another called
    after it."""

    def __init__(self, real, before, after):
        """Call order goes: before, real, after.
        If 'before' returns True, then 'real' and 'after' are not called."""
        self.real = real
        self.before = before
        self.after = after

    def __call__(self, *args, **kwargs):
        if self.before(*args, **kwargs):
            return
        self.real(*args, **kwargs)
        self.after(*args, **kwargs)


def NoOpFunction(*args, **kwargs):
    """A function that accepts any arguments and returns immediately."""
    pass


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
            before_func = NoOpFunction
        if not after_func:
            after_func = NoOpFunction

        # Set the original real function to use the hooked function
        setattr(cls, objname, HookedFunction(obj, before_func, after_func))

if __name__ == "__main__":
    system = sysiface.SystemFactory(0, 0).build()
    controlled_rtp = ExampleControlledRTP(system, "../logging.conf")
    make_hooks(controlled_rtp)
    controlled_rtp._ReliableTransportProtocol__send_explicit_ack(None)
