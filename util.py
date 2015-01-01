#!/usr/bin/env python

import sys
import logging
import os
import ctypes
import functools
from twisted.internet import error
from twisted.python import log

def create_new_log_level(level, name):
    """Add a custom log level. See my comment here:
    http://stackoverflow.com/questions/2183233/how-to-add-a-custom-loglevel-to-pythons-logging-facility
    Raise ValueError if the log level name already exists. Don't raise
    if the level value already exists, because that could be useful for
    aliases.
    """
    # We don't use 'getLevelName' to determine if the name is claimed because
    # it won't reliably indicate if a level name is not defined. For example
    # if no name is associated with level 11, getLevelName will return the
    # string "Level 11".
    # It's possible (but silly) to use logging.addLevelName(11, "Level 11"),
    # in which case it's not possible to determine if the name "Level 11"
    # is already claimed or not. So use getattr instead.
    try:
        getattr(logging.Logger, name.lower())
    except AttributeError:
        pass
    else:
        raise(ValueError("Logging level name {} already "
                         "exists.".format(name.lower())))

    def newlog(self, msg, level=level, *args, **kwargs):
        if self.isEnabledFor(level):
            self._log(level, msg, args, **kwargs)
    logging.addLevelName(level, name)
    setattr(logging.Logger, name.lower(), newlog)

def create_extended_debug_log_levels():
    """Create extended debug levels. Currently using these levels in RIPv2,
    RTP, and (future) EIGRP."""
    for level, name in [(10, "DEBUG1"),
                        ( 9, "DEBUG2"),
                        ( 8, "DEBUG3"),
                        ( 7, "DEBUG4"),
                        ( 6, "DEBUG5")]:
        create_new_log_level(level, name)

def is_admin():
    """Cross-platform method of checking for root/admin privs. Works on Linux
    and Windows, haven't tried mac. See:
    http://stackoverflow.com/questions/1026431/crossplatform-way-to-check-admin-rights-in-python-script
    """
    admin = False
    try:
        admin = os.getuid() == 0
    except AttributeError:
        try:
            admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except AttributeError:
            sys.stderr.write("Unable to check if you are running as a \n"
                             "privileged user. You may be using an \n"
                             "unsupported OS.")
            return False
    return admin

def suppress_reactor_not_running(logfunc=None):
    """Install a Twisted log observer that will remove
    "twisted.internet.error.ReactorNotRunning" errors during shutdown.
    See util._suppress_reactor_not_running for more information.

    logfunc -- a function to be called instead when this behavior occurs.
               Should accept one argument that describes the problem."""
    suppressfunc = functools.partial(_suppress_reactor_not_running,
                                     logfunc=logfunc)
    log.addObserver(suppressfunc)

def _suppress_reactor_not_running(msg, logfunc):
    # reactor apparently calls reactor.stop() more than once when shutting
    # down under certain circumstances, like when a signal goes uncaught
    # (e.g. CTRL+C). It only does this sometimes. It prints a stacktrace
    # to the console. I see several old (now-fixed) bug reports relating
    # to this and some stackexchange threads discussing how to suppress
    # these kinds of messages, but nothing that tells me how to get this
    # to stop happening "the right way". Since I never call reactor.stop
    # it seems like this is twisted's problem. This is kludgey but it
    # works, and it shouldn't block any useful messages from being printed.
    if not msg.has_key("isError") or \
       not msg.has_key("failure"):
        return
    if msg["isError"] and \
       msg["failure"].type == error.ReactorNotRunning:
        if logfunc:
            logfunc("Suppressing ReactorNotRunning error.")
        for k in msg:
            msg[k] = None
