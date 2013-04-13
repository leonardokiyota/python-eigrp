#!/usr/bin/env python

import sys
import optparse
import logging
import logging.config
import functools
import struct
from twisted.internet import reactor
from twisted.internet import protocol
from twisted.python import log

import tw_baseiptransport
import sysiface
import util

class EIGRP(protocol.DatagramProtocol):
    def __init__(self, rid, asn, routes, import_routes, interfaces, log_config,
                 admin_port):
        """An EIGRP implementation based on Cisco's draft informational RFC
        located here:

        http://www.ietf.org/id/draft-savage-eigrp-00.txt

        rid -- The router ID to use
        asn -- The autonomous system number
        """
        input_err_msg = "%s must be a positive number less than 65536."
        if not isinstance(rid, int):
            raise(TypeError(input_err_msg % "Router ID"))
        if not (0 <= rid < 65536):
            raise(ValueError(input_err_msg % "Router ID"))
        if not isinstance(asn, int):
            raise(TypeError(input_err_msg % "AS Number"))
        if not (0 <= asn < 65536):
            raise(ValueError(input_err_msg % "AS Number"))
        self._rid = rid
        self._asn = asn
        self._hdrver = 2

        self._init_logging(log_config)
        #eigrpadmin.run(self, port=admin_port)

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

    def run(self):
        reactor.listenIP(reactor, 88, self)
        reactor.run()

    def startProtocol(self):
        pass

    def datagramReceived(self, data, addr_and_zero):
        addr = addr_and_zero[0]
        try:
            hdr = RTPHeader(data[:RTPHeader.HEADERLEN])
        except struct.error:
            pass
        print "Received datagram from %s" % addr


class RTPHeader(object):
    """Reliable Transport Protocol Header."""

    FORMAT = "BBHIIIHH"
    HEADERLEN = struct.calcsize(FORMAT)

    def __init__(self, raw=None, hdrver=None, opcode=None, flags=None,
                 seq=None, ack=None, rid=None, asn=None):
        if raw and \
           hdrver == None and \
           opcode == None and \
           flags  == None and \
           seq    == None and \
           ack    == None and \
           rid    == None and \
           asn    == None:
            self.unpack(raw)
        elif not raw and \
             hdrver != None and \
             opcode != None and \
             flags  != None and \
             seq    != None and \
             ack    != None and \
             rid    != None and \
             asn    != None:
            self._hdrver = hdrver
            self._opcode = opcode
            self._flags = flags
            self._seq = seq
            self._ack = ack
            self._rid = rid
            self._asn = asn
        else:
            raise(ValueError("Either 'raw' is required, or all other arguments"
                             " are required."))

    def unpack(self, raw):
        self._raw, self._hdrver, self._opcode, self._flags, self._seq, \
             self._ack, self._rid, self._asn = struct.unpack(self.FORMAT, raw)

    def pack(self):
        return struct.pack(self.FORMAT, self._hdrver, self._opcode,
                           self._flags, self._seq, self._ack, self._rid,
                           self._asn)

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
#    op.add_option("-t", "--base-timer", type="int",
#                  help="Use non-default update/gc/timeout timers. The update "
#                  "timer is set to this value and gc/timeout timers are based "
#                  "on it")
    options, arguments = op.parse_args(argv)
    if not options.interface:
        op.error("At least one interface IP is required (-i).")
    if len(arguments) > 1:
        op.error("Unexpected non-option argument(s): '" + \
                 " ".join(arguments[1:]) + "'")

    return options, arguments

def main(argv):
    options, arguments = parse_args(argv)
    eigrpserv = EIGRP(options.router_id, options.as_number, options.route, options.import_routes, options.interface, options.log_config, options.admin_port)
    eigrpserv.run()

if __name__ == "__main__":
    main(sys.argv)
