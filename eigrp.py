#!/usr/bin/env python

import sys
import optparse
import logging
import logging.config
import functools
import struct
import binascii
from twisted.internet import reactor
from twisted.internet import protocol
from twisted.python import log
import ipaddr

import tw_baseiptransport
import sysiface
import util

class EIGRP(protocol.DatagramProtocol):
    def __init__(self, rid, asn, routes, import_routes, interfaces, log_config,
                 admin_port, hdrver=2):
        """An EIGRP implementation based on Cisco's draft informational RFC
        located here:

        http://www.ietf.org/id/draft-savage-eigrp-00.txt

        rid -- The router ID to use
        asn -- The autonomous system number
        """
        asn_rid_err_msg = "%s must be a positive number less than 65536."
        if not isinstance(rid, int):
            raise(TypeError(asn_rid_err_msg % "Router ID"))
        if not (0 <= rid < 65536):
            raise(ValueError(asn_rid_err_msg % "Router ID"))
        if not isinstance(asn, int):
            raise(TypeError(asn_rid_err_msg % "AS Number"))
        if not (0 <= asn < 65536):
            raise(ValueError(asn_rid_err_msg % "AS Number"))
        self._rid = rid
        self._asn = asn

        if hdrver == 2:
            self._rtphdr = RTPHeader2
        else:
            raise(ValueError("Unsupported header version: %d" % hdrver))

        self._init_logging(log_config)
        if sys.platform == "linux2":
            self._sys = sysiface.LinuxSystem(log_config=log_config)
        elif sys.platform == "win":
            self._sys = sysiface.WindowsSystem(log_config=log_config)
        else:
            raise(NotSupported("No support for current OS."))
        self._register_op_handlers()
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

    def _register_op_handlers(self):
        self._op_handlers = dict()
        self._op_handlers[self._rtphdr.OPC_UPDATE] = self._eigrp_packet_handler_update
        self._op_handlers[self._rtphdr.OPC_REQUEST] = self._eigrp_packet_handler_request
        self._op_handlers[self._rtphdr.OPC_QUERY] = self._eigrp_packet_handler_query
        self._op_handlers[self._rtphdr.OPC_REPLY] = self._eigrp_packet_handler_reply
        self._op_handlers[self._rtphdr.OPC_HELLO] = self._eigrp_packet_handler_hello
        self._op_handlers[self._rtphdr.OPC_SIAQUERY] = self._eigrp_packet_handler_siaquery
        self._op_handlers[self._rtphdr.OPC_SIAREPLY] = self._eigrp_packet_handler_siareply

    def _eigrp_packet_handler_update(self, addr, hdr, data):
        self.log.debug("Processing UPDATE")

    def _eigrp_packet_handler_request(self, addr, hdr, data):
        self.log.debug("Processing REQUEST")

    def _eigrp_packet_handler_query(self, addr, hdr, data):
        self.log.debug("Processing QUERY")

    def _eigrp_packet_handler_reply(self, addr, hdr, data):
        self.log.debug("Processing REPLY")

    def _eigrp_packet_handler_hello(self, addr, hdr, data):
        self.log.debug("Processing HELLO")

    def _eigrp_packet_handler_siaquery(self, addr, hdr, data):
        self.log.debug("Processing SIAQUERY")

    def _eigrp_packet_handler_siareply(self, addr, hdr, data):
        self.log.debug("Processing SIAREPLY")

    def run(self):
        reactor.listenIP(reactor, 88, self)
        self.log.info("EIGRP is starting up...")
        reactor.run()

    def _cleanup(self):
        # XXX Add cleanup for routes when we have any to remove
        self.log.info("Cleaning up.")
        self._sys.cleanup()

    def startProtocol(self):
        pass

    def stopProtocol(self):
        self.log.info("EIGRP is shutting down.")
        self._cleanup()

    def datagramReceived(self, data, addr_and_zero):
        addr = addr_and_zero[0]
        host_local = False
        addr = ipaddr.IPv4Address(addr)
        for local_iface in self._sys.logical_ifaces:
            if local_iface.ip.ip.exploded == addr.exploded:
                host_local = True
                break
        if host_local:
            self.log.debug5("Ignoring message from local system.")
            return

        self.log.debug("Received datagram from %s" % addr)
        try:
            hdr = self._rtphdr(data[:self._rtphdr.HEADERLEN])
        except struct.error:
            bytes_to_print = self._rtphdr.HEADERLEN
            self.log.warn("Received malformed datagram from %s. Hexdump of "
                          "first %d bytes: %s" % (addr, bytes_to_print, \
                          binascii.hexlify(data[:bytes_to_print])))
            return
        if hdr.hdrver != self._rtphdr.VER:
            self.log.warn("Received incompatible header version %d from "
                          "host %s" % (hdr.hdrver, addr))
            return

        # XXX RTP, ND/NR processing here

        payload = data[self._rtphdr.HEADERLEN:]
        try:
            handler = self._op_handlers[hdr.opcode]
        except KeyError:
            self.log.info("Received invalid/unhandled opcode %d from %s" % \
                          (hdr.opcode, addr))
            return
        handler(addr, hdr, payload)


class EIGRPException(Exception):
    def __init__(self, msg=""):
       self.msg = msg


class NotSupported(EIGRPException):
    def __init__(self, *args, **kwargs):
        super(EIGRPException, self).__thisclass__.__init__(self, *args, **kwargs)

class StubFields(object):
    """Stub class to test checksum calculation"""
    def pack(self):
        return "hi"


class RTPPacket(object):
    def __init__(self, hdr, fields):
        self.hdr = hdr
        self.fields = fields

    def pack(self):
        self.hdr.chksum = 0
        prehdr = self.hdr.pack()
        fields = self.fields.pack()
        self.hdr.chksum = self.calc_chksum(prehdr, fields)
        hdr = self.hdr.pack()
        return hdr + fields

    # Checksum related functions are from:
    # http://stackoverflow.com/questions/1767910/checksum-udp-calculation-python
    @staticmethod
    def calc_chksum(prehdr, fields):
        """Get one's complement of the one's complement sum. Covers header
        fields and the TLVs.
        prehdr should be the packed header, with checksum set to 0
        fields should be the packed TLV fields (not in a list)
        Returns the 16 bit checksum.
        """
        data = prehdr + fields
        data = map(lambda x: ord(x), data)
        data = struct.pack("%dB" % len(data), *data)
        s = 0
        for i in range(0, len(data), 2):
            w = ord(data[i]) + (ord(data[i+1]) << 8)
            s = RTPPacket.carry_around_add(s, w)
        return ~s & 0xffff

    @staticmethod
    def carry_around_add(a, b):
        c = a + b
        return (c & 0xffff) + (c >> 16)


class RTPHeader2(object):
    """Reliable Transport Protocol Header (header version 2)."""

    FORMAT = "BBHIIIHH"
    HEADERLEN = struct.calcsize(FORMAT)
    VER = 2

    OPC_UPDATE   = 1
    OPC_REQUEST  = 2
    OPC_QUERY    = 3  # Should this be 4? RFC says 4 but might be a typo.
    OPC_REPLY    = 4
    OPC_HELLO    = 5
    OPC_PROBE    = 7
    OPC_SIAQUERY = 10
    OPC_SIAREPLY = 11

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
            self.hdrver = hdrver
            self.opcode = opcode
            self.flags = flags
            self.seq = seq
            self.ack = ack
            self.rid = rid
            self.asn = asn
            self.chksum = 0
        else:
            raise(ValueError("Either 'raw' is required, or all other arguments"
                             " are required."))

    def unpack(self, raw):
        self.hdrver, self.opcode, self.chksum, self.flags, self.seq, \
             self.ack, self.rid, self.asn = struct.unpack(self.FORMAT, raw)

    def pack(self):
        return struct.pack(self.FORMAT, self.hdrver, self.opcode, self.chksum,
                           self.flags, self.seq, self.ack, self.rid,
                           self.asn)

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
