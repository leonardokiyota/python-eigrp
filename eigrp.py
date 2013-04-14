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

    DEFAULT_K_VALUES = [ 1, 74, 1, 0, 0, 0 ]
    DEFAULT_HT_MULTIPLIER = 3

    def __init__(self, rid, asn, routes, import_routes, interfaces, log_config,
                 admin_port, kvalues=None, hdrver=2, hello_interval=5):
        """An EIGRP implementation based on Cisco's draft informational RFC
        located here:

        http://www.ietf.org/id/draft-savage-eigrp-00.txt

        rid -- The router ID to use
        asn -- The autonomous system number
        routes -- Iterable of routes to import
        import_routes -- Import routes from the kernel (True or False)
        interfaces -- Iterable of IP addresses to send from
        log_config -- Configuration filename
        admin_port -- The TCP port to bind to the administrative interface
                      (not implemented)
        kvalues -- Iterable of K-value weights. Indexes are mapped to K1
                    through K6 (index 0 -> K1). If None, use defaults.
        hdrver -- Version of the RTP header to use. Only 2 is supported.
        hello_interval -- The hello interval. Also influences holdtime.
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
        self._ht_multiplier = self.DEFAULT_HT_MULTIPLIER

        # Holdtime must fit in a 16 bit field, so the hello interval could
        # in theory be set to a max of 65535/HT_MULTIPLIER. Since this is
        # measured in seconds, in reality it will be set much shorter.
        max_hello_interval = 65535 / self._ht_multiplier
        if not (1 <= hello_interval <= max_hello_interval):
            raise(ValueError("hello_interval must be between 1 and %d" % \
                             max_hello_interval))

        self._hello_interval = hello_interval
        self._holdtime = self._hello_interval * self._ht_multiplier

        if not len(kvalues) == 6:
            raise(ValueError("Exactly 6 K-values must be present."))
        try:
            for k in kvalues:
                if not (0 <= k <= 255):
                    raise(ValueError("Each kvalue must be between 0 and 255."))
        except TypeError:
            raise(TypeError("kvalues must be an iterable."))
            if not sum(kvalues):
                raise(ValueError("At least one kvalue must be non-zero."))
        self._kvalues = kvalues

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
        reactor.callWhenRunning(self._send_periodic_hello)
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

    def _send_periodic_hello(self):
        reactor.callLater(self._hello_timer, self._send_periodic_hello)

    def _register_op_handlers(self):
        self._op_handlers = dict()
        self._op_handlers[self._rtphdr.OPC_UPDATE] = self._eigrp_op_handler_update
        self._op_handlers[self._rtphdr.OPC_REQUEST] = self._eigrp_op_handler_request
        self._op_handlers[self._rtphdr.OPC_QUERY] = self._eigrp_op_handler_query
        self._op_handlers[self._rtphdr.OPC_REPLY] = self._eigrp_op_handler_reply
        self._op_handlers[self._rtphdr.OPC_HELLO] = self._eigrp_op_handler_hello
        self._op_handlers[self._rtphdr.OPC_SIAQUERY] = self._eigrp_op_handler_siaquery
        self._op_handlers[self._rtphdr.OPC_SIAREPLY] = self._eigrp_op_handler_siareply

    def _eigrp_op_handler_update(self, addr, hdr, data):
        self.log.debug("Processing UPDATE")

    def _eigrp_op_handler_request(self, addr, hdr, data):
        self.log.debug("Processing REQUEST")

    def _eigrp_op_handler_query(self, addr, hdr, data):
        self.log.debug("Processing QUERY")

    def _eigrp_op_handler_reply(self, addr, hdr, data):
        self.log.debug("Processing REPLY")

    def _eigrp_op_handler_hello(self, addr, hdr, data):
        self.log.debug("Processing HELLO")

    def _eigrp_op_handler_siaquery(self, addr, hdr, data):
        self.log.debug("Processing SIAQUERY")

    def _eigrp_op_handler_siareply(self, addr, hdr, data):
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


class EIGRPFieldFactory(object):
    """Factory for EIGRP TLV fields."""

    def build(self, raw):
        """Returns the TLV parsed from the raw data."""
        try:
            _proto, _type, _len = struct.unpack(EIGRPField.BASE_FORMAT,
                                               raw[:EIGRPField.BASE_FORMATLEN])
            if _type == EIGRPFieldParam.TYPE:
                return EIGRPFieldParam(raw=raw[EIGRPField.BASE_FORMATLEN:])
            elif _type == EIGRPFieldAuth.TYPE:
                return EIGRPFieldAuth(raw=raw[EIGRPField.BASE_FORMATLEN:])
            elif _type == EIGRPFieldSeq.TYPE:
                return EIGRPFieldSeq(raw=raw[EIGRPField.BASE_FORMATLEN:])
            elif _type == EIGRPFieldSwVersion.TYPE:
                return EIGRPFieldSwVersion(raw=raw[EIGRPField.BASE_FORMATLEN:])
            elif _type == EIGRPFieldMulticastSeq.TYPE:
                return EIGRPFieldMulticastSeq(raw=raw[EIGRPField.BASE_FORMATLEN:])
            elif _type == EIGRPFieldPeerInfo.TYPE:
                return EIGRPFieldPeerInfo(raw=raw[EIGRPField.BASE_FORMATLEN:])
            elif _type == EIGRPFieldPeerTerm.TYPE:
                return EIGRPFieldPeerTerm(raw=raw[EIGRPField.BASE_FORMATLEN:])
            else:
                raise(ValueError("Unknown value in TLV: %d" % _type))
        except struct.error:
            raise(FormatException("Unpacking failed (malformed TLV?)."))


class EIGRPField(object):
    """Base class for EIGRP Fields (TLVs)."""

    PROTO_IP4 = 1
    PROTO_IP6 = 4

    BASE_FORMAT    = "BBH"
    BASE_FORMATLEN = struct.calcsize(BASE_FORMAT)

    def __init__(self, proto=None):
        if proto == None:
            self._proto = self.PROTO_IP4
        if proto != self.PROTO_IP4:
            raise(ValueError("Only PROTO_IP4 is supported."))
        self._proto = proto


class EIGRPFieldParam(EIGRPField):
    """Parameter type TLV"""

    TYPE = 1

    FORMAT = "BBBBBBH"
    FORMATLEN = struct.calcsize(FORMAT)

    def __init__(self, raw=None, k1=None, k2=None, k3=None, k4=None, k5=None,
                 k6=None, holdtime=None, *args, **kwargs):
        super(EIGRPField, self).__thisclass__.__init__(self, *args, **kwargs)
        if raw and \
           not (k1 != None or \
                k2 != None or \
                k3 != None or \
                k4 != None or \
                k5 != None or \
                k6 != None or \
                holdtime):
            self._k1, self._k2, self._k3, self._k4, self._k5, self._k6, \
                      self._holdtime = self.unpack(raw)
        elif not raw and \
             (k1 != None and \
              k2 != None and \
              k3 != None and \
              k4 != None and \
              k5 != None and \
              k6 != None and \
              holdtime):
            self._k1 = k1
            self._k2 = k2
            self._k3 = k3
            self._k4 = k4
            self._k5 = k5
            self._k6 = k6
            self._holdtime = holdtime
            self._type = self.TYPE_PARAM
            self._len = self.FORMATLEN
        else:
            raise(ValueError("Either raw or all other values are required, not"
                             " both."))

    def pack(self):
        return struct.pack(self.BASE_FORMAT + self.FORMAT, self._proto,
                           self._type, self._len, self._k1, self._k2,
                           self._k3,self._k4, self._k5, self._k6,
                           self._holdtime)

    def unpack(self, raw):
        return struct.unpack(self.FORMAT, raw)


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

    FLAG_INIT = 1
    FLAG_CR   = 2

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
