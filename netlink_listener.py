#!/usr/bin/env python

"""Minimal netlink route protocol and route attribute processing for Twisted.
Main purpose is to processing link up/down messages through Twisted."""

import struct
from twisted.internet import protocol

import tw_baseiptransport
from tw_baseiptransport import reactor

RTMGRP_LINK     = 1
RTMGRP_NOTIFY   = 2
RTMGRP_NEIGH    = 4
RTMGRP_TC       = 8

RTMGRP_IPV4_IFADDR  = 0x10
RTMGRP_IPV4_MROUTE  = 0x20
RTMGRP_IPV4_ROUTE   = 0x40
RTMGRP_IPV4_RULE    = 0x80

RTMGRP_IPV6_IFADDR  = 0x100
RTMGRP_IPV6_MROUTE  = 0x200
RTMGRP_IPV6_ROUTE   = 0x400
RTMGRP_IPV6_IFINFO  = 0x800

# from linux/if_addr.h

IFA_UNSPEC    = 0
IFA_ADDRESS   = 1
IFA_LOCAL     = 2
IFA_LABEL     = 3
IFA_BROADCAST = 4
IFA_ANYCAST   = 5
IFA_CACHEINFO = 6
IFA_MULTICAST = 7

# from linux/if_link.h
IFLA_UNSPEC      = 0
IFLA_ADDRESS     = 1
IFLA_BROADCAST   = 2
IFLA_IFNAME      = 3
IFLA_MTU         = 4
IFLA_LINK        = 5
IFLA_QDISC       = 6
IFLA_STATS       = 7
IFLA_COST        = 8
IFLA_PRIORITY    = 9
IFLA_MASTER      = 10
IFLA_WIRELESS    = 11
IFLA_PROTINFO    = 12
IFLA_TXQLEN      = 13
IFLA_MAP         = 14
IFLA_WEIGHT      = 15
IFLA_OPERSTATE   = 16
IFLA_LINKMODE    = 17
IFLA_LINKINFO    = 18
IFLA_NET_NS_PID  = 19
IFLA_IFALIAS     = 20
IFLA_NUM_VF      = 21
IFLA_VFINFO_LIST = 22
IFLA_STATS64     = 23
IFLA_VF_PORTS    = 24
IFLA_PORT_SELF   = 25
IFLA_AF_SPEC     = 26
IFLA_GROUP       = 27
IFLA_NET_NS_FD   = 28
IFLA_EXT_MASK    = 29
IFLA_MAX         = 30

class RtAttrBase(object):
    def __init__(self):
        self.fields = dict()

    def __str__(self):
        s = "type: {}, fields: ".format(self.TYPENAME)
        for k, v in self.fields.items():
            s += "{}={}, ".format(k, v)
        s.rstrip(", ")
        return s


class RtAttrIFLAIfname(RtAttrBase):

    TYPE         = 3
    TYPENAME     = "Interface name"
    FIELDS_DESC  = [ 'ifname' ]

    def __init__(self, data, *args, **kwargs):
        RtAttrBase.__init__(self, *args, **kwargs)
        self.fields['ifname'] = str(data)


class RtAttrIFLAOperState(RtAttrBase):

    TYPE        = 16
    TYPENAME    = "Operational state"
    FIELDSDESC  = [ 'state' ]

    # See: https://www.kernel.org/doc/Documentation/networking/operstates.txt
    OPER_UNKNOWN         = 0
    OPER_NOTPRESENT      = 1
    OPER_DOWN            = 2
    OPER_LOWERLAYERDOWN  = 3
    OPER_TESTING         = 4
    OPER_DORMANT         = 5
    OPER_UP              = 6

    _OPER_MIN = 0
    _OPER_MAX = 6

    def __init__(self, data, *args, **kwargs):
        RtAttrBase.__init__(self, *args, **kwargs)
        self.fields['state'] = struct.unpack("B", data)[0]
        if not self._OPER_MIN < self.fields['state'] < self._OPER_MAX:
            raise ValueError("Operational state out of range: "
                             "{}".format(self.fields['state']))


class RtAttrCreationError(Exception):
    pass


class RtAttrFactory(object):
    def __init__(self, use_default_rtattrs=True, extra_rtattr_classes=None):
        """If use_default_rtattrs is True, factory will register a list of
        all currently defined rtattrs.
        Any extra rtattr classes in extra_rtattr_classes will also be
        registered."""
        self._rtattrs = dict()

        if use_default_rtattrs:
            self.register_rtattrs([RtAttrIFLAOperState,
                                   RtAttrIFLAIfname,
                                  ])

        if extra_rtattr_classes:
            self.register_rtattrs(extra_rtattr_classes)

    def register_rtattrs(self, rtattr_classes):
        for cls in rtattr_classes:
            if cls.TYPE in self._rtattrs:
                raise ValueError("RtAttr type {} already "
                                 "registered.".format(cls.TYPE))
            self._rtattrs[cls.TYPE] = cls

    def create(self, attrtype, attrdata):
        try:
            cls = self._rtattrs[attrtype]
        except KeyError:
            raise RtAttrCreationError("No rtattr registered for type "
                                      "{}".format(attrtype))

        return cls(attrdata)


class NetlinkRouteProtocol(protocol.DatagramProtocol):

    NLMSGHDR_FMT    = "IHHII"
    IFINFOMSG_FMT   = "BHiII"
    RTATTR_HDR_FMT  = "HH"

    NLMSGHDR_SIZE          = struct.calcsize(NLMSGHDR_FMT)
    IFINFOMSG_SIZE         = struct.calcsize(IFINFOMSG_FMT)
    RTATTR_HDR_SIZE        = struct.calcsize(RTATTR_HDR_FMT)
    IFINFOMSG_START_OFFSET = NLMSGHDR_SIZE
    RTATTR_START_OFFSET    = NLMSGHDR_SIZE + IFINFOMSG_SIZE

    def __init__(self):
        self._rtattr_factory = RtAttrFactory()

    def datagramReceived(self, data, addr_and_port):
        addr = addr_and_port[0]
        port = addr_and_port[1]

        if port == RTMGRP_LINK:
            self._handle_link_message(data)
        else:
            raise ValueError("Unknown RT management group/port: "
                             "{}".format(port))

    def _handle_link_message(self, data):
        """Override in subclass to take action based on parsed rtattrs."""
        self._parse_link_message(data)

    def _parse_link_message(self, data):
        """Parses a link message and returns any supported route attributes
        from it."""
        # See rtnetlink(7) for format details.
        # This consists of an ifinfomsg followed by a series of route
        # attributes (rtattrs). Each route attribute is 4-byte aligned.
        nlmsghdr = struct.unpack_from(self.NLMSGHDR_FMT, data, offset=0)
        ifinfomsg = struct.unpack_from(self.IFINFOMSG_FMT, data, offset=self.IFINFOMSG_START_OFFSET)
        offset = self.RTATTR_START_OFFSET
        rtattrs = list()
        while True:
            try:
                attrlen = int(struct.unpack_from("H", data, offset=offset)[0])
                offset += 2
            except struct.error:
                break

            # Each attribute is 4-byte aligned. Determine pad length.
            padlen = (4 - (attrlen % 4)) % 4

            attrtype = int(struct.unpack_from("H", data, offset=offset)[0])
            offset += 2

            # Unpack the attribute's data, minus the 2-byte 'type' and 'length'
            # fields which were already unpacked.
            attrdata = data[offset:offset+attrlen-4]
            offset += attrlen - 4

            # Skip the pad.
            offset += padlen

            try:
                rtattrs.append(self._rtattr_factory.create(attrtype, attrdata))
            except RtAttrCreationError:
                # Skip attrs that we don't care about.
                continue
        return rtattrs


class LinuxIfaceEventListener(NetlinkRouteProtocol):

    """Handles interface events. Right now only handles if a link's
    operational state changes to up or not up."""

    def __init__(self, link_up_cb, link_down_cb, *args, **kwargs):
        """When a message is received that a link is either up or down,
        the interface name will be passed to the appropriate callback
        function."""
        NetlinkRouteProtocol.__init__(self, *args, **kwargs)
        reactor.listenNetlink(port=RTMGRP_LINK,
                              protocol=self,
                              netlinkType=tw_baseiptransport.NetlinkPort.NETLINK_ROUTE)
        self._link_up = link_up_cb
        self._link_down = link_down_cb

    def _handle_link_message(self, data):
        linkname = None
        cb = None

        # Iterate through the route attributes until we find the link name
        # and we determine if the link went up or down. If we don't see both,
        # do nothing. Ignore other route attributes.
        for rtattr in self._parse_link_message(data):
            if rtattr.TYPE == RtAttrIFLAOperState.TYPE:
                if rtattr.fields['state'] == RtAttrIFLAOperState.OPER_UP:
                    cb = self._link_up
                else:
                    cb = self._link_down
                if linkname:
                    cb(linkname)
            elif rtattr.TYPE == RtAttrIFLAIfname.TYPE:
                linkname = rtattr.fields['ifname']
                if cb:
                    cb(linkname)


# Example usage...
class SomeClass(object):
    def __init__(self):
        self._iface_event_listener = LinuxIfaceEventListener(self.link_up, self.link_down)

    def link_up(self, name):
        print "Link up: " + name

    def link_down(self, name):
        print "Link down: " + name


def main():
    example_cls = SomeClass()
    reactor.run()

if __name__ == "__main__":
    main()
