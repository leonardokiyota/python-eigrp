#!/usr/bin/env python

"""Interface to the OS."""

# Copyright (C) 2012 Patrick F. Allen
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

import sys
import subprocess
import re

import ipaddr

# subprocess.check_output doesn't exist in 2.6, haven't looked at 3.x.
# Have done all testing on 2.7, so it's safer to just require 2.7 for now.
if not 0x2070000 <= sys.hexversion < 0x2080000:
    raise ImportError("sysiface module requires Python 2.7.")

class _System(object):
    """Abstract class for OS-specific functions. These are all the OS-specific
    methods that need to be overridden by a subclass in order to function on a
    different OS."""

    def __init__(self):
        self.loopback = "127.0.0.1"
        self.update_interface_info()
        self._rule_installed = False

    def init_routing(self):
        """Do anything related to starting routing on the system."""
        pass

    def modify_route(self, net, plen, metric, nexthop):
        """Update the metric and nexthop address to a prefix.
        net -- the IP network address (not including netmask)
        plen -- the prefix length
        metric -- the metric to use, as an integer
        nexthop -- the nexthop IP address
        """
        self.uninstall_route(net, plen)
        self.install_route(net, plen, metric, nexthop)

    def cleanup(self):
        """Clean up the system. Called when exiting.

        Override in subclass."""
        assert False

    def update_interface_info(self):
        """Updates self according to the current state of physical and logical
        IP interfaces on the device.

        Sets self.phy_ifaces and self.logical_ifaces to be lists of
        physical interfaces and logical interfaces, respectively. See
        PhysicalInterface and LogicalInterface classes for examples.

        Override in subclass."""
        assert False

    def uninstall_route(self, net, mask):
        """Uninstall a route from the system routing table.

        Override in subclass."""
        assert False

    def install_route(self, net, preflen, metric, nexthop):
        """Install a route in the system routing table.

        Override in subclass."""
        assert False

    def get_local_routes(self):
        """Retrieves routes from the system routing table.

        Return value is a list of (address, mask) tuples defining local routes.

        Override in subclass."""
        assert False

    def is_self(self, host):
        """Determines if an IP address belongs to the local machine.

        Returns True if so, otherwise returns False."""
        for iface in self.logical_ifaces:
            if host == iface.ip.ip.exploded:
                return True
        return False


class WindowsSystem(_System):
    """The Windows system interface."""

    # TODO Recently updated to handle non-string arguments. Needs testing.
    CMD_BASE = "route {}"
    OPTS_BASE = " {} mask {}"
    ROUTE_DEL = CMD_BASE.format("delete") + OPTS_BASE
    ROUTE_ADD = CMD_BASE.format("add")    + OPTS_BASE + " {} metric {}"

    def init_routing(self):
        # XXX This should also handle:
        # Check if ip routing is already enabled
        # If yes, do nothing
        # If no, enable it, and set a flag to disable routing again in cleanup
        pass

    def cleanup(self):
        pass

    def update_interface_info(self):
        ipconfig_output = subprocess.check_output("ipconfig")

        self.phy_ifaces = []
        self.logical_ifaces = []

        # XXX Extract actual physical interfaces... though these aren't really
        # used now anyway except for debug messages.
        self.phy_ifaces.append(PhysicalInterface("GenericWindowsPhy", None))
        masks = re.findall("Subnet Mask.*: (.*)\r", ipconfig_output)
        ips = re.findall("IPv4 Address.*: (.*)\r", ipconfig_output)
        assert len(ips) == len(masks)
        mapper = lambda ip, mask: ip + "/" + mask

        for net in map(mapper, ips, masks):
            self.logical_ifaces.append(LogicalInterface(self.phy_ifaces[0],
                                                        net))

    def uninstall_route(self, net, preflen):
        # Convert the prefix length into a dotted decimal mask
        mask = self.preflen_to_snmask(preflen)
        cmd = self.ROUTE_DEL.format(net, mask)
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        if not "OK!" in output:
            raise ValueError #ModifyRouteError("uninstall", output)

    def install_route(self, net, preflen, metric, nexthop):
        mask = self.preflen_to_snmask(preflen)
        cmd = self.ROUTE_ADD.format(net,
                                    mask,
                                    nexthop,
                                    metric)
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        if not "OK!" in output:
            raise ValueError #ModifyRouteError("uninstall", output)

    @staticmethod
    def preflen_to_snmask(preflen):
        return ipaddr.IPv4Network("0.0.0.0/%d" % preflen).netmask

    def get_local_routes(self):
        output = subprocess.check_output("route print",
                                         stderr=subprocess.STDOUT)
        routes = re.search("IPv4 Route Table.*?^ (.*?)=", output,
                           re.DOTALL | re.MULTILINE).group(1)
        for rtline in routes.splitlines():
            rtinfo = rtline.split()
            dst_network = rtinfo[0]
            mask = rtinfo[1]
            rt = ipaddr.IPv4Network(dst_network + "/" + mask)
            if rt.ip.is_loopback   or \
               rt.ip.is_link_local or \
               rt.ip.is_multicast  or \
               rt.ip.exploded == "255.255.255.255":
                continue
            yield (rt.ip.exploded, rt.netmask.exploded)


class LinuxSystem(_System):
    """The Linux system interface."""

    IP_CMD = "/sbin/ip"
    RT_DEL_ARGS = "route del {}/{}"
    RT_ADD_ARGS = "route add {}/{} via {} metric {} " \
                  "table {}"

    def __init__(self, table=52, priority=1000, *args, **kwargs):
        """Args:
        table -- the routing table to install routes to (if applicable on
            the current platform).
        priority -- the desirability of routes learned by the process
            relative to other routing daemons (if applicable on the current
            platform)"""
        super(_System, self).__thisclass__.__init__(self, *args, **kwargs)

        if not 0 < table < 255:
            raise ValueError
        if not 0 < priority < 32767:
            raise ValueError

        self._table = table
        self._priority = priority

    def init_routing(self):
        # XXX This should also handle:
        # Check if ip routing is already enabled
        # If yes, do nothing
        # If no, enable it, and set a flag to disable routing again in cleanup
        self._install_rule()

    def _install_rule(self):
        self._rule_installed = True
        cmd = [self.IP_CMD] + ("rule add priority %d table %d" % \
               (self._priority, self._table)).split()
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            raise ValueError #(ModifyRouteError("rule_install"))

    def _uninstall_rule(self):
        cmd = [self.IP_CMD] + ("rule del priority %d table %d" % \
               (self._priority, self._table)).split()
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            raise ValueError #(ModifyRouteError("rule_install"))

    def update_interface_info(self):
        """Updates self according to the current state of physical and logical
        IP interfaces on the device."""
        ip_output = subprocess.check_output("ip addr show".split())
        raw_ifaces = re.split("\n\d*: ", ip_output)

        # First interface does not start with a newline, so strip the interface
        # index.
        raw_ifaces[0] = raw_ifaces[0].lstrip("1: ")

        self.phy_ifaces = []
        self.logical_ifaces = []
        for iface in raw_ifaces:
            name = re.match("(.*):", iface).group(1)
            flags = re.search("<(\S*)> ", iface).group(1).split(",")
            phy_iface = PhysicalInterface(name, flags)
            self.phy_ifaces.append(phy_iface)
            for addr in re.findall("\n\s*inet (\S*)", iface):
                logical_iface = LogicalInterface(phy_iface, addr)
                self.logical_ifaces.append(logical_iface)

    def uninstall_route(self, net, preflen):
        cmd = [self.IP_CMD] + ("route del {}/{} table {}".format(net, preflen, self._table).split())
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            raise ValueError #ModifyRouteError("route_uninstall", output)

    def install_route(self, net, preflen, metric, nexthop):
        cmd = [self.IP_CMD] + ("route add {}/{} via {} metric {} table {}".format(net, preflen, nexthop, metric, self._table).split())
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            raise ValueError #ModifyRouteError("route_install", output)

    def get_local_routes(self):
        cmd = [self.IP_CMD] + "route show".split()
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            raise ValueError #ModifyRouteError("route_install", output)
        for route in output.splitlines():
            dst_network = route.split()[0]

            # Default route shows up as the word 'default'
            if dst_network == "default":
                dst_network = "0.0.0.0/0"
            parsed_network = ipaddr.IPv4Network(dst_network)
            yield (parsed_network.ip.exploded, parsed_network.netmask.exploded)

    def cleanup(self):
        """Perform any necessary system cleanup."""
        if self._rule_installed:
            self._uninstall_rule()


class PhysicalInterface(object):
    def __init__(self, name, flags):
        self.name = name
        self._flags = flags

    # TODO Retrieve actual interface info for stubs below.
    # Method will be different for Windows/Linux.
    def get_bandwidth(self):
        """Throughput expressed as picoseconds per kilobyte of data sent."""
        return 100

    def get_delay(self):
        """Delay expressed in 10 microsecond units."""
        return 10

    def get_load(self):
        """Load of the link based on output packets. 1 means a low load.
        255 means a high load."""
        return 1

    def get_reliability(self):
        """Link reliability expressed as a number between 1 and 255. 1 means
        completely unreliable, 255 means completely reliable. 0 is invalid."""
        return 255

    def get_mtu(self):
        return 1500
 
    def is_up(self):
        """Is the interface "up?"""
        return True

    def is_down(self):
        """Is the interface "down?"""
        return not self.is_up()

 
class LogicalInterface(object):
    def __init__(self, phy_iface, ip, metric=1):
        self.phy_iface = phy_iface
        self.ip = ipaddr.IPv4Network(ip)
        self.metric = metric


class SystemFactory(object):
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        if sys.platform == "linux2":
            self.system = LinuxSystem
        elif sys.platform == "win":
            self.system = WindowsSystem
        else:
            raise ValueError("No support for platform %s." % sys.platform)

    def build(self):
        return self.system(*self.args, **self.kwargs)
