"""Classes for EIGRP TLVs."""

import struct
import ipaddr


class ValueMetaclass(type):
    """Convenience metaclass for values in the TLV.
    Forces the format string to network byte ordering, calculates the
    format length (LEN), and assigns a brief NAME attribute
    based on the class name."""
    def __init__(cls, name, bases, dct):
        super(type, cls).__thisclass__.__init__(cls, name, bases, dct)
        if hasattr(cls, "FORMAT"):
            cls.FORMAT = ">" + cls.FORMAT
            cls.LEN = struct.calcsize(cls.FORMAT)
        cls.NAME = name.lstrip("Value").lstrip("Classic").lower()


class ValueBase(object):
    """Base class for the "value" section of a TLV. This is primarily for
    fixed-length TLVs.

    Derived classes should have FIELDS, FORMAT, and LEN class attributes if
    they want to use ValueBase's generic pack/unpack functions.
    FIELDS should be a list of strings describing the fields within the value.
    FORMAT is the format to be used with struct.pack/unpack.
    LEN is the return value of struct.calcsize(FORMAT). Classes that inherit
        from ValueBase will have this attribute set by the ValueMetaclass.

    Derived classes may also have to override the (un)pack functions if they
    have non-scalar fields or fields that require extra processing after
    pack/unpack is called. For example, to do validation or convert a
    binary IP into a dotted quad."""

    __metaclass__ = ValueMetaclass

    def __init__(self, *args, **kwargs):
        """The only expected keyword arg is 'raw'"""
        if kwargs and args:
            raise(ValueError("Either args or kwargs are expected, not both."))
        if "raw" in kwargs:
            self._parse_kwargs(kwargs)
        elif args:
            self._parse_args(args)
        else:
            raise(ValueError("One of args or kwargs['raw'] is expected."))
        self._packed = None

    def _parse_kwargs(self, kwargs):
        """Override in subclass if different parsing is needed."""
        for k, v in map(None, self._get_public_fields(),
                        self.unpack(kwargs["raw"])):
            setattr(self, k, v)

    def _parse_args(self, args):
        """Parse args and assign class variables based on the names in
        self.FIELDS. Override in subclass if different parsing is needed."""
        for k, v in map(None, self.FIELDS, args):
            setattr(self, k, v)

    def _get_public_fields(self):
        """Get public class fields. Override in subclass if this should
        return something other than the regular self.FIELDS."""
        return self.FIELDS

    def _get_private_fields(self):
        """Get private class fields. Override in subclass if this should
        return something other than the regular self.FIELDS."""
        return self.FIELDS

    def getlen(self):
        """Get the format length. Override in subclass if this should return
        something other than self.LEN."""
        return self.LEN

    def pack(self):
        """Return the binary representation of this object."""
        if not self._packed:
            self._packed = struct.pack(self.FORMAT,
                       *[getattr(self, f) for f in self._get_private_fields()])
        return self._packed

    def unpack(self, raw):
        """Return a tuple containing the unpacked stresentation of this
        object. Return values correspond to self.FIELDS."""
        return struct.unpack(self.FORMAT, raw[:self.getlen()])

    def __setattr__(self, attr, val):
        """Force a repack if an attribute was modified after the last pack."""
        super(object, self).__thisclass__.__setattr__(self, "_packed", None)
        super(object, self).__thisclass__.__setattr__(self, attr, val)

    def __str__(self):
        s = type(self).__name__ + "("
        for f in self.FIELDS:
            s += f + "=" + str(getattr(self, f)) + ", "
        s = s.rstrip(", ")
        s += ")"
        return s


class ValueNexthop(ValueBase):
    FIELDS = [ "ip" ]
    FORMAT = "I"

    def __init__(self, *args, **kwargs):
        super(ValueBase, self).__thisclass__.__init__(self, *args, **kwargs)
        if args:
            self.ip = ipaddr.IPv4Address(self.ip)

    def unpack(self, raw):
        return [ipaddr.IPv4Address(super(ValueBase,
                                   self).__thisclass__.unpack(self, raw)[0])]

    def pack(self):
        if not self._packed:
            self._packed = self.ip.packed
        return self._packed


class ValueClassicMetric(ValueBase):
    # Note: mtu is split into 2 high bytes and 1 low byte.
    FIELDS = [ "dly", "bw", "mtu", "hops", "rel", "load", "tag", "flags" ]
    _PRIVFIELDS = [ "dly", "bw", "mtuhigh", "mtulow", "hops", "rel", "load",
                    "tag", "flags" ]
    FORMAT = "IIHBBBBBB"

    def __init__(self, *args, **kwargs):
        self._mtulow = 0
        self._mtuhigh = 0
        super(ValueBase, self).__thisclass__.__init__(self, *args, **kwargs)

    def _get_private_fields(self):
        return self._PRIVFIELDS

    @property
    def mtuhigh(self):
        return self._mtuhigh

    @mtuhigh.setter
    def mtuhigh(self, val):
        self._mtuhigh = val
        self._mtu = self._calc_mtu(self._mtuhigh, self._mtulow)

    @property
    def mtulow(self):
        return self._mtulow

    @mtulow.setter
    def mtulow(self, val):
        self._mtulow = val
        self._mtu = self._calc_mtu(self._mtuhigh, self._mtulow)

    @property
    def mtu(self):
        return self._mtu

    @mtu.setter
    def mtu(self, val):
        self._mtu = val
        if self._mtu:
            self._mtuhigh, self._mtulow = divmod(self._mtu, 0x10000)

    @staticmethod
    def _calc_mtu(high, low):
        """Add the 2 high bytes and 1 low byte to get the actual mtu."""
        return low + (high << 8)

    def unpack(self, raw):
        """Find the two-value mtu (split into high and low bytes) and
        replace them with a single value mtu."""
        unpacked = super(ValueBase, self).__thisclass__.unpack(self, raw)
        mtuhigh_index = self.FIELDS.index("mtu")
        mtuhigh = unpacked[mtuhigh_index]
        mtulow = unpacked[mtuhigh_index+1]
        mtu = self._calc_mtu(mtuhigh, mtulow)
        return unpacked[:mtuhigh_index] + tuple([mtu]) + \
               unpacked[mtuhigh_index+2:]


class ValueClassicDest(ValueBase):
    # FORMAT and LEN are only set after init or unpacking because addr is a
    # variable length depending on what is being unpacked.
    FIELDS = [ "plen", "addr" ]

    def __init__(self, *args, **kwargs):
        super(ValueBase, self).__thisclass__.__init__(self, *args, **kwargs)
        if args:
            self.addr = ipaddr.IPv4Address(self.addr)
            self._setformat(plen)

    def _setformat(self, plen):
        self.FORMAT = "B%ds" % self._getaddrpacklen(plen)
        self.LEN = struct.calcsize(self.FORMAT)

    def unpack(self, raw):
        plen, addr = super(ValueBase, self).__thisclass__.unpack(self, raw)
        self._setformat(plen)
        return plen, ipaddr.IPv4Address(ipaddr.Bytes(addr.ljust(4, "\x00")))

    def pack(self):
        if not self._packed:
            self._packed = struct.pack("B", self.plen) + \
                           self.addr.packed[:self._getaddrpacklen(self.plen)]
        return self._packed

    def _getpacklen(self, raw):
        if not raw:
            raise(ValueError("Raw cannot be empty."))
        try:
            plen = struct.unpack("B", raw[0])[0]
        except struct.error:
            raise(ValueError("Plen argument must be an integer."))
        if not (0 <= plen <= 32):
            raise(ValueError("Plen must be between 0 and 32."))
        # +1 is for the prefix length
        return self._getaddrpacklen(plen) + 1

    @staticmethod
    def _getaddrpacklen(plen):
        # See A.8.4 of the draft RFC.
        return ((plen - 1) / 8 + 1)


class ValueParam(ValueBase):
    FIELDS = [ "k1", "k2", "k3", "k4", "k5", "holdtime" ]
    FORMAT = "BBBBBxH"


class ValueSeq(ValueBase):

    """A sequence value for the sequence TLV. Stores a list of address strings
    in binary form. ValueSeq does not know how to interpret the addresses
    (i.e. it doesn't know if they are IPv4, IPv6, or something else)."""

    ADDRLEN_FMT = "B"
    ADDRLEN_FMT_SIZE = struct.calcsize(ADDRLEN_FMT)
    MAX_ADDR_SIZE = (1 << (8 * ADDRLEN_FMT_SIZE)) - 1

    def __init__(self, *args, **kwargs):
        super(ValueBase, self).__thisclass__.__init__(self, *args, **kwargs)
        self.addrs = list()

    def _parse_kwargs(self, kwargs):
        self.addrs = self.unpack(kwargs["raw"])

    def _parse_args(self, args):
        # The addrlen field is derived from len(addr)
        for addr in args:
            self.add_addr(addr)

    def add_addr(self, addr):
        if len(addr) > MAX_ADDR_SIZE:
            raise(ValueError("Address length exceeds max address size."))
        self.addrs.append(addr)

    def pack(self):
        if not self._packed:
            # Only assign to self._packed once because parent's
            # __setattr__ will clear self._packed every time it is modified.

            # For every addr in self.addrs:
            #   Get the length and insert
            #  get the length of the 
            packed = ""
            for addr in self.addrs:
                packed += struct.pack(self.ADDRLEN_FMT, len(addr))
                packed += addr
            self._packed = packed
        return self._packed

    def unpack(self, raw):
        offset = 0
        rawlen = len(raw)
        seq_addrs = list()

        # Save off addresses until there is no more data.
        # Addresses are in binary and could be any length, though
        # typical lengths are 4 for IPv4 and 16 for IPv6. We'll support
        # addresses of any length here.
        while offset < rawlen:
            size = struct.unpack_from(addrlen_fmt, raw, offset)
            offset += addrlen_fmt_size
            seq_addrs.append(struct.unpack_from(raw, "%ss" % size, offset))
            offset += size
        return seq_addrs

    def getlen(self):
        total_len = self.ADDRLEN_FMT_SIZE * len(self.addrs)
        for addr in self.addrs:
            total_len += len(addr)
        return total_len

    def __str__(self):
        return type(self).__name__ + "(%s addresses)" % len(self.addrs)


class ValueMulticastSeq(ValueBase):
    FIELDS = [ "seq" ]
    FORMAT = "I"


class TLVBase(object):
    """Base class for EIGRP TLVs."""

    PROTO_GENERIC = 0
    PROTO_IP4     = 0x100
    PROTO_IP6     = 0x400

    HDR_FORMAT = ">HH"
    HDR_LEN = struct.calcsize(HDR_FORMAT)

    def __init__(self, *args, **kwargs):
        """There is only one used kwarg: "raw".
        args should be all required arguments for the TLV's Value members.
        """
        self.type = self.TYPE
        if args and kwargs:
            raise(ValueError("Either args or kwargs is expected, not both."))
        if "raw" in kwargs:
            self._parse_kwargs(kwargs)
        elif args:
            self._parse_args(arg)
        else:
            raise(ValueError("One of args or kwargs['raw'] is expected."))

    def _parse_kwargs(self, kwargs):
        """Override in subclass to parse kwargs for a TLV differently."""
        hdr, values = self.unpack(kwargs["raw"])
        for valclass, instance in map(None, self.VALUES, values):
            setattr(self, valclass.NAME, instance)

    def _parse_args(self, args):
        """Override in subclass to parse args for a TLV differently."""
        index = 0
        for valclass in self.VALUES:
            nargs = len(valclass.FIELDS)
            setattr(self, valclass.NAME, valclass(*args[index:index+nargs]))
            index += nargs

    def getlen(self):
        totallen = 0
        for valclass in self.VALUES:
            totallen += getattr(self, valclass.NAME).getlen()
        return self.HDR_LEN + totallen

    def __str__(self):
        s = type(self).__name__ + "("
        for v in self.VALUES:
            s += str(getattr(self, v.NAME)) + ", "
        s = s.rstrip(", ") 
        s += ")"
        return s

    def pack(self):
        packed = ""
        for valclass in self.VALUES:
            packed += getattr(self, valclass.NAME).pack()
        padlen = self.getpad(len(packed))
        self.len = self.HDR_LEN + len(packed) + padlen
        hdr = self.packhdr()
        packed = hdr + packed
        return packed + ("\x00" * padlen)

    def packhdr(self):
        return struct.pack(self.HDR_FORMAT, self.type, self.len)

    @staticmethod
    def unpackhdr(self, raw):
        return struct.unpack(TLVBase.HDR_FORMAT, raw[:TLVBase.HDR_LEN])

    def unpackvalues(self, raw):
        index = 0
        objs = list()
        for valclass in self.VALUES:
            obj = valclass(raw=raw)
            objs.append(obj)
            index += obj.getlen()
        # Check for 4 byte alignment
        pad = self.getpad(index)
        if index + pad != len(raw):
            raise(ValueError("Raw data was not padded to 4 bytes, or" 
                             "garbage follows the data."))
        return objs

    def unpack(self, raw):
        hdr = self.unpackhdr(raw)
        values = self.unpackvalues(raw[self.HDR_LEN:self.HDR_LEN+self.len])
        return hdr, values

    @staticmethod
    def getpad(datalen, alignment=4):
        """Returns length needed to pad to the specified byte alignment."""
        return (alignment - (datalen % alignment)) % alignment


class TLVParam(TLVBase):
    TYPE   = TLVBase.PROTO_GENERIC | 1
    VALUES = [ ValueParam ]


class TLVAuth(TLVBase):
    # TODO
    TYPE   = TLVBase.PROTO_GENERIC | 2
    VALUES = [ ]


class TLVSeq(TLVBase):
    TYPE   = TLVBase.PROTO_GENERIC | 3
    VALUES = [ ValueSeq ]


class TLVVersion(TLVBase):
    # TODO
    TYPE   = TLVBase.PROTO_GENERIC | 4
    VALUES = [ ]


class TLVMulticastSeq(TLVBase):
    # TODO
    TYPE   = TLVBase.PROTO_GENERIC | 5
    VALUES = [ ValueMulticastSeq ]


class TLVPeerInfo(TLVBase):
    # TODO
    TYPE   = TLVBase.PROTO_GENERIC | 6
    VALUES = [ ]


class TLVPeerTerm(TLVBase):
    # TODO
    TYPE   = TLVBase.PROTO_GENERIC | 7
    VALUES = [ ]


class TLVPeerTIDList(TLVBase):
    # TODO
    TYPE   = TLVBase.PROTO_GENERIC | 8
    VALUES = [ ]


class TLVInternal4(TLVBase):
    TYPE   = TLVBase.PROTO_IP4 | 2
    VALUES = [ ValueNexthop, ValueClassicMetric, ValueClassicDest ]


class TLVFactory(object):
    """Factory for arbitrary Type Length Value fields."""

    def __init__(self, tlvclasses=None, hdr_unpacker=TLVBase.unpackhdr,
                 typeindex=0):
        """tlvclasses is an iterable of classes to register during init.
        hdr_unpacker is a function that can be used to unpack TLV headers for
                     the format your TLVs will use. This should return
                     an indexable object containing at least a "type" field.
        typeindex is the index of the "type" field that is returned from
                  hdr_unpacker. It does seem silly for this to be something
                  other than 0 given the order of words in the name "TLV",
                  but it's an option."""
        self.tlvs = dict()
        if tlvclasses:
            self.register_tlvs(tlvclasses)
        self._unpack_hdr = hdr_unpacker
        self._typeindex = typeindex

    def register_tlvs(tlvclasses):
        try:
            iter(tlvclasses)
        except TypeError:
            tlvclasses = list(tlvclasses)
        for tlv in tlvclasses:
            if tlv.TYPE in self.tlvs:
                raise(ValueError("TLV type %d already registered." % tlv.TYPE))
            self.tlvs[tlv.TYPE] = tlv

    def build_all(self, raw):
        """Generator to yield all parsed TLVs from raw data."""
        index = 0
        rawlen = len(raw)
        while index < rawlen:
            tlv = self.build(raw[index:])
            index += tlv.getlen()
            yield tlv

    def build(self, raw):
        """Returns one TLV parsed from raw data."""
        try:
            _type = self.unpack_hdr(raw)[self._typeindex]
            return self._tlvs[_type](raw=raw)
        except struct.error:
            raise
        except KeyError:
            raise(ValueError("Unknown type in TLV: %d" % _type))
