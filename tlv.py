"""Classes for EIGRP TLVs."""

import struct
import ipaddr


class ValueMetaclass(type):
    """Metaclass for values in the TLV.
    Assigns big-endian byte ordering to the format string, calculates the
    format length (LEN), and assigns a brief NAME attribute
    based on the class name."""
    def __init__(cls, name, bases, dct):
        super(type, cls).__thisclass__.__init__(cls, name, bases, dct)
        if hasattr(cls, "FORMAT"):
            cls.FORMAT = ">" + cls.FORMAT
            cls.LEN = struct.calcsize(cls.FORMAT)
        cls.NAME = name.lstrip("Value").lstrip("Classic").lower()


class ValueBase(object):
    """Base class for the "value" section of a TLV.

    Derived classes should have FIELDS, FORMAT, and LEN class attributes if
    they want to use ValueBase's generic pack/unpack functions.
    FIELDS should be a list of strings describing the fields within the value.
    FORMAT is the format to be used with struct.pack/unpack.
    LEN is the return value of struct.calcsize(FORMAT).

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
            for k, v in map(None, self._get_public_fields(),
                            self.unpack(kwargs["raw"])):
                setattr(self, k, v)
        elif args:
            for k, v in map(None, self.FIELDS, args):
                setattr(self, k, v)
        else:
            raise(ValueError("One of args or kwargs is expected."))
        self._packed = None

    def _get_public_fields(self):
        """Get public class fields. Override in subclass if this should
        return something other than the regular self.FIELDS."""
        return self.FIELDS

    def _get_private_fields(self):
        """Get private class fields. Override in subclass if this should
        return something other than the regular self.FIELDS."""
        return self.FIELDS

    def getlen(self):
        return self.LEN

    def pack(self):
        """Return the binary stresentation of this object."""
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
            hdr, values = self.unpack(kwargs["raw"])
            for valclass, instance in map(None, self.VALUES, values):
                setattr(self, valclass.NAME, instance)
        elif args:
            index = 0
            for valclass in self.VALUES:
                nargs = len(valclass.FIELDS)
                setattr(self, valclass.NAME,
                        valclass(*args[index:index+nargs]))
                index += nargs
        else:
            raise(ValueError("One of args or kwargs is expected."))

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
        values = self.unpackvalues(raw[self.HDR_LEN:])
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
    # TODO
    TYPE   = TLVBase.PROTO_GENERIC | 3
    VALUES = [ ]


class TLVVersion(TLVBase):
    # TODO
    TYPE   = TLVBase.PROTO_GENERIC | 4
    VALUES = [ ]


class TLVMulticastSeq(TLVBase):
    # TODO
    TYPE   = TLVBase.PROTO_GENERIC | 5
    VALUES = [ ]


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
        self._tlvs = dict()
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
            if tlv.TYPE in self._tlvs:
                raise(ValueError("TLV type %d already registered." % tlv.TYPE))
            self._tlvs[tlv.TYPE] = tlv

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
