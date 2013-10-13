#!/usr/bin/env python

"""A chat client that finds link-local users using RTP. Used to demonstrate
that this implementation of RTP is decoupled from EIGRP."""

import sys
sys.path.append("..")

from tw_baseiptransport import reactor
import rtp
import rtptlv
import util
import sysiface

# No reason for using this number other than I think it is unused elsewhere
PROTO_RTPCHAT = 0x0a00

class _BaseRTPChatGUI(object):
    """This is the base class for RTPChat graphical user interfaces. This
    serves as a programming inteface that should be overriden by the actual
    GUI class."""

    def __init__(self, sendfunc):
        """sendfunc -- The function that the GUI should call when the
                       GUI has text to send."""
        self._send = sendfunc

    def receive_text(self, neighbor, text):
        """Called when a neighbor has sent us a text message."""

    def update_username(self, neighbor, text):
        """Called when we receive a new username for a neighbor. (Including
        when we first discover a neighbor and obtain its username.)"""


class RTPChatGtkGUI(_BaseRTPChatGUI):
    def receive_text(self, neighbor, text):
        print("*** GUI got text")

    def update_username(self, neighbor, text):
        print("*** GUI got updated username")


class ValueText(rtptlv.ValueBase):
    """Plain text data."""

    FIELDS = [ "text" ]

    def __init__(self, *args, **kwargs):
        self.text = ""
        super(rtptlv.ValueBase, self).__thisclass__.__init__(self, *args,
                                                             **kwargs)

    def pack(self):
        return self.text

    def unpack(self, raw):
        return raw

    def _parse_kwargs(self, kwargs):
        self.text = self.unpack(kwargs["raw"])

    def _parse_args(self, args):
        if len(args) != 1:
            raise(ValueError("Exactly one arg is expected."))
        self.text = args[0]

    def getlen(self):
        return len(self.text)

    def __str__(self):
        return type(self).__name__ + "({} characters)".format(len(self.text))


class ValueEmpty(rtptlv.ValueBase):
    # ValueBase won't allow an empty TLV, so allow for that here.

    LEN = 0
    FIELDS = []

    def __init__(self, *args, **kwargs):
        pass

    def pack(self):
        return ""


class TLVText(rtptlv.TLVBase):
    TYPE   = PROTO_RTPCHAT | 1
    VALUES = [ ValueText ]


class TLVUserResponse(rtptlv.TLVBase):
    TYPE   = PROTO_RTPCHAT | 2
    VALUES = [ ValueText ]


class TLVUserRequest(rtptlv.TLVBase):
    TYPE   = PROTO_RTPCHAT | 3
    VALUES = [ ValueEmpty ]

    def __init__(self, *args, **kwargs):
        self.empty = ValueEmpty()
        self.type = self.TYPE


class RTPChat(rtp.ReliableTransportProtocol):

    """An example of an upper layer to RTP that is not EIGRP. Used to
    demonstrate that this implementation of RTP is decoupled from EIGRP."""

    # Supported UI options
    GTK_UI = 1

    def __init__(self, username, ui, ip, *args, **kwargs):
        rtp.ReliableTransportProtocol.__init__(self, *args, **kwargs)
        self.activate_iface(ip)
        if ui == self.GTK_UI:
            self._ui = RTPChatGtkGUI(self._send_chat_msg)
        else:
            raise(ValueError("Unsupported GUI type: {}".format(ui)))
        self._username = username
        self._tlvfactory.register_tlvs([TLVText,
                                        TLVUserRequest,
                                        TLVUserResponse])

    def _process_reply_tlvs(self, neighbor, hdr, tlvs):
        self.log.debug5("RTPCHAT processing reply TLV")
        for tlv in tlvs:
            if tlv.type == TLVText.TYPE:
                self.log.debug5("Receiving Text TLV.")
                self._process_chat_msg(neighbor, tlv.text)
            elif tlv.type == TLVUserResponse.TYPE:
                self.log.debug5("Receiving User Response TLV.")
                self._update_username(neighbor, tlv.text.text)
            else:
                self.log.debug("Unknown reply TLV: {}".format(tlv))

    def _update_username(self, neighbor, text):
        self.log.debug("Updating neighbor {} to use username {}".format(neighbor, text))
        neighbor._username = text
        self._ui.update_username(neighbor, text)

    def _process_chat_msg(self, neighbor, text):
        self._ui.receive_text(neighbor)

    def _send_username(self, neighbor):
        """Send our username to a neighbor."""
        tlvs = [TLVUserResponse(self._username)]
        self.log.debug5("Sending our username to neighbor {}...".format(neighbor))
        neighbor.send(self._rtphdr.OPC_REPLY, tlvs, True)

    def _process_request_tlvs(self, neighbor, hdr, tlvs):
        self.log.debug5("RTPCHAT processing request.")
        for tlv in tlvs:
            if tlv.type == TLVUserRequest.TYPE:
                self.log.debug5("Receiving User Request TLV.")
                self._send_username(neighbor)
            else:
                self.log.debug("Receiving unknown TLV type.")

    def _send_chat_msg(self, neighbor, text):
        tlvs = [TLVText(text)]
        self.neighbor.send(self._rtphdr.OPC_REPLY, tlvs, True)

    def initReceived(self, neighbor):
        pass

    def foundNeighbor(self, neighbor):
        self._request_username(neighbor)

    def _request_username(self, neighbor):
        tlvs = [TLVUserRequest()]
        self.log.debug5("Requesting username from neighbor {}".format(neighbor))
        neighbor.send(self._rtphdr.OPC_REQUEST, tlvs, True)

    def lostNeighbor(self, neighbor):
        pass

    def rtpReceived(self, neighbor, hdr, tlvs):
        self.log.debug5("RTPCHAT received a message...")
        if hdr.opcode == self._rtphdr.OPC_REPLY:
            self._process_reply_tlvs(neighbor, hdr, tlvs)
        elif hdr.opcode == self._rtphdr.OPC_REQUEST:
            self._process_request_tlvs(neighbor, hdr, tlvs)
        else:
            self.log.debug("Received unknown opcode: {}".format(hdr.opcode))

    def run(self):
        reactor.listenIP(88, self)
        self.log.info("RTPChat is starting...")
        reactor.run()


def main(args):
    if not util.is_admin():
        print("Must run as root/admin. Exiting.")
        return 1

    try:
        ip = args[1]
        user = args[2]
        logconfig = args[3]
    except:
        print("Usage: ./rtpchat.py ip user logconfig")
        return 1

    system = sysiface.SystemFactory(0, 0).build()
    rtpchat = RTPChat(user, RTPChat.GTK_UI, ip, system=system,
                      logconfig=logconfig)
    rtpchat.run()

if __name__ == "__main__":
    sys.exit(main(sys.argv))
