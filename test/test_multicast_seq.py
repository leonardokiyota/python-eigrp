#!/usr/bin/env python

import sys
sys.path.append("..")
sys.path.append("../examples")

import util
import rtpchat
import sysiface
import rtp_control

class DropPacketsRTPChat(rtpchat.RTPChat):
    def before_ReliableTransportProtocol__send_explicit_ack(self, neighbor):
        if neighbor._state_receive == neighbor._up_receive:
            # Neighbor is UP, this is when we want to drop ACKs.
            return True


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
    chat = DropPacketsRTPChat(user, DropPacketsRTPChat.GTK_UI, ip,
                              system=system, logconfig=logconfig)
    rtp_control.make_hooks(chat)
    chat.run()

if __name__ == "__main__":
    main(sys.argv)
