The purpose of this page is to informally describe tests to verify basic operation of EIGRP components.

# RTP testing #

## Testing outline ##

  1. Neighbor discovery
    1. Adding a neighbor
      1. Reaching PENDING state
      1. Reaching UP state (including alerting upper layer)
      1. Do not reach UP state when we do not receive an ACK for our INIT
      1. Do not reach PENDING state if k-values do not agree (this should be moved into EIGRP, but right now it's in RTP)
    1. Removing a neighbor
      1. Losing a neighbor due to retransmission timer being exceeded (Note: this "feature" might not be standard -- need to check)
      1. Losing a neighbor due to hold timer being exceeded
      1. Losing a neighbor due to "goodbye" message -- not implemented
  1. Transmissions
    1. Verify unicast packets can be transmitted and received by an upper layer
    1. Verify multicast packets can be transmitted and received by an upper layer
    1. Verify that unreliable packets are not ACKed
    1. Verify that reliable packets are ACKed
    1. Verify correct sequence number wrapping (should start over at 1) -- note: yet to be implemented
    1. Verify correct sending of the "next multicast sequence number" and "sequence" TLVs when needed