# Ping-Of-Death

- **Description**: Ping of Death simulation using custom network stack. The program creates and sends a valid, manually created ICMP echo request packet within the payload of a standard IPv4 Packet. This custom ICMP packet is formatted with the correct fields as an automatically generated ICMP packet with all the bits set correctly for fragmentation, size, etc... The receiving server strips the carrying packet and extracts the custom built ICMP packet in the payload. The server (receiver) imitates the process of receiving an IPv4 packet and it reassembles packets if fragments are received.  The ICMP packet sent carries a payload that will cause the overflow to occur on the server after it is reassembled. For this simulation the server (receiver) fails to check whether the reassembled packet exceeds the maximum allowed size, hence it can be exploited with the ping of death.
___
- **Relevant Area** : Computer Security, Networking.
___
- **Tools / Platforms**:  Python, Unix
___

