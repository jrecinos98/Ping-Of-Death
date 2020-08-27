# Ping-Of-Death

- **Description** : Ping of Death simulation using custom network stack. The program creates and sends a valid, user-defined IP packet 
within the payload of a standard IPv4 Packet. This custom IP packet contains the same fields as a default IPv4 packet and all the bits 
are set correctly for fragmentation, size, etc... The receiving server strips the carrying packet and extracts the custom built IP packet in the payload. 
The server (receiver) imitates the process of receiving an IPv4 packet and it reassembles packets if fragments are received. However the server (receiver)
fails to check whether the reassembled packet exceeds the maximum allowed size, hence it can be exploited with the ping of death.
___
- **Relevant Area** : Computer Security, Networking.
___
- **Tools / Platforms**:  Python, Unix
___

