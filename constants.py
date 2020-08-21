class CONSTANTS:
	DEST_IP = 'cs177.seclab.cs.ucsb.edu'
	DEST_PORT =  29435

	PAYLOAD_SOURCE_IP = '192.168.222.1'
	PAYLOAD_DEST_IP = '192.168.222.2'
	MTU = 1500 #bytes

	class IP_HEADER:
		#indicates a length of 5 × 32 bits = 160 bits = 20 bytes
		MIN_HEADER_LEN = 5 # b'\x00\x05'
		EMPTY = b'\x00'
		VERSION = b'\x40'
		#Needs to be 2 bytes long to be or with the frag offset
		MORE_FRAGS_FLAG = b'\x20\x00' #001 0 (last bit is part of frag offset)
		LAST_FRAG_FLAG = b'\x00\x00'  #000 0
		#Make TTL its max value. I think it is used with ICMP message.
		TTL = b'\x40'
		TCP_PROTOCOL = b'\x06'
		ICMP_PROTOCOL = b'\x01'
		
	class ICMP_TYPE:
		ECHO_REPLY = 0
		ECHO_REQUEST = 8
		TIME_EXCEEDED = 11

	class ICMP_CODE:
		TTL_EXPIRE = 0
		#This project does not send this code
		FRAG_REASSEMBLE_EXCEEDED = 1
		IP_MISSING_OPTION = 1
		IP_BAD_LENGTH = 2
