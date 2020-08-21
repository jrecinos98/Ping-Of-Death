import socket
import signal
import struct
import random
import sys
from scapy.all import checksum
from constants import CONSTANTS

class ExitAction(Exception):
	pass

def receiveSignal(sigNum, frame):
	raise ExitAction()

def big_endian(num: int, option ="u_short"):
	if(option == "int"):
		return struct.pack( ">i",num)
	elif(option =="u_int"):
		#Unsigned int
		return struct.pack( ">I",num)
	elif(option == "short" ):
		return struct.pack( ">h",num)
	elif(option == "u_short"):
		return struct.pack( ">H",num)
	elif(option == "long" ):
		return struct.pack( ">l",num)
	elif(option == "u_long"):
		return struct.pack( ">L",num)
	else:
		return struct.pack(option,num)

def reorder_bytes(b_string):
	num = int_from_bytes(b_string)
	#int to bytes arranges in big endian
	return int_to_bytes(num)

#Generates random ID for datagram packet
def generate_id() -> int:
	return random.randint(0x400,0xFFFF)

#Turn an integer into a byte string. If size is set it will return a string with a number of bytes == size
def int_to_bytes(x: int, size = 1) -> bytes:
	if size > 1:
		return x.to_bytes(size, 'big')
	else:
		return x.to_bytes((x.bit_length() + 7) // 8, 'big')

#Turn a byte string back to its integer form
def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')

# Returns the byte string that results from performing bitwise or on b1 and b2
def or_byte(b1: bytes, b2:bytes)-> bytes:
	out = int_from_bytes(b1) | int_from_bytes(b2)
	return int_to_bytes(out)

#Turns a string IP address into its byte string representation
def ip_to_bytes(ip: str) -> bytes:
	bin_ip= bin(struct.unpack('!I', socket.inet_aton(ip))[0])
	#Remove the '0b' from the string to parse to int. Then turn it into bytes
	return int_to_bytes(int(bin_ip[2:],2), 4)

#Specifically to handle the IP Flag bits and the Fragment offset
def set_flag(b1: bytes, b2: bytes) -> bytes:
	return big_endian((int_from_bytes(b1) | int_from_bytes(b2)), "u_short")

#Builds the IPv4 header for a datagram .
def build_IPv4_header(packet_id: int, last_fragment: bool, fragment_offset: int, payload_size: int) -> bytes:
	#HEADER LEN IS THE NUMBER OF 32-bit WORDS in the header
	header_size = CONSTANTS.IP_HEADER.MIN_HEADER_LEN # + options (if applicable)

	#Total Packet len is the number of bytes in the packet, counting header and payload
	#Convert header_size to bytes (header_size* 32 bits)/ 8
	packet_len = (header_size * 4) + payload_size
	
	flag = CONSTANTS.IP_HEADER.MORE_FRAGS_FLAG
	#If this is the last fragment we use a different flag
	if(last_fragment):
		flag = CONSTANTS.IP_HEADER.LAST_FRAG_FLAG
	#Each of these is 4 bytes so it should fit in an int.
				#Version + size of header (IHL)							# DSCP / ECN       #Total Packet Length (2 bytes)
	first_word = or_byte(CONSTANTS.IP_HEADER.VERSION, int_to_bytes(header_size))+ CONSTANTS.IP_HEADER.EMPTY + int_to_bytes(packet_len, 2)		 #EVERY FIELD IS IN BIG ENDIAN  	   
									# Bitwise or the 3 bits for flag with the 13 bits of the fragment offset. Max fragment offset is 2^13 - 1
	second_word = int_to_bytes(packet_id,2) + set_flag(flag,int_to_bytes(fragment_offset, 2)) #EVERY FIELD IS IN BIG ENDIAN
	

	third_word  =  reorder_bytes(CONSTANTS.IP_HEADER.TTL) + reorder_bytes(CONSTANTS.IP_HEADER.ICMP_PROTOCOL) # Need to append the check sum. It is calculated below
	
	fourth_word =  ip_to_bytes(CONSTANTS.PAYLOAD_SOURCE_IP)
	
	fifth_word = ip_to_bytes(CONSTANTS.PAYLOAD_DEST_IP)
	
	temp_packet = first_word + second_word+ third_word+ fourth_word+ fifth_word
	
	#check_sum = calculate_check_sum(words)
	check_sum = checksum(temp_packet)
	#combine into one long byte string
	return first_word+second_word+third_word+ int_to_bytes(check_sum, 2)+ fourth_word + fifth_word

def build_ICMP_message(msg_type: int, id: int, extra: bytes = None, code = 0) -> bytes:
	type_code = int_to_bytes(((msg_type << 8) | code)) # add the empty bytes of checksum
	check_sum = 0
	second_word = int_to_bytes(id, 2) + int_to_bytes(0,2) #Sequence num 
	if(extra == None):
		check_sum =  checksum(type_code+second_word)
	else:
		check_sum = checksum(type_code+ second_word+ extra)
	type_code= type_code + int_to_bytes(check_sum, 2)
	return type_code+second_word if extra == None else type_code + second_word+ extra

#Builds an IPv4 datagram (header fields and payload set)
def build_packet( payload: bytes, packet_id: int, fragment_offset: int, last_fragment=False) -> bytes:
	#create payload and get size
	header = build_IPv4_header(packet_id, last_fragment, fragment_offset, len(payload))
	return header + payload

def is_connection_closed(server_reply):
	return server_reply == None 


def read_reply(sock):
	#Size is a short int (2 bytes)
	size = int.from_bytes(read(sock,2), "big")
	#TODO check size is > 0
	if(size == 0):
		print("Size of 0")
	print("Size: "+ str(size))
	return read(sock, size)

#read number of bytes
def read(sock, size):
	chunks = []
	bytes_recd = 0
	while bytes_recd < size:
		#print("Reading now.")
		try:
			chunk = sock.recv(min(size - bytes_recd, 8192))
			if chunk == b'':
				return ""
			chunks.append(chunk)
			bytes_recd = bytes_recd + len(chunk)
			#print("Received {} bytes so far.".format(bytes_recd))
		except socket.error:
			print("Error on read")
			return ""
	return b''.join(chunks)

#m_len is the size of the message (bytes). msg is the serialized string
def send_msg(socket, m_len, msg):
	send_bytes(socket, m_len)
	send_bytes(socket, msg)

# Sends byte string data over a socket
def send_bytes(socket, data):
	buf = data
	size = len(data)
	sentBytes=0
	while (sentBytes < size):
		try:
			sent= socket.send(data)
			if sent == '':
				print("Data not sent completely")
			#len(sent) will be num of characters sent 
			buf = buf[sent+1:]
			sentBytes+= sent
		except socket.error:
			print("Error on send message")
			return -1
	return sentBytes

def test():
	packet = build_packet(1234,0x04d2,0, msg_code= 0)
	print(packet)
	print("len: ", len(packet))

#calculates the checksum for the packet and returns it as a byte string
#NOT COMPLETELY RIGHT. NEED TO DO ONE's COMPLEMENT TO THE TOTAL SUM AT THE END
def calculate_check_sum(words: list) -> int:
	c_sum = 0
	#Gets the second half of the word
	mask =  0x0000FFFF
	for i in words:
		#print("OG Sum: ", hex(c_sum))
		num = int_from_bytes(i)
		#Get upper bits 
		first_half = (num >> 8*2)
		#Get lower bits
		second_half = (num & mask)
		#print("First : ", hex(first_half))
		#print("Second: ", hex(second_half))
		c_sum += first_half + second_half
		#carry_bit will be 0 unless there is overflow
		carry_bit = c_sum >> 8*2
		#print("Sum   : ", hex(c_sum))
		if(carry_bit > 0):
			c_sum = (c_sum&mask) + carry_bit
			#print("Newsum: ", hex(c_sum))
		
		#print("_____"*10)
	return c_sum

