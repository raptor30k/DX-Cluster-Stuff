#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
import socket

tcpOut = ('localhost', 7772)

def sendTCP(message):
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
		try:
			sock.settimeout(0.2)
			sock.connect(tcpOut)
		except Exception:
			return
		sock.sendall(bytes(message, 'ascii'))
		# response = str(sock.recv(1024), 'ascii')
		# print("Received: {}".format(response))

def main(args):
	global tn
	tn_host = "dxc.nc7j.com"
	tn_port = 7373
	# tn_host = "25.66.85.76"
	# tn_port = 7300
	tn_username = "K7UOP\n"

	# dx_filter = "set dx filter\n"
	# dx_filter = "set dx filter spotter=WA7LNW-#\n"
	# dx_filter = ""
	dx_filter = "set dx filter spottercont = NA"
	# dx_filter = "set dx filter spotterstate=[AZ,UT,NV,CA,NM]\n"
	try:
		tn = telnetlib.Telnet(tn_host, tn_port, 1)
	except:
		print("Unable to connect to Telnet server: " + tn_host)
		return
	#tn.set_debuglevel(100)
	# tn.read_until(b"Please enter your call:\r")
	tn.read_until(b"our call")
	reply = tn_username + dx_filter
	tn.write(reply.encode())
	while True:
		msg = tn.read_until(b"\n").decode()
		sendTCP(msg)
		print(msg.rstrip())
	return 0

if __name__ == '__main__':
	import sys
	import telnetlib
	try:
		main(sys.argv)
	except KeyboardInterrupt:
		print('Caught CTRL-C')
		tn.write("Bye".encode())
		tn.close()
		sys.exit
