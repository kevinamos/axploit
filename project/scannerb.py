import nmap
import sys
import optparse
def nmapScan(tgtHost, args):
	try:
		nmScan = nmap.PortScanner()
		tgtHost=str(tgtHost)
		nmScan.scan(hosts=tgtHost, arguments=args)
		#state=nmScan[tgtHost].state()
		#['tcp'][int(tgtPort)]['state']
		version=''
 
		if '/' not in tgtHost:
			if '-sV' in args:
				version=1
				print ('PORT\tSTATE\t\t SERVICE\t VERSION') 
			else:
				print ('PORT\tSTATE\t\t SERVICE')
			for proto in nmScan[tgtHost].all_protocols():
				lport = nmScan[tgtHost][proto].keys()
				lport.sort()	
				for port in lport:
					if version:
						product=nmScan[tgtHost][proto][port]['product']
						version=nmScan[tgtHost][proto][port]['version']
						extra=nmScan[tgtHost][proto][port]['extrainfo']
						version=str(product) + " " + str(version) + " " + str(extra)
					service=nmScan[tgtHost][proto][port]['name'].strip()
			
					print ('%s\t%s\t\t %s\t%s' % (port, nmScan[tgtHost][proto][port]['state'], service, version))
			if str(args)=='-O':
				print "Running "+nmScan[tgtHost]['osmatch'][0]['osclass'][0]['osfamily'] + " " + str (nmScan[tgtHost]['osmatch'][0]['osclass'][0]['osgen'])
				print 'OS CPE ' + str(nmScan[tgtHost]['osmatch'][0]['osclass'][0]['cpe'])
				print "Device type "+ str(nmScan[tgtHost]['osmatch'][0]['osclass'][0]['type'])
				print "Accuracy " + str(nmScan[tgtHost]['osmatch'][0]['osclass'][0]['accuracy'])				
		else:
			for h in nmScan.all_hosts():
				print "scan report for " + str(nmScan[h]['addresses']['ipv4'])
				print "Host is up"
				if '-sV' in args:
					version=1
					print ('PORT\tSTATE\t\t SERVICE\t VERSION') 
				else:
					print ('PORT\tSTATE\t\t SERVICE')			
				for proto in nmScan[h].all_protocols():
					lport = nmScan[h][proto].keys()
					lport.sort()	
					for port in lport:
						service=nmScan[h][proto][port]['name'].strip()
						if version:
							product=nmScan[h][proto][port]['product']
							version=nmScan[h][proto][port]['version']
							extra=nmScan[h][proto][port]['extrainfo']
							version=str(product) + " " + str(version) + " " + str(extra)			
							
						print ('%s\t%s\t\t %s\t %s' % (port, nmScan[h][proto][port]['state'], service,version))
			print str(nmScan.scanstats()['totalhosts']) + ' total hosts'
			print str(nmScan.scanstats()['uphosts'])	+ ' hosts  Up'	
	except Exception, e:
		print "Ecountered the following error => "+ str(e)
	
	
def main():
	if len(sys.argv) < 3:
		print sys.argv[0] + " <target ip >  <scan option(s)>"
		sys.exit(0)
	
	#for tgtPort in tgtPorts:
	nmapScan(sys.argv[1], sys.argv[2])
if __name__ == '__main__':
	main()
