import nmap
import sys
import optparse
class NmapScanner():
    def __init__(self):
        self.version_detection=False
        self.os_detection=False
    def nmapScan(self, *args):
        try:
            self.nmScan = nmap.PortScanner()
            self.tgtHost=[]
            nm_command=[]
            if len(args)==1:
                print 'hey'
                self.nmScan.scan(str(args[0]))
                nm=args[0].split(' ')
                [nm_command.append(i) for  i in nm if i !='' ]
                print nm_command 
            else:
                self.nmScan.scan(hosts=args[0], arguments=args[1])
            self.tgtHost=self.nmScan.all_hosts()
            if self.tgtHost==[]:
                self.tgtHost=''
                return 'Target is unreachable !'
            else:
                self.tgtHost=self.nmScan.all_hosts()[0]
            print self.tgtHost
            if '-O' in args   or '-O' in nm_command:
                self.os_detection=True
                self.os="Os: "+self.nmScan[self.tgtHost]['osmatch'][0]['osclass'][0]['osfamily'] + " " + str (self.nmScan[self.tgtHost]['osmatch'][0]['osclass'][0]['osgen']) +" "
                self.cpe='OS CPE: ' + str(self.nmScan[self.tgtHost]['osmatch'][0]['osclass'][0]['cpe'])+" "
                self.device_type="Device type: "+ str(self.nmScan[self.tgtHost]['osmatch'][0]['osclass'][0]['type'])+" "
                self.accuracy="Accuracy: " + str(self.nmScan[self.tgtHost]['osmatch'][0]['osclass'][0]['accuracy'])   +" "            
                
            if '-sV' in args or '-sV' in nm_command:
                print 'version detection on'
                self.version_detection=True  
            #state=nmScan[tgtHost].state()
            #['tcp'][int(tgtPort)]['state']
            self.version=''
            self.product=[]

            self.s_version=[]
            self.extra=[]
            self.state=[]
            self.service=[]
            self.port=[]
            self.reason=[]
            
            #self.protocols=self.nmScan[self.tgtHost].all_protocols()
            self.protocols=self.nmScan[self.tgtHost].all_protocols()

        except Exception, e:
            print str(e) + 'tttttt' 
            return e
            


            
    
    
def main():
    if len(sys.argv) < 3:
        print sys.argv[0] + " <target ip >  <scan option(s)>"
        sys.exit(0)
    
    #for tgtPort in tgtPorts:
    self.nmapScan(sys.argv[1], sys.argv[2])
if __name__ == '__main__':
    main()
