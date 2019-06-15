
Description
~~~~~~~~~~~~~

This module allows you to perform DNS spoofing or DNS cache poisoning and ARP spoofing also known as ARP cache poisoning.
ARP cache poisoning is a layer 2 attack which will deveive the victim that you have a certain mac address which you dont.
This allows you to intercept traffic between hosts in layer 2.
Dns Cache poisoning is a layer 3 attack which allows the attacker to deveive the victim that they have the corresponding Ip address to a DNS query.


How to use
~~~~~~~~~~~~

-Choose your interface. The module only supports wlan0 and eth0 interfaces. 
-Choose the attack type i.e either dns spoofing or dns spoofing.
In the event that your NIC(network interface card) does not support promiscous mode, the ARP spoofing attack should precede
Dns spooofing or even sniffing. After the attack 

Problem?
~~~~~~~~~~~~~~~~~
  If you are experiencing trouble , please check for the following:

  -Ensure the interface you are trying to use is up. If down, you can issue Linux command (without quotes): "sudo interfacename up" Where interface name is either wlan0 or eth0)

  -Ensure that you have permissions to se the interface, you can solve this by starting the program as rootor using sudo before starting the program on the commandline.



