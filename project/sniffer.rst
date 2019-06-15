
Description
~~~~~~~~~~~~~

The sniffer allows you to sniff network traffic and extract sensitive information that might be helpful
in carrying out other forms of attacks. The main things extracted include:

  - Usernames
  - Email addresses
  - cookies
  - passwords

How to use
~~~~~~~~~~~~

-Choose the interface type you want to sniff on. The module only supports wlan0 and eth0 interfaces. 

- Enter the target/Victim- this helps the you avoid processing packets from untargeted users.
  If this field is left blank, any data from any host in the network will be sniffed.

-Where "packet too large"  message is displayed, please check the results in the file under the folder 
 sensitives. The file nameis equal to the time of the scan with a txt extension. 

Problem sniffing?
~~~~~~~~~~~~~~~~~
  If you are experiencing trouble sniffing traffic, please check for the following:

  -Ensure the interface you are trying to sniff on is up. If down, you can issue Linux command (without quotes): "sudo interfacename up" Where interface name is either wlan0 or eth0)

  -Ensure that you have permissions to sniff on the interface, Usually solve this starting the program as rootor using sudo before starting the program on the commandline.

