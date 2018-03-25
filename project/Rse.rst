
Description
~~~~~~~~~~~~~

This module allows you to perform remote shell execution. THe module requires you to get your payload into the remote computer using your own crafty methods. Thereafter, the code is exectuded and connects back to the attacker computer.
The attacker can the execute commands on the remote nachine as if they were physically interacting with it.

How to use
~~~~~~~~~~~~

-Enter the port number on which to listen. 
-After notification of connection you will be able to enter commands in the interface shown.

Problem?
~~~~~~~~~~~~~~~~~
  If you are experiencing trouble , please check for the following:

  -Ensure the interface you are trying to use is up. If down, you can issue Linux command (without quotes): "sudo interfacename up" Where interface name is either wlan0 or eth0)

  -Ensure that you have permissions to se the interface, you can solve this by starting the program as rootor using sudo before starting the program on the commandline.
