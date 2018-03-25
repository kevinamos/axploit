*Description* 
~~~~~~~~~~~~~~~~~~~~~~~~~
This module uses nmap - A Network exploration tool and security / port scanner

This module uses a number of options to perform different scans and network explorations.

*Scan techniques*:
~~~~~~~~~~~~~~~~~~~~~~~~~
 -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
 -sU: UDP Scan
 -sN/sF/sX: TCP Null, FIN, and Xmas scans
 --scanflags <flags>: Customize TCP scan flags
 -sI <zombie host[:probeport]>: Idle scan
 -sY/sZ: SCTP INIT/COOKIE-ECHO scans
 -sO: IP protocol scan
 -b <FTP relay host>: FTP bounce scan
*Port specification and scan order*:
 -p <port ranges>: Only scan specified ports
 Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
 --exclude-ports <port ranges>: Exclude the specified ports from scanning
 -F: Fast mode - Scan fewer ports than the default scan
 -r: Scan ports consecutively - don't randomize
 --top-ports <number>: Scan <number> most common ports
 --port-ratio <ratio>: Scan ports more common than <ratio>
*Service/Version Detection*:
 -sV: Probe open ports to determine service/version info
 --version-intensity <level>: Set from 0 (light) to 9 (try all probes)
 --version-light: Limit to most likely probes (intensity 2)
 --version-all: Try every single probe (intensity 9)
 --version-trace: Show detailed version scan activity (for debugging)
*OS detection*:
 -O: Enable OS detection
 --osscan-limit: Limit OS detection to promising targets
 --osscan-guess: Guess OS more aggressively
*Timing and performance*:
Options which take <time> are in seconds, or append 'ms' (milliseconds),
 's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).
 -T<0-5>: Set timing template (higher is faster)
 --min-hostgroup/max-hostgroup <size>: Parallel host scan group sizes
 --min-parallelism/max-parallelism <numprobes>: Probe parallelization
 --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>: Specifies
     probe round trip time.
 --max-retries <tries>: Caps number of port scan probe retransmissions.
 --host-timeout <time>: Give up on target after this long
 --scan-delay/--max-scan-delay <time>: Adjust delay between probes
 --min-rate <number>: Send packets no slower than <number> per second
 --max-rate <number>: Send packets no faster than <number> per second
*Firewall/IDS Evasion and spoofing*:
 -f; --mtu <val>: fragment packets (optionally w/given MTU)
 -D <decoy1,decoy2[,ME],...>: Cloak a scan with decoys
 -S <IP_Address>: Spoof source address
 -e <iface>: Use specified interface
 -g/--source-port <portnum>: Use given port number
 --proxies <url1,[url2],...>: Relay connections through HTTP/SOCKS4 proxies
 --data <hex string>: Append a custom payload to sent packets
 --data-string <string>: Append a custom ASCII string to sent packets
 --data-length <num>: Append random data to sent packets
 --ip-options <options>: Send packets with specified ip options
 --ttl <val>: Set IP time-to-live field
 --spoof-mac <mac address/prefix/vendor name>: Spoof your MAC address
 --badsum: Send packets with a bogus TCP/UDP/SCTP checksum
*Output*:
 -oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3
 and Grepable format, respectively, to the given filename.
 -oA <basename>: Output in the three major formats at once
 -v: Increase verbosity level (use -vv or more for greater effect)
 -d: Increase debugging level (use -dd or more for greater effect)
 --reason: Display the reason a port is in a particular state
 --open: Only show open (or possibly open) ports
 --packet-trace: Show all packets sent and received
 --iflist: Print host interfaces and routes (for debugging)
 --append-output: Append to rather than clobber specified output files
 --resume <filename>: Resume an aborted scan
 --stylesheet <path/URL>: XSL stylesheet to transform XML output to HTML
 --webxml: Reference stylesheet from Nmap.Org for more portable XML
 --no-stylesheet: Prevent associating of XSL stylesheet w/XML output
*Misc*:
 -6: Enable IPv6 scanning
 -A: Enable OS detection, version detection, script scanning, and traceroute
 --datadir <dirname>: Specify custom Nmap data file location
 --send-eth/--send-ip: Send using raw ethernet frames or IP packets
 --privileged: Assume that the user is fully privileged
 --unprivileged: Assume the user lacks raw socket privileges
 -V: Print version number
 -h: Print this help summary page.
*Examples*:
 nmap -v -A scanme.nmap.org
 nmap -v -sn 192.168.0.0/16 10.0.0.0/8
 nmap -v -iR 10000 -Pn -p 80
SEE THE MAN PAGE (https://nmap.org/book/man.html) FOR MORE OPTIONS AND EXAMPLES

*Target specifications*
~~~~~~~~~~~~~~~~~~~~~~~~~
While targets are usually specified on the command lines, the following options are also available to control target selection:
-iL inputfilename (Input from list) .
   Reads target specifications from inputfilename. Passing a huge list of hosts is often awkward on the command line, yet it is a common
   desire. For example, your DHCP server might export a list of 10,000 current leases that you wish to scan. Or maybe you want to scan all
   IP addresses except for those to locate hosts using unauthorized static IP addresses. Simply generate the list of hosts to scan and pass
   that filename to Nmap as an argument to the -iL option. Entries can be in any of the formats accepted by Nmap on the command line (IP
   address, hostname, CIDR, IPv6, or octet ranges). Each entry must be separated by one or more spaces, tabs, or newlines. You can specify
   a hyphen (-) as the filename if you want Nmap to read hosts from standard input rather than an actual file.
   The input file may contain comments that start with # and extend to the end of the line.
-iR num hosts (Choose random targets) .
   For Internet-wide surveys and other research, you may want to choose targets at random. The num hosts argument tells Nmap how many IPs
   to generate. Undesirable IPs such as those in certain private, multicast, or unallocated address ranges are automatically skipped. The
   argument 0 can be specified for a never-ending scan. Keep in mind that some network administrators bristle at unauthorized scans of
   their networks and may complain. Use this option at your own risk! If you find yourself really bored one rainy afternoon, try the
   command nmap -Pn -sS -p 80 -iR 0 --open.  to locate random web servers for browsing.
--exclude host1[,host2[,...]] (Exclude hosts/networks) .
   Specifies a comma-separated list of targets to be excluded from the scan even if they are part of the overall network range you specify.
   The list you pass in uses normal Nmap syntax, so it can include hostnames, CIDR netblocks, octet ranges, etc. This can be useful when
   the network you wish to scan includes untouchable mission-critical servers, systems that are known to react adversely to port scans, or
   subnets administered by other people.
--excludefile exclude_file (Exclude list from file) .
   This offers the same functionality as the --exclude option, except that the excluded targets are provided in a newline-, space-, or
   tab-delimited exclude_file rather than on the command line.
   The exclude file may contain comments that start with # and extend to the end of the line.
*Host Discovery*
-Pn (No ping) .
   This option skips the Nmap discovery stage altogether. Normally, Nmap uses this stage to determine active machines for heavier scanning.
   By default, Nmap only performs heavy probing such as port scans, version detection, or OS detection against hosts that are found to be
   up. Disabling host discovery with -Pn causes Nmap to attempt the requested scanning functions against every target IP address specified.
   So if a class B target address space (/16) is specified on the command line, all 65,536 IP addresses are scanned. Proper host discovery
   is skipped as with the list scan, but instead of stopping and printing the target list, Nmap continues to perform requested functions as
   if each target IP is active. To skip ping scan and port scan, while still allowing NSE to run, use the two options -Pn -sn together.
   For machines on a local ethernet network, ARP scanning will still be performed (unless --disable-arp-ping or --send-ip is specified)
   because Nmap needs MAC addresses to further scan target hosts. In previous versions of Nmap, -Pn was -P0.  and -PN..
*-PS port list (TCP SYN Ping)*.
   This option sends an empty TCP packet with the SYN flag set. The default destination port is 80 (configurable at compile time by
   changing DEFAULT_TCP_PROBE_PORT_SPEC.  in nmap.h)..  Alternate ports can be specified as a parameter. The syntax is the same as for the
   -p except that port type specifiers like T: are not allowed. Examples are -PS22 and -PS22-25,80,113,1050,35000. Note that there can be
   no space between -PS and the port list. If multiple probes are specified they will be sent in parallel.
   The SYN flag suggests to the remote system that you are attempting to establish a connection. Normally the destination port will be
   closed, and a RST (reset) packet sent back. If the port happens to be open, the target will take the second step of a TCP
   three-way-handshake.  by responding with a SYN/ACK TCP packet. The machine running Nmap then tears down the nascent connection by
   responding with a RST rather than sending an ACK packet which would complete the three-way-handshake and establish a full connection.
   The RST packet is sent by the kernel of the machine running Nmap in response to the unexpected SYN/ACK, not by Nmap itself.
   Nmap does not care whether the port is open or closed. Either the RST or SYN/ACK response discussed previously tell Nmap that the host
   is available and responsive.
   On Unix boxes, only the privileged user root.  is generally able to send and receive raw TCP packets..  For unprivileged users, a
   workaround is automatically employed.  whereby the connect system call is initiated against each target port. This has the effect of
   sending a SYN packet to the target host, in an attempt to establish a connection. If connect returns with a quick success or an
   ECONNREFUSED failure, the underlying TCP stack must have received a SYN/ACK or RST and the host is marked available. If the connection
   attempt is left hanging until a timeout is reached, the host is marked as down.
*-PA port list (TCP ACK Ping)*.
   The TCP ACK ping is quite similar to the just-discussed SYN ping. The difference, as you could likely guess, is that the TCP ACK flag is
   set instead of the SYN flag. Such an ACK packet purports to be acknowledging data over an established TCP connection, but no such
   connection exists. So remote hosts should always respond with a RST packet, disclosing their existence in the process.
   The -PA option uses the same default port as the SYN probe (80) and can also take a list of destination ports in the same format. If an
   unprivileged user tries this, the connect workaround discussed previously is used. This workaround is imperfect because connect is
   actually sending a SYN packet rather than an ACK.
   The reason for offering both SYN and ACK ping probes is to maximize the chances of bypassing firewalls. Many administrators configure
   routers and other simple firewalls to block incoming SYN packets except for those destined for public services like the company web site
   or mail server. This prevents other incoming connections to the organization, while allowing users to make unobstructed outgoing
   connections to the Internet. This non-stateful approach takes up few resources on the firewall/router and is widely supported by
   hardware and software filters. The Linux Netfilter/iptables.  firewall software offers the --syn convenience option to implement this
   stateless approach. When stateless firewall rules such as this are in place, SYN ping probes (-PS) are likely to be blocked when sent to
   closed target ports. In such cases, the ACK probe shines as it cuts right through these rules.
   Another common type of firewall uses stateful rules that drop unexpected packets. This feature was initially found mostly on high-end
   firewalls, though it has become much more common over the years. The Linux Netfilter/iptables system supports this through the --state
   option, which categorizes packets based on connection state. A SYN probe is more likely to work against such a system, as unexpected ACK
   packets are generally recognized as bogus and dropped. A solution to this quandary is to send both SYN and ACK probes by specifying -PS
   and -PA.
*-PU port list (UDP Ping)*.
   Another host discovery option is the UDP ping, which sends a UDP packet to the given ports. For most ports, the packet will be empty,
   though some use a protocol-specific payload that is more likely to elicit a response.  The payload database is described at
   https://nmap.org/book/nmap-payloads.html..  --data, --data-string, and --data-length options.
   The port list takes the same format as with the previously discussed -PS and -PA options. If no ports are specified, the default is
   40125..  This default can be configured at compile-time by changing DEFAULT_UDP_PROBE_PORT_SPEC.  in nmap.h..  A highly uncommon port is
   used by default because sending to open ports is often undesirable for this particular scan type.
   Upon hitting a closed port on the target machine, the UDP probe should elicit an ICMP port unreachable packet in return. This signifies
   to Nmap that the machine is up and available. Many other types of ICMP errors, such as host/network unreachables or TTL exceeded are
   indicative of a down or unreachable host. A lack of response is also interpreted this way. If an open port is reached, most services
   simply ignore the empty packet and fail to return any response. This is why the default probe port is 40125, which is highly unlikely to
   be in use. A few services, such as the Character Generator (chargen) protocol, will respond to an empty UDP packet, and thus disclose to
   Nmap that the machine is available.
   The primary advantage of this scan type is that it bypasses firewalls and filters that only screen TCP. For example, I once owned a
   Linksys BEFW11S4 wireless broadband router. The external interface of this device filtered all TCP ports by default, but UDP probes
   would still elicit port unreachable messages and thus give away the device.
*-PY port list (SCTP INIT Ping)*.
   This option sends an SCTP packet containing a minimal INIT chunk. The default destination port is 80 (configurable at compile time by
   changing DEFAULT_SCTP_PROBE_PORT_SPEC.  in nmap.h). Alternate ports can be specified as a parameter. The syntax is the same as for the
   -p except that port type specifiers like S: are not allowed. Examples are -PY22 and -PY22,80,179,5060. Note that there can be no space
   between -PY and the port list. If multiple probes are specified they will be sent in parallel.
   The INIT chunk suggests to the remote system that you are attempting to establish an association. Normally the destination port will be
   closed, and an ABORT chunk will be sent back. If the port happens to be open, the target will take the second step of an SCTP
   four-way-handshake.  by responding with an INIT-ACK chunk. If the machine running Nmap has a functional SCTP stack, then it tears down
   the nascent association by responding with an ABORT chunk rather than sending a COOKIE-ECHO chunk which would be the next step in the
   four-way-handshake. The ABORT packet is sent by the kernel of the machine running Nmap in response to the unexpected INIT-ACK, not by
   Nmap itself.
   Nmap does not care whether the port is open or closed. Either the ABORT or INIT-ACK response discussed previously tell Nmap that the
   host is available and responsive.On Unix boxes, only the privileged user root.  is generally able to send and receive raw SCTP packets.. 
   Using SCTP INIT Pings is
   currently not possible for unprivileged users..
-*PE; -PP; -PM (ICMP Ping Types)*.
   In addition to the unusual TCP, UDP and SCTP host discovery types discussed previously, Nmap can send the standard packets sent by the
   ubiquitous ping program. Nmap sends an ICMP type 8 (echo request) packet to the target IP addresses, expecting a type 0 (echo reply) in
   return from available hosts..  Unfortunately for network explorers, many hosts and firewalls now block these packets, rather than
   responding as required by RFC 1122[2]..  For this reason, ICMP-only scans are rarely reliable enough against unknown targets over the
   Internet. But for system administrators monitoring an internal network, they can be a practical and efficient approach. Use the -PE
   option to enable this echo request behavior.
   While echo request is the standard ICMP ping query, Nmap does not stop there. The ICMP standards (RFC 792[3].  and RFC 950[4].  ) also
   specify timestamp request, information request, and address mask request packets as codes 13, 15, and 17, respectively. While the
   ostensible purpose for these queries is to learn information such as address masks and current times, they can easily be used for host
   discovery. A system that replies is up and available. Nmap does not currently implement information request packets, as they are not
   widely supported. RFC 1122 insists that a host SHOULD NOT implement these messages. Timestamp and address mask queries can be sent
   with the -PP and -PM options, respectively. A timestamp reply (ICMP code 14) or address mask reply (code 18) discloses that the host is
   available. These two queries can be valuable when administrators specifically block echo request packets while forgetting that other
   ICMP queries can be used for the same purpose.

-*PO protocol list (IP Protocol Ping)*.
   One of the newer host discovery options is the IP protocol ping, which sends IP packets with the specified protocol number set in their
   IP header. The protocol list takes the same format as do port lists in the previously discussed TCP, UDP and SCTP host discovery
   options. If no protocols are specified, the default is to send multiple IP packets for ICMP (protocol 1), IGMP (protocol 2), and
   IP-in-IP (protocol 4). The default protocols can be configured at compile-time by changing DEFAULT_PROTO_PROBE_PORT_SPEC.  in nmap.h.
   Note that for the ICMP, IGMP, TCP (protocol 6), UDP (protocol 17) and SCTP (protocol 132), the packets are sent with the proper protocol
   headers.  while other protocols are sent with no additional data beyond the IP header (unless any of --data, --data-string, or
   --data-length options are specified).This host discovery method looks for either responses using the same protocol as a probe, 
   or ICMP protocol unreachable messages which
   signify that the given protocol isn't supported on the destination host. Either type of response signifies that the target host is
   alive.
-*PR (ARP Ping)*.
   One of the most common Nmap usage scenarios is to scan an ethernet LAN. On most LANs, especially those using private address ranges
   specified by RFC 1918[5], the vast majority of IP addresses are unused at any given time. When Nmap tries to send a raw IP packet such
   as an ICMP echo request, the operating system must determine the destination hardware (ARP) address corresponding to the target IP so
   that it can properly address the ethernet frame. This is often slow and problematic, since operating systems weren't written with the
   expectation that they would need to do millions of ARP requests against unavailable hosts in a short time period.
   ARP scan puts Nmap and its optimized algorithms in charge of ARP requests. And if it gets a response back, Nmap doesn't even need to
   worry about the IP-based ping packets since it already knows the host is up. This makes ARP scan much faster and more reliable than
   IP-based scans. So it is done by default when scanning ethernet hosts that Nmap detects are on a local ethernet network. Even if
   different ping types (such as -PE or -PS) are specified, Nmap uses ARP instead for any of the targets which are on the same LAN. If you
   absolutely don't want to do an ARP scan, specify --disable-arp-ping.
   For IPv6 (-6 option), -PR uses ICMPv6 Neighbor Discovery instead of ARP. Neighbor Discovery, defined in RFC 4861, can be seen as the
   IPv6 equivalent of ARP.
--disable-arp-ping (No ARP or ND Ping) .
   Nmap normally does ARP or IPv6 Neighbor Discovery (ND) discovery of locally connected ethernet hosts, even if other host discovery
   options such as -Pn or -PE are used. To disable this implicit behavior, use the --disable-arp-ping option.
   The default behavior is normally faster, but this option is useful on networks using proxy ARP, in which a router speculatively replies
   to all ARP requests, making every target appear to be up according to ARP scan.
--traceroute (Trace path to host) .
   Traceroutes are performed post-scan using information from the scan results to determine the port and protocol most likely to reach the
   target. It works with all scan types except connect scans (-sT) and idle scans (-sI). All traces use Nmap's dynamic timing model and are
   performed in parallel.    
-n (No DNS resolution) .
   Tells Nmap to never do reverse DNS resolution on the active IP addresses it finds. Since DNS can be slow even with Nmap's built-in
   parallel stub resolver, this option can slash scanning times.

-R (DNS resolution for all targets) .
   Tells Nmap to always do reverse DNS resolution on the target IP addresses. Normally reverse DNS is only performed against responsive
   (online) hosts.
--system-dns (Use system DNS resolver) .
   By default, Nmap resolves IP addresses by sending queries directly to the name servers configured on your host and then listening for
   responses. Many requests (often dozens) are performed in parallel to improve performance. Specify this option to use your system
   resolver instead (one IP at a time via the getnameinfo call). This is slower and rarely useful unless you find a bug in the Nmap
   parallel resolver (please let us know if you do). The system resolver is always used for IPv6 scans.
--dns-servers server1[,server2[,...]]  (Servers to use for reverse DNS queries) .
   By default, Nmap determines your DNS servers (for rDNS resolution) from your resolv.conf file (Unix) or the Registry (Win32).
   Alternatively, you may use this option to specify alternate servers. This option is not honored if you are using --system-dns or an IPv6
   scan. Using multiple DNS servers is often faster, especially if you choose authoritative servers for your target IP space. This option
   can also improve stealth, as your requests can be bounced off just about any recursive DNS server on the Internet.
   This option also comes in handy when scanning private networks. Sometimes only a few name servers provide proper rDNS information, and
   you may not even know where they are. You can scan the network for port 53 (perhaps with version detection), then try Nmap list scans
   (-sL) specifying each name server one at a time with --dns-servers until you find one which works.

*Port Scanning techniques*
~~~~~~~~~~~~~~~~~~~~~~~~~
By default, Nmap performs a SYN Scan, though it substitutes a connect scan if the user does not have proper
privileges to send raw packets (requires root access on Unix). Of the scans listed in this section, unprivileged users can only execute
connect and FTP bounce scans.

*-sS (TCP SYN scan)*.
  SYN scan is the default and most popular scan option for good reasons. 
  It can be performed quickly, scanning thousands of ports persecond on a 
  fast network not hampered by restrictive firewalls. It is also relatively 
  unobtrusive and stealthy since it never completes TCP connections. SYN scan works against any compliant TCP stack rather than depending on idiosyncrasies of specific platforms as Nmap's FIN/NULL/Xmas, Maimon and idle scans do. It also allows clear, reliable differentiation between the open, closed, and filtered states.This technique is often referred to as half-open scanning, because you don't open a full TCP connection. You send a SYN packet, as ifyou are going to open a real connection and then wait for a response. A SYN/ACK indicates the port is listening (open), while a RST(reset) is indicative of a non-listener. If no response is received after several retransmissions, the port is marked as filtered. Theport is also marked filtered if an ICMP unreachable error (type 3, code 0, 1, 2, 3, 9, 10, or 13) is received. The port is alsoconsidered open if a SYN packet (without the ACK flag) is received in response. This can be due to an extremely rare TCP feature known
  as a simultaneous open or split handshake connection (see https://nmap.org/misc/split-handshake.pdf).

*-sT (TCP connect scan)*.
  TCP connect scan is the default TCP scan type when SYN scan is not an option. This is the case when a user does not have raw packetprivileges. Instead of writing raw packets as most other scan types do, Nmap asks the underlying operating system to establish a connection with the target machine and port by issuing the connect system call. This is the same high-level system call that web browsers, P2P clients, and most other network-enabled applications use to establish a connection. It is part of a programming interface known as the Berkeley Sockets API. Rather than read raw packet responses off the wire, Nmap uses this API to obtain status information on each connection attempt.
  When SYN scan is available, it is usually a better choice. Nmap has less control over the high level connect call than with raw packets, making it less efficient. The system call completes connections to open target ports rather than performing the half-open reset that SYN scan does. Not only does this take longer and require more packets to obtain the same information, but target machines are more likely to log the connection. A decent IDS will catch either, but most machines have no such alarm system. Many services on your average Unix system will add a note to syslog, and sometimes a cryptic error message, when Nmap connects and then closes the connection without sending data. Truly pathetic services crash when this happens, though that is uncommon. An administrator who sees a bunch of connection
  attempts in her logs from a single system should know that she has been connect scanned.

*-sU (UDP scans)*.
  While most popular services on the Internet run over the TCP protocol, UDP[6] services are widely deployed. DNS, SNMP, and DHCP (registered ports 53, 161/162, and 67/68) are three of the most common. Because UDP scanning is generally slower and more difficult than TCP, some security auditors ignore these ports. This is a mistake, as exploitable UDP services are quite common and attackers certainly don't ignore the whole protocol. Fortunately, Nmap can help inventory UDP ports.
  UDP scan is activated with the -sU option. It can be combined with a TCP scan type such as SYN scan (-sS) to check both protocols during the same run.UDP scan works by sending a UDP packet to every targeted port. For some common ports such as 53 and 161, a protocol-specific payload is sent to increase response rate, but for most ports the packet is empty unless the --data, --data-string, or --data-length options are specified. If an ICMP port unreachable error (type 3, code 3) is returned, the port is closed. Other ICMP unreachable errors (type 3, codes 0, 1, 2, 9, 10, or 13) mark the port as filtered. Occasionally, a service will respond with a UDP packet, proving that it is open. If no response is received after retransmissions, the port is classified as open|filtered. This means that the port could be open, or
  perhaps packet filters are blocking the communication. Version detection (-sV) can be used to help differentiate the truly open ports from the filtered ones. A big challenge with UDP scanning is doing it quickly. Open and filtered ports rarely send any response, leaving Nmap to time out and then conduct retransmissions just in case the probe or response were lost. Closed ports are often an even bigger problem. They usually send back an ICMP port unreachable error. But unlike the RST packets sent by closed TCP ports in response to a SYN or connect scan, many hosts rate limit.  ICMP port unreachable messages by default. Linux and Solaris are particularly strict about this. For example, the Linux 2.4.20 kernel limits destination unreachable messages to one per second (in net/ipv4/icmp.c). Nmap detects rate limiting and slows down accordingly to avoid flooding the network with useless packets that the target machine will
  drop. Unfortunately, a Linux-style limit of one packet per second makes a 65,536-port scan take more than 18 hours. Ideas for speeding your UDP scans up include scanning more hosts in parallel, doing a quick scan of just the popular ports first, scanning from behind the firewall, and using --host-timeout to skip slow hosts.
*-sY (SCTP INIT scan)*.
  SCTP[7] is a relatively new alternative to the TCP and UDP protocols, combining most characteristics of TCP and UDP, and also adding new features like multi-homing and multi-streaming. It is mostly being used for SS7/SIGTRAN related services but has the potential to be used for other applications as well. SCTP INIT scan is the SCTP equivalent of a TCP SYN scan. It can be performed quickly, scanning thousands of ports per second on a fast network not hampered by restrictive firewalls. Like SYN scan, INIT scan is relatively unobtrusive and stealthy, since it never completes SCTP associations. It also allows clear, reliable differentiation between the open,
  closed, and filtered states. This technique is often referred to as half-open scanning, because you don't open a full SCTP association. You send an INIT chunk, as if you are going to open a real association and then wait for a response. An INIT-ACK chunk indicates the port is listening (open), while
  an ABORT chunk is indicative of a non-listener. If no response is received after several retransmissions, the port is marked as filtered. The port is also marked filtered if an ICMP unreachable error (type 3, code 0, 1, 2, 3, 9, 10, or 13) is received. *-sN; -sF; -sX (TCP NULL, FIN, and Xmas scans)*.
  These three scan types (even more are possible with the --scanflags option described in the next section) exploit a subtle loophole in the TCP RFC[8] to differentiate between open and closed ports. Page 65 of RFC 793 says that if the [destination] port state is CLOSED .... an incoming segment not containing a RST causes a RST to be sent in response.  Then the next page discusses packets sent to open ports without the SYN, RST, or ACK bits set, stating that: you are unlikely to get here, but if you do, drop the segment, and return. When scanning systems compliant with this RFC text, any packet not containing SYN, RST, or ACK bits will result in a returned RST if the
  port is closed and no response at all if the port is open. As long as none of those three bits are included, any combination of the other three (FIN, PSH, and URG) are OK. Nmap exploits this with three scan types:
Null scan (-sN): 
  Does not set any bits (TCP flag header is 0) 
  FIN scan (-sF) :
  Sets just the TCP FIN bit.
  Xmas scan (-sX):
  Sets the FIN, PSH, and URG flags, lighting the packet up like a Christmas tree.
  These three scan types are exactly the same in behavior except for the TCP flags set in probe packets. If a RST packet is received, the
  port is considered closed, while no response means it is open|filtered. The port is marked filtered if an ICMP unreachable error (type
  3, code 0, 1, 2, 3, 9, 10, or 13) is received.
  The key advantage to these scan types is that they can sneak through certain non-stateful firewalls and packet filtering routers.
  Another advantage is that these scan types are a little more stealthy than even a SYN scan. Don't count on this though-most modern IDS
  products can be configured to detect them. The big downside is that not all systems follow RFC 793 to the letter. A number of systems
  send RST responses to the probes regardless of whether the port is open or not. This causes all of the ports to be labeled closed. Major
  operating systems that do this are Microsoft Windows, many Cisco devices, BSDI, and IBM OS/400. This scan does work against most
  Unix-based systems though. Another downside of these scans is that they can't distinguish open ports from certain filtered ones, leaving
  you with the response open|filtered.
  *-sA (TCP ACK scan)*.
  This scan is different than the others discussed so far in that it never determines open (or even open|filtered) ports. It is used to
  map out firewall rulesets, determining whether they are stateful or not and which ports are filtered.
  The ACK scan probe packet has only the ACK flag set (unless you use --scanflags). When scanning unfiltered systems, open and closed
  ports will both return a RST packet. Nmap then labels them as unfiltered, meaning that they are reachable by the ACK packet, but whether they are open or closed is undetermined. Ports that don't respond, or send certain ICMP error messages back (type 3, code 0, 1, 2, 3, 9, 10, or 13), are labeled filtered.
  *-sW (TCP Window scan)*.
  Window scan is exactly the same as ACK scan except that it exploits an implementation detail of certain systems to differentiate open ports from closed ones, rather than always printing unfiltered when a RST is returned. It does this by examining the TCP Window field of the RST packets returned. On some systems, open ports use a positive window size (even for RST packets) while closed ones have a zero window. So instead of always listing a port as unfiltered when it receives a RST back, Window scan lists the port as open or closed if the TCP Window value in that reset is positive or zero, respectively.This scan relies on an implementation detail of a minority of systems out on the Internet, so you can't always trust it. Systems that don't support it will usually return all ports closed. Of course, it is possible that the machine really has no open ports. If most scanned ports are closed but a few common port numbers (such as 22, 25, 53) are filtered, the system is most likely susceptible. Occasionally, systems will even show the exact opposite behavior. If your scan shows 1,000 open ports and three closed or filtered ports, then those three may very well be the truly open ones.
  *-sM (TCP Maimon scan)*.
  The Maimon scan is named after its discoverer, Uriel Maimon..  He described the technique in Phrack Magazine issue #49 (November 1996).. Nmap, which included this technique, was released two issues later. This technique is exactly the same as NULL, FIN, and Xmas scans, except that the probe is FIN/ACK. According to RFC 793[8] (TCP), a RST packet should be generated in response to such a probe whether the port is open or closed. However, Uriel noticed that many BSD-derived systems simply drop the packet if the port is open.
*--scanflags (Custom TCP scan)*.
  Truly advanced Nmap users need not limit themselves to the canned scan types offered. The --scanflags option allows you to design your own scan by specifying arbitrary TCP flags..  Let your creative juices flow, while evading intrusion detection systems.  whose vendors simply paged through the Nmap man page adding specific rules!
  The --scanflags argument can be a numerical flag value such as 9 (PSH and FIN), but using symbolic names is easier. Just mash together any combination of URG, ACK, PSH, RST, SYN, and FIN. For example, --scanflags URGACKPSHRSTSYNFIN sets everything, though it's not very useful for scanning. The order these are specified in is irrelevant.
  In addition to specifying the desired flags, you can specify a TCP scan type (such as -sA or -sF). That base type tells Nmap how to interpret responses. For example, a SYN scan considers no-response to indicate a filtered port, while a FIN scan treats the same as open|filtered. Nmap will behave the same way it does for the base scan type, except that it will use the TCP flags you specify instead. If you don't specify a base type, SYN scan is used.
  *-sZ (SCTP COOKIE ECHO scan)*. SCTP COOKIE ECHO scan is a more advanced SCTP scan. It takes advantage of the fact that SCTP implementations should silently drop packets containing COOKIE ECHO chunks on open ports, but send an ABORT if the port is closed. The advantage of this scan type is that it is not as obvious a port scan than an INIT scan. Also, there may be non-stateful firewall rulesets blocking INIT chunks, but not COOKIE. ECHO chunks. Don't be fooled into thinking that this will make a port scan invisible; a good IDS will be able to detect SCTP COOKIE ECHO
  scans too. The downside is that SCTP COOKIE ECHO scans cannot differentiate between open and filtered ports, leaving you with the state open|filtered in both cases.
  *-sI zombie host[:probeport] (idle scan)*.
  This advanced scan method allows for a truly blind TCP port scan of the target (meaning no packets are sent to the target from your real IP address). Instead, a unique side-channel attack exploits predictable IP fragmentation ID sequence generation on the zombie host to glean information about the open ports on the target. IDS systems will display the scan as coming from the zombie machine you specify (which must be up and meet certain criteria).  This fascinating scan type is too complex to fully describe in this reference guide, so wrote and posted an informal paper with full details at https://nmap.org/book/idlescan.html. Besides being extraordinarily stealthy (due to its blind nature), this scan type permits mapping out IP-based trust relationships between machines. The port listing shows open ports from the perspective of the zombie host.  So you can try scanning a target using various zombies that you think might be trusted.  (via router/packet filter rules). You can add a colon followed by a port number to the zombie host if you wish to probe a particular port on the zombie for IP ID changes.Otherwise Nmap will use the port it uses by default for TCP pings (80).

*-sO (IP protocol scan)*. IP protocol scan allows you to determine which IP protocols (TCP, ICMP, IGMP, etc.) are supported by target machines. This isn't technically a port scan, since it cycles through Ip protocol
