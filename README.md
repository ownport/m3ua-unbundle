m3ua-unbundle
=============

**Warning! [ownport/m3ua-unbundle](https://github.com/ownport/m3ua-unbundle) repository is deprecated and not supported any more. For latest version of m3ua-unbundle.py script please use [ownport/wireshark-tools](https://github.com/ownport/wireshark-pytools) repository**



Python script allows to unbundle M3UA messages from IP packet.

According to RFC 2960 more than one messages may be carried in the same SCTP packet. It's good to minimize overhead but the analysis of SIGTRAN trace can be not so easy.

For example, we have wireshark trace with M3UA packets inside. Each SCTP packet in this trace contains more than few M3UA messages.

```
--------------------------- Packet 1
Internet Protocol Version 4, Src: 10.10.10.10 (10.10.10.10), Dst: 11.11.11.11 (11.11.11.11)
Stream Control Transmission Protocol, Src Port: m3ua (2905), Dst Port: 31697 (31697)
MTP 3 User Adaptation Layer
Signalling Connection Control Part
BSSAP
GSM A-I/F DTAP - Connect
Stream Control Transmission Protocol
MTP 3 User Adaptation Layer
Signalling Connection Control Part
Stream Control Transmission Protocol
MTP 3 User Adaptation Layer
Signalling Connection Control Part
BSSAP
GSM A-I/F DTAP - Call Proceeding
Stream Control Transmission Protocol
MTP 3 User Adaptation Layer
Signalling Connection Control Part
BSSAP
GSM A-I/F DTAP - Release
Stream Control Transmission Protocol
MTP 3 User Adaptation Layer
Signalling Connection Control Part
BSSAP
GSM A-I/F DTAP - Facility
Stream Control Transmission Protocol
MTP 3 User Adaptation Layer
Signalling Connection Control Part
Stream Control Transmission Protocol
MTP 3 User Adaptation Layer
Signalling Connection Control Part
BSSAP
GSM A-I/F BSSMAP - Paging
Stream Control Transmission Protocol
MTP 3 User Adaptation Layer
Signalling Connection Control Part
Stream Control Transmission Protocol
MTP 3 User Adaptation Layer
Signalling Connection Control Part
BSSAP
GSM A-I/F BSSMAP - Cipher Mode Command
```

That's just only one packet. After selection all messages for one call or transaction you will get much more information. Extra information, which are not needed for analysis, which are related to another events.

m3ua-unbundle script allows you to solve this issue. It's unbundle all messages which are higher that M3UA layer, convert them to MTP3 layer and create as single packets

```
--------------------------- Packet 1
Message Transfer Part Level 3
Signalling Connection Control Part
BSSAP
GSM A-I/F DTAP - Connect
Stream Control Transmission Protocol

--------------------------- Packet 2
Message Transfer Part Level 3
Signalling Connection Control Part
BSSAP
GSM A-I/F DTAP - Call Proceeding

--------------------------- Packet 3
Message Transfer Part Level 3
Signalling Connection Control Part
BSSAP
GSM A-I/F DTAP - Release

--------------------------- Packet 4
Message Transfer Part Level 3
Signalling Connection Control Part
BSSAP
GSM A-I/F DTAP - Facility

--------------------------- Packet 5
Message Transfer Part Level 3
Signalling Connection Control Part
BSSAP
GSM A-I/F BSSMAP - Paging

--------------------------- Packet 6
Message Transfer Part Level 3
Signalling Connection Control Part
BSSAP
GSM A-I/F BSSMAP - Cipher Mode Command
```

**Note:** Convertion from SCTP/M3UA to MTP3 layer can save around 50% of file size due to removing overhead of these layers.

**Hint:** If you need to analyze big traces, better to split it by amount of packets
```
# editcap -c <amount of packets> <source_trace.pcap> <prefix>
```

Installation
------------

`tshark` and `text2pcap` should be installed in your system, then just copy m3ua-unbundle.py. 

How to use
----------

```
tshark -x -r <source.pcap> | python m3ua-unbundle.py  | text2pcap -l141 -t "%H:%M:%S." - <result.pcap>
```

Similar projects
----------------
* [SCTP unbundle](http://frox25.no-ip.org/~mtve/wiki/SctpDechunk.html)

Links
---------
- [Wireshark]<http://www.wireshark.org/>

