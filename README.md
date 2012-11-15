m3ua-unbundle
=============

Python script allows to unbundle M3UA messages from IP packet

Installation
------------

[tshark] and [text2pcap] should be installed in your system, then just copy m3ua-unbundle.py

How to use
----------

```
tshark -x -r <source.pcap> | python m3ua-unbundle.py  | text2pcap -l141 -t "%H:%M:%S." - <result.pcap>
```


Similar projects
----------------
* [SCTP unbundle](http://frox25.no-ip.org/~mtve/wiki/SctpDechunk.html)
