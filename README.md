Psniffer
========
This is a project from my course that requires us building a GUI program with basic functions of a sniffer by using [winpcap](www.winpcap.org/) library.

Psniffer is a GUI sniffer wrritten by Python using wxPython, winpcapy and matplotlib.

#Requirement:
* [wxPython]( http://www.wxpython.org/)
* [matplotlib](http://matplotlib.org/)
* [winpcapy](https://code.google.com/p/winpcapy/)

#Run Psniffer:
```
$python Psniffer.py
```

#Functions:

* list all network interfaces
* set filters before capturing 
* capture network packets
* analyze Protocol heads of packets(support IPv4, IPv6, TCP, UDP and ARP)
* view bytes of packets(support Hex and Char)
* protocol and IP stats
* save captured packets in JSON format

#Instructions:

* Select Interfaces where you want to capture packets
* Use Filters to select the type of packets you want to capture
* Start capture packets by clicking on Start in Capture Menu or 
the Start Icon in Toolbar
* Stop capture packets by clicking on Stop in Capture Menu or 
the Stop Icon in Toolbar
* Select captured packet in the list, then the detail head 
information and packet bytes will show bellow
* Click Save to save the detail head information and packet bytes 
in JSON format
* Use Stats to see the protocol and IP statistics
