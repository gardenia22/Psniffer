#-------------------------------------------------------------------------------
# Name:        Psniffer.py
#
# Author:      Gardenia22
#
# Created:     10/21/2014
# Copyright:   (c) Gardenia22 2014
#
#-------------------------------------------------------------------------------

from ctypes import *
from winpcapy import *
import time
import threading
import data
## ip_address struct
class ip_address(Structure):
    _fields_ = [('byte1', u_char),
                ('byte2', u_char),
                ('byte3', u_char),
                ('byte4', u_char)]


def Interfaces():#List all the interfaces
    
    alldevs=POINTER(pcap_if_t)()
    errbuf= create_string_buffer(PCAP_ERRBUF_SIZE)
    res = []
    ## Retrieve the device list
    if (pcap_findalldevs(byref(alldevs), errbuf) == -1):
        res = []
        #print ("Error in pcap_findalldevs: %s\n" % errbuf.value)
        #sys.exit(1)
    
    d = alldevs.contents
    i = 0
    res = []
    while d:
        i=i+1
        devs = ("%d. %s" % (i, d.name))
        if (d.description):
            devs = devs+'\n'+(" (%s)\n" % (d.description))

        else:
            devs = devs+'\n'+(" (No description available)\n")
        res.append(devs)
        if d.next:
            d=d.next.contents
        else:
            d=False
    pcap_freealldevs(alldevs)
    return res

class Captures(threading.Thread):
    def __init__(self,f,devs):
        threading.Thread.__init__(self)
        self.f = f
        self.flag = True
        self.devs = devs
        
    def stop(self):
        self.flag = False
        #print "stop"
    def run(self):
        filters = self.f.filters
        header = POINTER(pcap_pkthdr)()
        pkt_data = POINTER(c_ubyte)()
        alldevs=POINTER(pcap_if_t)()
        errbuf= create_string_buffer(PCAP_ERRBUF_SIZE)

        ## Retrieve the device list
        if (pcap_findalldevs(byref(alldevs), errbuf) == -1):
            print ("Error in pcap_findalldevs: %s\n" % errbuf.value)
            sys.exit(1)
                
        ## open the devs
        d=alldevs
        for i in range(0,self.devs-1):
            d=d.contents.next
        d=d.contents
        dev = ("%d. %s" % (i, d.name))
        if (d.description):
            dev = dev+'\n'+(" (%s)\n" % (d.description))

        else:
            dev = dev+'\n'+(" (No description available)\n")
        adhandle = pcap_open_live(d.name,65536,1,1000,errbuf)
        if (adhandle == None):
            print("\nUnable to open the adapter. %s is not supported by Pcap-WinPcap\n" % d.contents.name)
            ## Free the device list
            pcap_freealldevs(alldevs)
            sys.exit(-1)
        pcap_freealldevs(alldevs)
        ## set the filters
        fcode = bpf_program()
        NetMask = 0xffffff
        
         
        ## compile the filter
        if pcap_compile(adhandle,byref(fcode),filters,1,NetMask) < 0:
            print('\nError compiling filter: wrong syntax.\n')
            pcap_close(adhandle)
            sys.exit(-3)
         
        ## set the filter
         
        if pcap_setfilter(adhandle,byref(fcode)) < 0:
            print('\nError setting the filter\n')
            pcap_close(adhandle)
            sys.exit(-4)

        res=pcap_next_ex( adhandle, byref(header), byref(pkt_data))
        #while(res >= 0 and self.flag and self.f.packetCounts<5000):
        while(res >= 0 and self.flag):
            if(res == 0):
                # Timeout elapsed
                break
            ## convert the timestamp to readable format
            local_tv_sec = header.contents.ts.tv_sec
            ltime=time.localtime(local_tv_sec);
            timestr=time.strftime("%H:%M:%S", ltime)
            #print
            #print("%s,%.6d len:%d" % (timestr, header.contents.ts.tv_usec, header.contents.len))
            frameHead = {
                "Frame Number":self.f.PacketCount(), 
                "Arrive Time":timestr, 
                "Interface Name":dev,
                "Frame Length":header.contents.len
                }
            #print pkt_data[:14]
            packet = []
            for i in range(0,header.contents.len):
                packet.append(pkt_data[i])
            
            self.AnalyzePacket(packet,frameHead)


            res=pcap_next_ex( adhandle, byref(header), byref(pkt_data))
            #print
            #print(pkt_data[0:header.contents.len])
        if(res == -1):
            print("Error reading the packets: %s\n", pcap_geterr(adhandle));
            sys.exit(-1)
        pcap_close(adhandle)
    def AnalyzePacket(self,packet,frameHead):
        self.f.packets.append(packet)
        ## extract src MAC address
        packetHead = []
        packetHead.append(["Frame Information",frameHead])
        src = "%.2x" % packet[0]
        for i in range(1,6):
            src += ":%.2x" % packet[i]
        
        ## extract dst MAC address
        dst = "%.2x" % packet[6]
        for i in range(7,12):
            dst += ":%.2x" % packet[i]
        
        ## extract protocol
        proto = "0x%.4x" % ((packet[12]<<8)+packet[13])
        etherHead = {
            "Source":src,
            "Destination":dst
            }
        if proto in data.etherType:
            etherHead["Protocol Type"] = data.etherType[proto]
        else:
            etherHead["Protocol Type"] = "Unknown Ethernet Protocol"
        packetHead.append(["Ethernet Information",etherHead])
        
        item = [
            frameHead["Frame Number"],
            frameHead["Arrive Time"],
            etherHead["Source"],
            etherHead["Destination"],
            frameHead["Frame Length"],
            etherHead["Protocol Type"]
            ]
        

        ## analyze ipv4 header
        if proto == "0x0800":
            ipv4Head = {
                "Version":packet[14]>>4,
                "Internet Header Length(IHL)":packet[14] % 16,
                "Differentiated Services Code Point (DSCP)":packet[15]>>2,
                "Explicit Congestion Notification (ECN)":packet[15] % 4,
                "Total Length":(packet[16]<<8)+packet[17],
                "Identification":(packet[18]<<8)+packet[19],
                "Flags":packet[20]>>5,
                "Fragment Offset":((packet[20] % 32)<<8)+packet[21],
                "Time To Live (TTL)":packet[22],
                "Header Checksum":(packet[24]<<8)+packet[25],
                "Source IP Address":"%d.%d.%d.%d" % (packet[26], packet[27], packet[28], packet[29] ),
                "Destination IP Address":"%d.%d.%d.%d" % (packet[30], packet[31], packet[32], packet[33] ),
            }
            ipv4proto = "0x%.2x" % packet[23]
            if ipv4proto in data.ipv4Type:
                ipv4Head["Protocol"] = data.ipv4Type[ipv4proto]
            else:
                ipv4Head["Protocol"] = "Unknown IPv4 Protocol"
            ds = 34
            if ipv4Head["Internet Header Length(IHL)"] > 5:
                ipv4Head["Copied"] = packet[34]>>7
                ipv4Head["Option Class"] = (packet[34]>>5) % 4
                ipv4Head["Option Number"] = packet[34] % 32
                ipv4Head["Option Length"] = packet[35]
                ds = 36
            packetHead.append(["IPv4 Information",ipv4Head]) 
            item[2] = ipv4Head["Source IP Address"]
            item[3] = ipv4Head["Destination IP Address"]
            item[5] = ipv4Head["Protocol"]
            ## analyze UDP header
            if (ipv4proto)=="0x11":
                udpHead = {
                    "Source port number":(packet[ds]<<8)+packet[ds+1],
                    "Destination port number":(packet[ds+2]<<8)+packet[ds+3],
                    "Length":(packet[ds+4]<<8)+packet[ds+5],
                    "Checksum":(packet[ds+6]<<8)+packet[ds+7]
                }
                packetHead.append(["UDP Information",udpHead])
            ## analyze TCP header
            if (ipv4proto)=="0x06":
                tcpHead = {
                    "Source port number":(packet[ds]<<8)+packet[ds+1],
                    "Destination port number":(packet[ds+2]<<8)+packet[ds+3],
                    "Sequence number":(((packet[ds+4]<<8)+packet[ds+5])<<16)+(packet[ds+6]<<8)+packet[ds+7],
                    "Acknowledgment number (if ACK set)":(((packet[ds+8]<<8)+packet[ds+9])<<16)+(packet[ds+10]<<8)+packet[ds+11],
                    "Data offset":packet[ds+12]>>4,
                    "Reserved":(packet[ds+12] % 16)>>1,
                    "NS":(packet[ds+12] & 1),
                    "CWR":(packet[ds+13] & 0x80) and 1,
                    "ECE":(packet[ds+13] & 0x40) and 1,
                    "URG":(packet[ds+13] & 0x20) and 1,
                    "ACK":(packet[ds+13] & 0x10) and 1,
                    "PSH":(packet[ds+13] & 0x08) and 1,
                    "RST":(packet[ds+13] & 0x04) and 1,
                    "SYN":(packet[ds+13] & 0x02) and 1,
                    "FIN":(packet[ds+13] & 0x01) and 1,
                    "Window size":(packet[ds+14]<<8)+packet[ds+15],
                    "Checksum":(packet[ds+16]<<8)+packet[ds+17],
                    "Urgent pointer":(packet[ds+18]<<8)+packet[ds+19],
                }
                packetHead.append(["TCP Information",tcpHead])

        ## analyze ipv6 header
        if proto == "0x86dd":
            ipv6Head = {
                "Version":packet[14]>>4,
                "Traffic Class":((packet[14] % 16)<<4)+(packet[15]>>4),
                "Flow Label":((packet[15] % 16)<<12)+(packet[16]<<8)+packet[17],
                "Payload Length":(packet[18]<<8)+packet[19],
                "Hop Limit":packet[21],
                "Source Address":"%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x" % (
                    packet[22],packet[23],packet[24],packet[25],packet[26],packet[27],packet[28],packet[29],
                    packet[30],packet[31],packet[32],packet[33],packet[34],packet[35],packet[36],packet[37]
                    ),
                "Destination Address":"%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x" % (
                    packet[38],packet[39],packet[40],packet[41],packet[42],packet[43],packet[44],packet[45],
                    packet[46],packet[47],packet[48],packet[49],packet[50],packet[51],packet[52],packet[53]
                    )
            }
            ipv6proto = "0x%.2x" % packet[20]
            if ipv6proto in data.ipv4Type:
                ipv6Head["Next Header"] = data.ipv4Type[ipv6proto]
            else:
                ipv6Head["Next Header"] = "Unknown Ipv6 protocol"
            packetHead.append(["IPv6 Information",ipv6Head]) 
            item[2] = ipv6Head["Source Address"]
            item[3] = ipv6Head["Destination Address"]
            item[5] = ipv6Head["Next Header"]
            ds = 54
            ## analyze UDP header
            if (ipv6proto)=="0x11":
                udpHead = {
                    "Source port number":(packet[ds]<<8)+packet[ds+1],
                    "Destination port number":(packet[ds+2]<<8)+packet[ds+3],
                    "Length":(packet[ds+4]<<8)+packet[ds+5],
                    "Checksum":(packet[ds+6]<<8)+packet[ds+7]
                }
                packetHead.append(["UDP Information",udpHead])
            ## analyze TCP header
            if (ipv6proto)=="0x06":
                tcpHead = {
                    "Source port number":(packet[ds]<<8)+packet[ds+1],
                    "Destination port number":(packet[ds+2]<<8)+packet[ds+3],
                    "Sequence number":(((packet[ds+4]<<8)+packet[ds+5])<<16)+(packet[ds+6]<<8)+packet[ds+7],
                    "Acknowledgment number (if ACK set)":(((packet[ds+8]<<8)+packet[ds+9])<<16)+(packet[ds+10]<<8)+packet[ds+11],
                    "Data offset":packet[ds+12]>>4,
                    "Reserved":(packet[ds+12] % 16)>>1,
                    "NS":(packet[ds+12] & 1),
                    "CWR":(packet[ds+13] & 0x80) and 1,
                    "ECE":(packet[ds+13] & 0x40) and 1,
                    "URG":(packet[ds+13] & 0x20) and 1,
                    "ACK":(packet[ds+13] & 0x10) and 1,
                    "PSH":(packet[ds+13] & 0x08) and 1,
                    "RST":(packet[ds+13] & 0x04) and 1,
                    "SYN":(packet[ds+13] & 0x02) and 1,
                    "FIN":(packet[ds+13] & 0x01) and 1,
                    "Window size":(packet[ds+14]<<8)+packet[ds+15],
                    "Checksum":(packet[ds+16]<<8)+packet[ds+17],
                    "Urgent pointer":(packet[ds+18]<<8)+packet[ds+19],
                }
                packetHead.append(["TCP Information",tcpHead])

        ## analyze ARP header
        if proto == "0x0806":
            arpHead = {
                "Hardware type (HTYPE)":(packet[14]<<8)+packet[15],
                "Protocol type (PTYPE)":(packet[16]<<8)+packet[17],
                "Hardware length (HLEN)":packet[18],
                "Protocol length (PLEN)":packet[19],
                "Operation":(packet[20]<<8)+packet[21],
                "Sender hardware address (SHA)":"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
                    packet[22],packet[23],packet[24],packet[25],packet[26],packet[27]
                    ),
                "Sender protocol address (SPA)":"%d.%d.%d.%d" % (
                    packet[28],packet[29],packet[30],packet[31]
                    ),
                "Target hardware address (THA)":"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
                    packet[32],packet[33],packet[34],packet[35],packet[36],packet[37]
                    ),
                "Target protocol address (TPA)":"%d.%d.%d.%d" % (
                    packet[38],packet[39],packet[40],packet[41]
                    ),
            }
            packetHead.append(["ARP Information",arpHead])
        self.f.packetHeads.append(packetHead)
        #print the item basic information into list
        self.f.AddListItem(item)
        #counts the protocol
        if item[5] in self.f.protocolStats:
            self.f.protocolStats[item[5]] += 1
        else:
            self.f.protocolStats[item[5]] = 1
        if proto == "0x86dd" or proto == "0x0800":
            self.f.ipCounts += 1
            if item[2] in self.f.sourceStats:
                self.f.sourceStats[item[2]] += 1
            else:
                self.f.sourceStats[item[2]] = 1
            if item[3] in self.f.destinationStats:
                self.f.destinationStats[item[3]] += 1
            else:
                self.f.destinationStats[item[3]] = 1