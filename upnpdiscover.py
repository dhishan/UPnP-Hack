from scapy.all import *
from threading import Thread
import re
# import inspect
# import threading


DSTMAC = '01:00:5e:7f:ff:fa' #  IP of 239.255.255.250 converted
UDPDST = 1900
httpumsg = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 10\r\nST: ssdp:all\r\n\r\n"
out = []
locations = []


def _upnp_discovery():
    pkt = Ether(src=get_if_hwaddr(ifn),dst=DSTMAC)/IP(src=ip_src,dst='239.255.255.250')/UDP(sport=15000,dport=UDPDST)/httpumsg
    print pkt.show()
    sendp(pkt,iface=ifn,verbose=1)


def _isvalidpkt(packet):
    global out
    if not hasattr(_isvalidpkt,"ip"):
        _isvalidpkt.ip = []
    if packet.haslayer(IP):
        ip_new = packet.getlayer(IP).src
        if ip_new not in _isvalidpkt.ip:
            out.append(packet)
            _isvalidpkt.ip.append(ip_new)
    return packet.show()

_isvalidpkt.ip = []


def _upnp_sniff():
    lfil = lambda(r): r.haslayer(UDP) and (r[UDP].sport == 1900)
    sniff(prn=_isvalidpkt,iface=ifn,store=1,lfilter=lfil,timeout=10)
    global out
    if out:
        for pkt in out:
            print pkt.summary()
            val = pkt.getlayer(UDP)
            pkt_raw = val[Raw].load
            print pkt_raw
            locations.append(_extract_loc(pkt_raw))
    return


def _extract_loc(raw_data):
    regex = r"^Location:(.*)\r"
    res = re.findall(regex,raw_data,re.MULTILINE | re.I)
    return res[0].strip()


t1 = Thread(name="sender",target=_upnp_discovery)
t2 = Thread(name="listener",target=_upnp_sniff)
