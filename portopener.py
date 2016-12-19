import sys
sys.path.inse rt(0,"/Library/Python/2.6/site-packages")
import upnpdiscover as ud
from urlparse import urlparse, urljoin
import urllib2
import funcs
import requests

if len(sys.argv) is not 2:
    print "Pass the interface for upnp discovery"


ud.ifn = sys.argv[1]
ud.ip_src = funcs.get_ip(sys.argv[1])

ud.t2.start()
ud.t1.start()
ud.t1.join()
ud.t2.join()
print ud.locations

urlloclist = []
for loc in ud.locations:
    urlloclist.append(urlparse(loc))

igd_profile = None
igd_url = None

# Get IGDs
for urls in urlloclist:
    req = urllib2.Request(urls.geturl())
    res = urllib2.urlopen(req)
    xml_f = res.read()
    if funcs.is_igd(xml_f):
        igd_profile = xml_f
        igd_url = urls
    res.close()


# print igd_url
if not igd_url:
    print "No IGD profiles"
    sys.exit()
control_url, upnp_schema = funcs.parse_igd_profile(igd_profile)
print control_url, upnp_schema

soap_url = urljoin(igd_url.geturl(),control_url)


header = funcs.get_soap_header(upnp_schema,'GetGenericPortMappingEntry')
status = True
ind = 0
while status:
    body = funcs.get_soap_body(upnp_schema,'GetGenericPortMappingEntry',arguments=[('NewPortMappingIndex','{0}'.format(ind))])
    r = requests.post(soap_url,headers=header,data=body)
    if r.status_code != 200:
        status = False
        break
    funcs.parse_port_mapping(r.text)
    ind += 1

# arguments = [
#     ('NewRemoteHost','0.0.0.0'),
#     ('NewExternalPort', str(4000)),           # specify port on router
#     ('NewProtocol', 'TCP'),                 # specify protocol
#     ('NewInternalPort', str(4000)),           # specify port on internal host
#     ('NewInternalClient', '192.168.0.20'),  # specify IP of internal host
#     ('NewEnabled', '1'),                    # turn mapping ON
#     ('NewPortMappingDescription', 'UPnP Port Mapping Exploit'),  # add a description
#     ('NewLeaseDuration', '0')]              # how long should it be
# body_set = funcs.get_soap_body(action='AddPortMapping',upnp_schema=upnp_schema,arguments=arguments)
# header_set = funcs.get_soap_header(upnp_schema,'AddPortMapping')
#
# r0 = requests.post(soap_url,headers=header_set,data=body_set)
# print r0.status_code

#
# arguments = [
# ('NewRemoteHost','0.0.0.0'),('NewExternalPort', str(51967)),('NewProtocol', 'UDP')
# ]
# body_set = funcs.get_soap_body(action='DeletePortMapping',upnp_schema=upnp_schema,arguments=arguments)
# header_set = funcs.get_soap_header(upnp_schema,'DeletePortMapping')
#
# r0 = requests.post(soap_url,headers=header_set,data=body_set)
# print r0.text


# body_get = funcs.get_soap_body(action='GetExternalIPAddress',upnp_schema=upnp_schema)
# header_get = funcs.get_soap_header(upnp_schema,'GetExternalIPAddress')
# r0 = requests.post(soap_url,headers=header_get,data=body_get)
# print r0.text
