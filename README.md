
# Securing Wi-Fi Worldwide
-----------------
"Securing the Wi-Fi Access points/Routers from malware"

---------------------------------------------------------------------------------------
> NYU
>  Dhishan Amaranath
> N16909360

> Guide: Thomas Reddington

## Abstract
Today every house and almost every public area are provided with wireless connectivity constituting of millions of wireless access points and routers throughout the world. Given the wide usage and minimal knowledge of these devices among the users, it is increasingly becoming a target for attackers. This paper outlines the security vulnerabilities, Attack vectors and Attack surfaces of everyday used wireless network devices, especially Wireless Access points and routers that allow Wi-Fi compliant device to connect to a wired network. This research tries to dissect the devices that provide connectivity into layers and with examples provides a brief description of each layer and security flaws associated with it.

## Layers providing Wireless connectivity
![](https://i.imgur.com/NoNziQM.jpg)

## Attacking Access Points
Access points are network devices working at Ethernet layer in the OSI stack. The security at this layer is provided by encrypting the data. It turns clear text data into secret code. There are mainly three types of encryption used today at this layer.

### WEP Cracking
As with any encryption, it needs keys for encrypting data. WEP uses a symmetric stream cipher algorithm called RC4. For any stream cipher, the key has to change for every packet; this randomness is provided by an IV(Initialization Vector) a 24 bit key sent in clear text in the 802.11 headers. So for WEP, the key for encryption is the 24 bits of IV from the header concatenated with the known key. Consider for example WEP-64, and here the 24 bits are the IV from the packet header and the 40 bits from the known key. Since the known key is the password of the network which the user enters, it is an ASCII. Each ASCII being a byte, the 40 bits are five characters. And then again a byte of each ASCII are limited to in the range of printable characters. As far the IV, there is a 50% chance of the IV repeating every 5000 packets because of the mere 24 bits.

Given the weak security of the WEP encryption, It is straightly easy to crack any WEP protected network. As an Example stated in Wikipedia, In 2005, a group from the U.S. Federal Bureau of Investigation gave a demonstration where they cracked a WEP-protected network in 3 minutes using publicly available tools.

To sum it up, WEP is merely a security measure in the AP layer.

### WPA/WPA2 Cracking
After the discovery of WEP vulnerability, the 802.11i protocol was announced with advanced security measures. The successor of WEP was WPA and its successor a year later WPA2. WAP and WPA2 differ in their encryption algorithms. WPA uses TKIP a more secure version of RC4 to keep it close to its predecessor. WPA2 uses AES, which is both computationally intensive and more secure. WPA/WPA2 both came with two different flavors, Personal and Enterprise. Even though both maintain the same set of encryption, they both differ in their authentication methods. WPA-Personal uses a pre-shared key mechanism whereas WPA-2 uses authentication server to provide authentication.

#### Authentication Hacking
##### PSK - WPA/WPA2 Personal
So far the known method of cracking authentication is by de-authenticating an existing user and capturing the handshaking messages and using the brute force password dictionary to guess the correct pass-phrase

##### PSK - WPA/WPA2 Enterprise
The authentication here is provided by the authentication server behind the access point and are relatively more secure than its Personal flavor. The access points use `Port-Based Access Control` to control the connectivity to the endpoint. Communication between the AP and the authentication server are made using `802.1x EAP` (Extensible Authentication Protocol) and its variants like PEAP, LEAP, TLS, etc.

#### Encryption Hacking
As mentioned earlier, the Encryption of WPA is done using TKIP where TKIP uses session based and longer keys making it harder for the attacker. But knowing the common types of packets like ARP and its common contents, there are instances where encryption is broken in a couple of minutes. The encryption of WPA2, the lesser of the devils, is AES, which is relatively hard and very CPU and time-intensive to break. This is among the known and most secure which is currently recommended for use.

#### WPS
 WPS was invented to make the process of connecting to Access points hazel free. To connect using WPS, you need to enter the eight digit pin dedicated to the access point.

##### Security of WPS
The last digit of the 8 digits of WPS is a check digit, computed from the first seven bits. It proves that the PIN you entered in two stages, The first 4 bits and then the second half. This reduces the complexity of cracking the pin to as simple as cracking a 4 digit pin and then a 3 digit pin. The complexity reduced from 10^8^ to 10^4^  + 10^3^.

Also, many manufacturers, calculate the pin from MAC address or serial number, both of which can be obtained easily, thereby making the whole WPS vulnerable.
The presence of WPS blows any security offered by the WPA out of the water.

## Attacking Router Layer

In the traditional sense, the functionality of router is routing the packets among the networks. But when looked from the eyes of security, the additional functionality of the routers are the ones that need more careful consideration. In addition to providing routing, the routers provide configurations such as default DNS server addresses to the devices connecting to it. DNS server maps name to the server IP location. A malicious DNS server can navigate the victims to phising sites and exploit users.

_**An simple example:**_ A hacker can create a replica of a legitimate mail login wherein he records the user's credentials and then navigate the user to the real website. We as human beings with feeble memory to remember all passwords are highly inclined to reuse them in various sites. With such credentials in the hands of an attacker, the possibilities of the exploit are infinite.

### Previous Attacks on DNS
_**Tale of One Thousand and One DSL modems:**_
**Vulnerability:** The attacker can access the admin panel & change default system password without authentication and verification
**Affected Device:** `COMTREND ADSL Router BTC(VivaCom) CT-5367 C01_R12`
**Exploit:** Change DNS & Password Settings of the DSL modems. The victims are navigated to malicious DNS servers. These DNS servers navigate the victims into fake bank sites and get user credentials. Other attackers used this to insert malicious softwares on to the victims computers by popping up to install plugins

_**Drive by Pharming:**_
> CSRF attack used against routers to change their DNS settings

**Vulnerability:** It is possible to send a request to the router that will modify its configuration. It does not validate POST, or Referrer or Anything unless the administrator password has been set by the customer
**Affected Device:** 2wire modem/router models 1701HG, 1800HW, and 2071, with 3.17.5, 3.7.1, and 5.29.51 software
**Exploit:** Change the IP association of the www.banamex.com URL to a malicious address in the Local DNS server of the router. This is done by a spam email where the image tag is a request to the router interface to change the Local DNS settings. Thus when the user typed in the address of the bank, is redirected to a phishing site.
**_Example:_**
```html
<img src="http://192.168.0.1/cgi?uname=admin&passwd=admin&dns_new=x.x.x.x"></img>
```

### Binary Malware in Linux Based routers
Today's routers are not just a chip designed to do only specific routing tasks. They are capable of running mini Linux os. Such a flexibility also gives more power to hackers. So far there has been only one major binary malware target to on Linux based routers.

_**Psyb0t**_: pysbot is a binary malware which is designed to run on the MIPS-based Linux routers. The malware is designed to self-proliferate and capable of acting based on the commands from an IRC channel. This malware is capable of initiating DDoS attacks, executing shell commands, search and attack servers running FTP, SQL, SMB shares, etc.. The proliferation was possible because of default passwords and due to the open of unnecessary ports in the target.

But since the Router Firmware resides in ROM and can't be written, this malware stays in RAM and does not cause permanent damage. A simple system reboot could erase it. But as long as the default credentials are in use, the routers were always susceptible.

Mode of entry in most cases was through SSH or Telnet or sometimes through Web interface enabled for remote login through default credentials.

## Attacks related to Modems

Modems are devices working at the physical layer. These devices convert digital signals into electrical signals for transportation. From the perspective of wireless internet or Wi-Fi, Modems are end devices and are usually connected to routers and act as Internet Gateway Device(IGD). The security of modems per se is basically the safety of the router to which modem is immediately connected to. Modern days ISP's provides a single device which constitutes modems and routers and many times even access points in a single device.

IGD's are the single point for any network for access to outside world, In other words, are the devices which connect to the internet. IGD provide various functionality like firewalls, DHCP control, remote management, NTP etc.

Access to such devices and Wi-Fi sources, in general, is provided through the Web interface, UPnP, SNMP and various services like Telnet, SSH, etc. For the purpose of this paper, I will explain how this can be a leveraged as an attack surface and demonstrate an exploit.

### SNMP:
Definition of SNMP by [SANS]:"The Simple Network Management Protocol, SNMP, is a commonly used service that provides network management and monitoring capabilities. SNMP offers the capability to poll networked devices and monitor data such as utilization and errors for various systems on the host. SNMP is also capable changing the configurations on the host, allowing the remote management of the network device." SNMP works by providing a default community string for read and write. Most often the SNMP service is installed by default without the knowledge of the admin. Thus the default string "public" and "private" for read and write respectively, remain unchanged and hackers use this to gain knowledge and change configurations of the device using SNMP clients. Adding to this is the SNMP passes the plaintext unencrypted. SNMP uses MIB (Management Information Base) table to store details. Using SNMP get, walk, set commands the agents can poll for information or set them.

#### SNMP Reflection Attack

**Attack:** SNMP reflection, like other reflection attacks, involves eliciting a flood of responses to a single spoofed IP address. During an SNMP reflection attack, the attacker sends out a large number of SNMP queries with a spoofed IP address to numerous devices that, in turn, reply to that victim (spoofed) address. The attack volume grows as more and more devices continue to reply until the target network is brought down under the collective volume of these SNMP responses.

**Affected Devices:** Most of the devices susceptible to this attack are ISP managed devices, As these devices are poorly managed and the users are unaware of this.

### UPnP:
Universal Plug and Play(UPnP) a relatively new set of networking protocol which has been in rising lately. The protocol was introduced by Microsoft to promote plug and play features for devices capable of networking. As with most protocols, UPnP was not designed with security in the mindset. Though there are very few notable UPnP attacks, with its increasing popularity, it's no doubt that a large-scale UPnP attack is "down the pike." The irony is, even the newer versions of UPnP has very minimal security in its core.
Before I introduce how UPnP can be abused, I will take a minute to describe the basics of UPnP. Here is the brief description of UPnP Architecture. Shamelessly copied from [UPnP Intro]

> UPnP is composed of several steps, including discovery, description, control, eventing, and presentation.
>- Discovery: during this step, service providers (called 'devices') and service users (called 'control points') discover each other.
>- Description: devices use XML to describe their information and services before being used. >- Control: control points use SOAP to control devices.
>- Eventing: subscribers will be informed when devices' states change. >- Presentation: devices can use browsers to present themselves.

#### UPnP devices as DDoS Botnets:
This attack is also called as `SSDP reflection DDoS attack`. The Discovery step above mentioned uses SSDP. SSDP is an HTTP request over UDP to identify all the devices that support UPnP and respond with a location for service description XML file.

![UPnP Discovery](https://i.imgur.com/PCSoEN8.png)

The HTTP request to the URLlocation mentioned in the SSDP response fetches an XML file describing all the services the device offer. Each of the service profile has an `<SCPDURL>` which again constitute of a relative location of the XML file which details more on each type of the service and the format for the requests.
![SCPD](https://i.imgur.com/T3UsFNn.png)

![soap actions](https://i.imgur.com/4AIEQHz.png)

The responses are XML files and relatively consume more bandwidth. The attacker can gather the list of vulnerable devices and create malicious requests to such devices spoofing the targets IP address. The attack can be amplified by using more bots to create successive HTTP requests to get further XML service profiles. Thus causing massive traffic at the attacker and eventually bringing down the network.

#### UPnP to create Chaos
Just like any program, the UPnP server does have variables or event states stored. The UPnP protocol does provide functionality for eventing. Here the clients subscribe to change in the states of the control points and notify them accordingly. This can be abused by creating a subscription under the spoofed address. This is possible as the UPnP does not define any validation for subscription and start notifying on the host address for any change in the state. With enough subscriptions, the chaos can be created.
**Event subscription**
```http
SUBSCRIBE publisher path HTTP/1.1
HOST: publisher host:publisher port
CALLBACK: <delivery URL>
NT: upnp:event
TIMEOUT: Second-requested subscription duration
```

#### UPnP to Punch Holes in Firewall
The main security risk from UPnP is when the Router having the UPnP feature is an Internet Gateway Device. The IGD profile of the UPnP allows the UPnP client to create a port mapping in the gateway device. It's an excellent feature when you want to play an X-Box game with a friend, and you do not have to take the burden of meddling with the settings of your router yourself. This power could be easily abused by any malware in your network.

Here is an example:
![UPnP Exploit](https://i.imgur.com/CO6fCVp.jpg)

This is allowed because the UPnP server doesn't validate the IP address of the requester with that of the request. I was able to exploit this vulnerability by writing few lines of python code using scapy.

##### Step 1: UPnP Discovery:
An SSDP discovery message broadcasted over an Multicast address:

**Request:**
![SSDP Request](https://i.imgur.com/uSR5MoM.png)
The UPnP devices identify themselves by sending an unicast response to my address. I sniffed the packets coming to my host and collected the information In my case, I had two devices capable of UPnP

**Response:**
With HTTP libraries in Python, I was able to get the XML files from both the locations and parse for the UPnP device which has IGD profile.
![SSDP description file](https://i.imgur.com/06NB8qb.png)

**_A little about UPnP schemas:_** The UPnP forums define the UPnP template for various profiles. InternetGatewayDevice:1/2 is one of such template. The Document can be obtained [here](http://upnp.org/specs/gw/UPnP-gw-InternetGatewayDevice-v2-Device.pdf). The IGD Schemas of interest here provide options to open ports, set/get connection types, get external IP, DNS settings, etc.

##### Step 2: Description:
The port opening part that I was concerned above was service profile under `WANIPConnection:1`. I was able to extract the `<SCPDURL>` which points to the XML location of this profile and get the list of arguments required to pass to the device to open up the port.

##### Step 3: UPnP Control:
The control requests to the device should be made using SOAP requests. SOAP requests are HTTP requests to the device where the body is in XML format where each argument is passed in the respective tags.
```xml
<?xml version="1.0" ?>
<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
        <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
            <NewRemoteHost>0.0.0.0</NewRemoteHost>
            <NewExternalPort>4000</NewExternalPort>
            <NewProtocol>TCP</NewProtocol>
            <NewInternalPort>4000</NewInternalPort>
            <NewInternalClient>192.168.0.20</NewInternalClient>
            <NewEnabled>1</NewEnabled>
            <NewPortMappingDescription>UPnP Port Mapping Exploit</NewPortMappingDescription>
            <NewLeaseDuration>0</NewLeaseDuration>
          </u:AddPortMapping>
        </s:Body>
      </s:Envelope>
   ......
```


_This also needs a POST request header_
```json
{'SOAPAction': '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"', 'Content-Type': 'text/xml'}
 ```

The request above responded with a `200 Success` code. I was able to verify the same by sending a request to get all port mapping entry using UPnP

![Response](https://i.imgur.com/L6r3YUa.png)

The scary part was, the IP I used to open up the port was not even mine. Think of all the ways an attacker could exploit. A simple desktop malware could open up the port for all the devices in the network to the outside world, Essentially handling the complete control to the hacker.

You can find the complete code I used to perform the exploit in my git hub repository(Link at the bottom of the file)

## Securing your Wi-Fi:
From the research above, Here are some of the things to check for securing your Wi-Fi. You can access your router web interface through your web browser. [Default Router Access](http://www.19216811ip.mobi/default-router-password-list/) Provides the list of default router IP address and the user credentials if you haven't changed it.

1) **Check your DNS settings:** DNS was and is still one of the major target for hackers. Check your DNS settings of the router and your host. >I was able to find a site which does this for you. [F-Secure Router Checker](https://campaigns.f-secure.com/router-checker/en_global/)

2) **Check for open ports:** Unnecessary open ports on your router allow attackers to enter your network. Following are some of the common ports you might see.
- 80,443: A web server - If you are aware of opening a webserver port yourself, its pretty much likely that the open port indicate the web interface of your router. If you have not changed the default credentials of the router and your port is open, it is very likely that you are already hacked. Do switch OFF the remote access feature of your router, if you still need remote access change the password of your router to something stronger. Also port 8080, 8000 are commonly used for web server.
- 22: SSH- It gives remote access to the host the router is forwarding the port to. Or it could be directed to the router itself. Unless you deliberately opened the port, switch off ssh access or disable port forwarding on your router for 22 - 23: Telnet - It's an insecure SSH. Never Use
- 21 and 20: It's used for FTP. File transfer, >Use any of the port checker tools available online to check. [Open Port Finder](http://www.yougetsignal.com/tools/open-ports/) is one such tool.

3) **Upgrade Firmware & Change Default Credentials:** Most of the problems or attacks are known to happen because the users are either unaware or negligent to update the firmware of your setup. For the same security reasons, the ISP's cannot access your router and update it.

4) **Disable unwanted services:** As I explained in the previous sections, services like `UPnP & SNMP` are very friendly and deadly. If the router web interface does provide options for switching off such services and unless you need it, turn off these services. Having remote access to your router with these settings turned on, the security risks amplify.

5) Always use WPA with strong password

**References:**
**WEP:**
[IEEE Std 802.11-2007](http://standards.ieee.org/getieee802/download/802.11-2007.pdf)
[Security of the WEP algorithm](http://www.isaac.cs.berkeley.edu/isaac/wep-faq.html)

**WPA/WPA2:**
[PSK  Hacking](http://www.og150.com/assets/Wireless%20Pre-Shared%20Key%20Cracking%20WPA,%20WPA2.pdf)
[Breaking TKIP](http://dl.aircrack-ng.org/breakingwepandwpa.pdf)
[Understanding WPA crack](http://arstechnica.com/security/2008/11/wpa-cracked/)

**DNS Attacks:**
[Tale of One Thousand and One DSL modems](https://securelist.com/analysis/publications/57776/the-tale-of-one-thousand-and-one-dsl-modems/)
[Comtrend ADSL Router CT-5367 C01_R12 - Remote Root Exploit](https://www.exploit-db.com/exploits/16275/)
[Exploiting CSRF vulnerability](http://www.wizcrafts.net/blogs/2008/01/hackers_exploit_vulnerability_in_2wire_modem.html)
[National Vulnerability Database](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2007-4389)

**Binary Malware:**
[Psyb0t](https://securelist.com/analysis/publications/36396/heads-of-the-hydra-malware-for-network-devices/)

**SNMP:**
[SNMP DDOS Attacks](https://www.bitag.org/report-snmp-ddos-attacks.php)
[Multiple Vulnerabilities in SNMP](http://www.ists.dartmouth.edu/library/9.pdf)
[SANS]: https://www.sans.org/security-resources/idfaq/using-snmp-for-reconnaissance/9/11 "Using SNMP for Reconnaissance"

**UPnP Protocol:**
[UPnP Intro]: https://dangfan.me/en/posts/upnp-intro "UPnP Working"
[UPnP Device Architecture](http://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf) 

**UPnP as Botnets:**

[Akamai Research](https://www.akamai.com/uk/en/multimedia/documents/state-of-the-internet/ssdp-reflection-ddos-attacks-threat-advisory.pdf)
[UPnP DDoS](http://resources.infosecinstitute.com/ddos-upnp-devices/)
[SSDP DDoS](https://blog.sucuri.net/2014/09/quick-analysis-of-a-ddos-attack-using-ssdp.html)

**UPnP to punch hole in Firewall:**

[Universal Plug and Play: Dead simple or simply deadly?](http://www.upnp-hacks.org/sane2006-paper.pdf)

[upnp-hacks](http://www.upnp-hacks.org/igd.html)

[UpnpPunch](https://github.com/sirMackk/ZeroNet/blob/upnp_punch_squashed/src/util/UpnpPunch.py)

[UPnP and Python](http://mattscodecave.com/posts/using-python-and-upnp-to-forward-a-port.html) 
[Git Hub Repo](https://github.com/dhishan/UPnP-Hack)


