from xml.dom.minidom import parseString, Document
import re
import os

get_ip = lambda(x): os.popen('ifconfig {0} | grep -e "inet\ " | cut -d" " -f2'.format(x)).read().strip()


def _node_val(node):
	if not node.hasChildNodes():
		return ''
	return node.childNodes[0].data


def _node_name(node):
	return node.tagName


def parse_igd_profile(profile_xml):

	dom = parseString(profile_xml)

	elems = dom.getElementsByTagName('serviceType')
	for service in elems:
		if _node_val(service).find('WANIPConnection') > 0:
			control_url = service.parentNode.getElementsByTagName('controlURL')[0].childNodes[0].data
			upnp_schema = _node_val(service).split(':')[-2]
			return control_url, upnp_schema

	return False


def is_igd(profile_xml):
	dom = parseString(profile_xml)
	elems = dom.getElementsByTagName('deviceType')
	for dev in elems:
		if "InternetGatewayDevice" in dev.firstChild.toxml():
			return True
	return False


def parse_port_mapping(xml_p):
	dom = parseString(xml_p)
	elem_head = _get_node_of(dom.firstChild,'GetGenericPortMappingEntryResponse')
	if elem_head:
		global elem_head
		for elem in elem_head.childNodes:
			print '{0} : {1}'.format(_node_name(elem),_node_val(elem))
		print ''

# namespaceURI="http://schemas.xmlsoap.org/soap/envelope/",


def _get_node_of(xml_node,tag):
	if not xml_node.hasChildNodes():
		return None
	if tag in xml_node.firstChild.tagName:
		return xml_node.firstChild
	for elem in xml_node.childNodes:
		node = _get_node_of(elem,tag)
	if xml_node.nextSibling and not node:
		node = _get_node_of(xml_node.nextSibling,tag)
	return node


def get_soap_header(upnp_schema,action):
	return {'SOAPAction': '"urn:schemas-upnp-org:service:{0}:1#{1}"'.format(upnp_schema,action), 'Content-Type': 'text/xml'}


def get_soap_body(action,upnp_schema,arguments=[]):
	doc = Document()
	# create the envelope element and set its attributes
	envelope = doc.createElementNS('', 's:Envelope')
	envelope.setAttribute('xmlns:s', 'http://schemas.xmlsoap.org/soap/envelope/')
	envelope.setAttribute('s:encodingStyle', 'http://schemas.xmlsoap.org/soap/encoding/')
	# create the body element
	body = doc.createElementNS('', 's:Body')
	fn = doc.createElementNS('', 'u:{0}'.format(action))
	fn.setAttribute('xmlns:u', 'urn:schemas-upnp-org:service:{0}:1'.format(upnp_schema))

	argument_list = []

	for k, v in arguments:
		tmp_node = doc.createElement(k)
		tmp_text_node = doc.createTextNode(v)
		tmp_node.appendChild(tmp_text_node)
		argument_list.append(tmp_node)

	for arg in argument_list:
		fn.appendChild(arg)

	body.appendChild(fn)
	envelope.appendChild(body)
	doc.appendChild(envelope)

	return doc.toxml()
