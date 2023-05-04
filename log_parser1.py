#from rawweb import Rawweb
from xml.etree import ElementTree as ET
import http.client
import urllib
import base64
import csv


log_path = 'burp_demo.log'
badwords = ['sleep', 'drop', 'uid', 'select', 'waitfor', 'delay', 'system', 'union', 'order by', 'group by']

def parse_log(log_path):
	'''
	This function accepts burp log file path.
	and returns a dict. of request and response
	result = {'GET /page.php...':'200 OK HTTP / 1.1....','':'',.....}
	'''
	result = {}
	try:
		with open(log_path): pass
	except IOError:
		print (log_path,"doesn't exist..")
		exit()
	try:
		tree = ET.parse(log_path)
	except Exception as e:
		print ('[+] Oops..! Please make sure binary data is not present in Log, like raw image dump, flash (.swf files) dump, etc.')
		exit()
	root = tree.getroot()
	for reqs in root.findall('item'):
		raw_req = reqs.find('request').text
		raw_req = urllib.parse.unquote(raw_req)
		raw_resp = reqs.find('response').text
		result[raw_req] = raw_resp
	return result

def parseRawHTTPReq(raw_req):
	try:
		raw = raw_req.decode('utf8')
	except Exception as e:
		raw = raw_req
	global headers,method,body,path
	headers = {}
	sp = raw.split('\n\n',1)
	if len(sp) > 1:
		head = sp[0]
		body = sp[1]
	else :
		head = sp[0]
		body = ""
	c1 = head.split('\n',head.count('\n'))
	method = c1[0].split(' ',2)[0]
	path = c1[0].split(' ',2)[1]
	for i in range(1, head.count('\n')+1):
		slice1 = c1[i].split(': ',1)
		if slice1[0] != "":
			try:
				headers[slice1[0]] = slice1[1]
			except:
				pass
	return (headers,method,body,path)

f = open('httplog.csv', "w")
c = csv.writer(f)
c.writerow(["method", "body", "path", "header", "single_q", "double_q", "dashes", "braces", "spaces", "badwords"])
f.close()

result = parse_log(log_path)
for items in result:
	data=[]
	raw = base64.b64decode(items)
	headers, method, body, path = parseRawHTTPReq(raw)
	data.append(method)
	data.append(body)
	data.append(path)
	data.append(headers)
	data.append(raw.count("'"))
	data.append(raw.count('"'))
	data.append(raw.count('-'))
	data.append(raw.count('{') + raw.count('}'))
	data.append(raw.count(' '))
	data.append(sum([raw.count(word) for word in badwords]))
	f = open('httplog.csv', "a", newline='')
	c = csv.writer(f)
	c.writerow(data)
	f.close()
