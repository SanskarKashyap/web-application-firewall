import csv
import base64
import urllib.parse
import xml.etree.ElementTree as ET
import os


log_path = 'burp_demo.log'
httplog_path = 'httplog.csv'

def parse_log(log_path):
	'''
	This function accepts a Burp log file path.
	and returns a dictionary of request and response.
	result = {'GET /page.php...':'200 OK HTTP / 1.1....','':'',.....}
	'''
	result = {}
	if not os.path.isfile(log_path):
		print (log_path,"doesn't exist..")
		exit()
	try:
		tree = ET.parse(log_path)
	except Exception as e:
		print ('[+] Opps..!Please make sure binary data is not present in Log, Like raw image dump,flash(.swf files) dump etc')
		exit()
	root = tree.getroot()
	for reqs in root.findall('item'):
		raw_req = reqs.find('request').text
		raw_req = urllib.parse.unquote(raw_req)
		raw_resp = reqs.find('response').text
		result[raw_req] = raw_resp
	return result

def parseRawHTTPReq(raw_req):
	'''
	Parses the raw HTTP request and returns a tuple of headers, method, body, and path.
	'''
	global headers, method, body, path
	headers = {}
	sp = raw_req.split(b'\n\n', 1)
	if len(sp) > 1:
		head = sp[0]
		body = sp[1]
	else:
		head = sp[0]
		body = "" 
	c1 = head.split(b'\n', head.count(b'\n'))
	method = c1[0].split(b' ', 2)[0].decode('utf-8')
	path = c1[0].split(b' ', 2)[1].decode('utf-8')
	for i in range(1, head.count(b'\n')+1):
		slice1 = c1[i].split(b': ', 1)
		if slice1[0] != b"":
			try:
				headers[slice1[0].decode('utf-8')] = slice1[1].decode('utf-8')
			except:
				pass
	return (headers, method, body, path)

# Parse the Burp log file and write the HTTP requests to a CSV file.
result = parse_log(log_path)
with open(httplog_path, 'w', newline='') as f:
	writer = csv.writer(f)
	writer.writerow(['method', 'body', 'path', 'header'])
	for items in result:
		raw = base64.b64decode(items)
		headers, method, body, path = parseRawHTTPReq(raw)
		writer.writerow([method, body, path, headers])
