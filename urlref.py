#!/usr/bin/env python

import pycap.capture as cap
import pycap.constants as const
import pycap.protocol as prot
from collections import defaultdict
import re
import time

def dict1(l):
	return dict([(x.lower(),'') \
		if len(x) == 1 else (x[0].lower(), x[1])
			for x in l])
def spl(s, c): return s.split(c, 1) if c in s else (s,'')

class NotHTTP(Exception):
	def __init__(self):
		pass

class HTTP:
	def __init__(self, s):
		m = re.match(r'^(GET|POST|PUT|DELETE) (\S+) HTTP/(1.\d)\r\n', s)
		if not m:
			raise NotHTTP
		self.method, self.fullpath, self.httpver = m.groups()
		headers, self.payload = spl(s, '\r\n\r\n')
		self.headers = dict1([h.split(': ', 1) for h in headers.split('\r\n')[1:]])
		self.path, self.fragment = spl(self.fullpath, '#')
		self.path, self.querystring = spl(self.path, '?')
		self.query = dict1([spl(s, '=') for s in re.split('&(?:amp;)?', self.querystring)])
		self.host = self.headers.get('host', '')
		self.url = 'http://' + self.host + self.path
	def __repr__(self):
		return 'method=%s path=%s httpver=%s query=%s headers=%s' % (
			self.method, self.path, self.httpver, self.query, self.headers)
	def __str__(self):
		return repr(self)

def payload(s, packet):
	try:
		h = HTTP(s)
		referer = h.headers.get('referer', None)
		if referer:
			print '%s %s %s' % (referer, h.url, time.time())
	except NotHTTP:
		pass

p = cap.capture()
try:
	while True:
		packet = p.next()
		if not packet:
			continue
		for x in packet:
			if type(x) == str:
				payload(x, packet)
except KeyboardInterrupt, e:
	pass

