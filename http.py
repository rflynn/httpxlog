#!/usr/bin/env python

"""
HTTP-parsing for urlref app
Couldn't find a decent standalone
"""

import re

from util import spl, flatten, dict1

class HTTP_NotHTTP(Exception):
	def __init__(self):
		pass

class HTTP_Req:
	def __init__(self, s, ts):
		m = re.match(r'^(GET|POST) (\S{1,4096}) HTTP/(1.\d)\r\n', s)
		if not m:
			raise HTTP_NotHTTP
		self.method, self.fullpath, self.httpver = m.groups()
		headers, self.payload = spl(s, '\r\n\r\n')
		self.headers = dict1([h.split(': ', 1) for h in headers.split('\r\n')[1:]])
		self.path, self.fragment = spl(self.fullpath, '#')
		self.path, self.querystring = spl(self.path, '?')
		self.query = dict1([spl(s, '=')
			for s in re.split('&(?:amp;)?', self.querystring)]) \
				if self.querystring else {}
		self.host = self.headers.get('host', [''])[0]
		self.url = 'http://' + self.host + self.path
		self.fullurl = 'http://' + self.host + self.fullpath
		self.ts = ts
		self.resp = None
		self.key = None
	def __repr__(self):
		return 'REQ %s %s %s %s ?=%s' % (
			self.key, self.method, self.path, self.httpver,
			self.query)
	def __str__(self):
		return repr(self)
	def geturl(self, opts):
		return self.fullurl if opts.include_query else self.url
	def referer(self, url):
		return self.headers.get('referer', [url])[0]
	def cookies(self):
		return ';'.join(self.headers.get('cookie',[]))
	def each_cookie(self):
		cookies = self.cookies()
		if not cookies:
			return []
		kv = flatten(c.strip().split('&') for c in cookies.split(';'))
		return [spl(val, '=') for val in kv]
	def dump(self, opts, reqcache):
		url = self.geturl(opts)
		ref = self.referer(url)
		return '%.2f %s %s %s outstanding=%u' % (
			self.ts, self.method, ref, url, len(reqcache))

class HTTP_Resp:
	def __init__(self, s, ts):
		m = re.match(r'^HTTP/(1.\d) (\d{3}) (?:[^\r\n]{1,64})\r\n', s)
		if not m:
			raise HTTP_NotHTTP
		self.httpver, self.code = m.groups()
		headers, self.payload = spl(s, '\r\n\r\n')
		self.headers = dict1([h.split(': ', 1) for h in headers.split('\r\n')[1:]])
		self.ts_start = ts
		self.ts_last = None
		self.size = len(s)
	def __repr__(self):
		return 'RESP code=%3u httpver=%s' % (self.code, self.httpver)
	def __str__(self):
		return repr(self)
	def dump(self, req, opts, reqcache):
		latency = max(0.001, self.ts_start - req.ts)
		totaltime = max(0.001, self.ts_last - req.ts)
		rate = self.size / totaltime / 1024.0
		url = req.geturl(opts)
		ref = req.referer(url)
		return '%.2f %s %s %s complete=%.3fs latency=%.3fs rate=%.1fK/s queued=%u' % (
			self.ts_last, self.code, ref, url, totaltime, latency, rate, len(reqcache))

class HTTP_ReqCache:
	""""""
	def __init__(self, action, max_age_sec=120):
		self.action = action
		self.max_age_sec = max_age_sec
		self.map = {}		# requests keyed by IP:IP:srcport
		self.ordered = []	# requests in order to facilitate timeout
	def keyresp(self, ip, tcp):
		return '%s:%s:%s' % (ip.destination, ip.source, tcp.destinationport)
	def keyreq(self, ip, tcp):
		return '%s:%s:%s' % (ip.source, ip.destination, tcp.sourceport)
	def mapadd(self, req):
		if req.key not in self.map:
			self.map[req.key] = [req]
		else:
			self.map[req.key].append(req)
	def add(self, ip, tcp, req):
		req.key = self.keyreq(ip, tcp)
		self.mapadd(req)
		self.ordered.append(req)
	def get(self, ip, tcp, dest=True):
		key = (self.keyresp if dest else self.keyreq)(ip, tcp)
		try:
			return self.map[key][0]
		except KeyError, IndexError:
			pass
	def remove(self, req):
		try:
			r = self.map[req.key]
			r.pop(0)
			if not r:
				del self.map[req.key]
		except KeyError:
			pass
		self.ordered.remove(req)
	def check(self, ts):
		"""timeout stale requests"""
		while self.ordered and ts - self.ordered[0].ts > self.max_age_sec:
			too_old = self.ordered[0]
			self.remove(too_old)
			self.act.on_http_resp_timeout(too_old, ts)
	def __len__(self):
		return sum(len(v) for v in self.map.itervalues())

