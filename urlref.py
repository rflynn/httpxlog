#!/usr/bin/env python

import pycap.capture as cap
import pycap.constants as const
import pycap.protocol as prot
import re
from optparse import OptionParser

from http import HTTP_Req, HTTP_Resp, HTTP_NotHTTP, HTTP_ReqCache
from util import spl, flatten, dict1, kv_kgrep, kv_vgrep

ETH_MTU = 1500

class Action:
	def __init__(self):
		pass

	def on_http_req(self, req, opts, reqcache):
		url = req.geturl(opts)
		ref = req.referer(url)
		print >> opts.logfd, '%.2f %s %s %s queue=%u' % (
			req.ts, req.method, ref, url, len(reqcache))

	def on_http_resp(self, req, opts, reqcache):
		resp = req.resp
		latency = max(0.001, resp.ts_start - req.ts)
		totaltime = max(0.001, resp.ts_last - req.ts)
		rate = resp.size / totaltime / 1024.0
		url = req.geturl(opts)
		ref = req.referer(url)
		print >> opts.logfd, \
			'%.2f %s %s %s complete=%.3fs latency=%.3fs rate=%.1fK/s queue=%u' % (
			resp.ts_last, resp.code, ref, url, totaltime, latency, rate, len(reqcache))

	def on_http_resp_timeout(self, resp, ts):
		print '%.2f TIMEOUT (%us): %s' % (ts, ts - resp.ts, resp)

def cookies_check(req):
	cookies = req.each_cookie()
	usernames = kv_kgrep(cookies, 'user(?:name)?|uname|uid', re.I)
	passwords = kv_kgrep(cookies, 'p(?:ass)wo?r?d|pass', re.I)
	passwords += kv_vgrep(cookies, 'p(?:ass)?wo?r?d|pass', re.I)
	if usernames: print 'Cookie plaintext usernames=', usernames
	if passwords: print 'Cookie plaintext passwords=', passwords

# TODO: refactor parameters
def on_tcp(ip, tcp, s, ts, act, reqcache, opts, fd):
	"""on each TCP packet try to parse HTTP"""
	try:
		req = reqcache.get(ip, tcp)
		if req:
			payloadsize = len(s)
			resp = req.resp
			if not resp:
				resp = HTTP_Resp(s, ts)
				req.resp = resp
			else:
				resp.size += payloadsize
			packetsize = len(ip.packet) + len(tcp.packet) + payloadsize
			if packetsize < ETH_MTU:
				# last packet because it's less than full
				resp.ts_last = ts
				reqcache.remove(req)
				act.on_http_resp(req, opts, reqcache)
		else:
			req = HTTP_Req(s, ts)
			reqcache.add(ip, tcp, req)
			act.on_http_req(req, opts, reqcache)
	except HTTP_NotHTTP:
		pass

if __name__ == '__main__':

	import sys
	import signal
	import time

	parser = OptionParser()
	# TODO: capture on non-default interface
	parser.add_option("--include-query", action="store_true", default=False,
		help="should URL include querystring http://foo vs. http://foo?query")
	(Opts, Args) = parser.parse_args()
	Opts.logfd = sys.stdout

	act = Action()
	reqcache = HTTP_ReqCache(act)

	def check_cache(signum, _):
		reqcache.check(time.time())
	signal.signal(signal.SIGALRM, check_cache)
	signal.setitimer(signal.ITIMER_REAL, reqcache.max_age_sec, 1)

	p = cap.capture()
	try:
		while True:
			packet = p.next()
			# we assume HTTP will be: eth:ip:tcp:http:timestamp
			if not packet or len(packet) != 5:
				continue
			# NOTE: this is fragile, there are other possible packet
			# scenarios (Teredo) that will break this
			eth,ip,tcp,s,ts = packet
			if type(s) != str or type(tcp) != prot.tcp or type(ip) != prot.ip:
				continue
			# number of ethernet payload bytes for calculating MTU
			on_tcp(ip, tcp, s, ts, act, reqcache, Opts, sys.stdout)
	except KeyboardInterrupt, e:
		pass

