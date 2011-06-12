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
	def on_http_req(self, req):
		pass
	def on_http_resp(self, resp, req, opts, reqcache, fd):
		print >> fd, resp.dump(req, opts, reqcache)
	def on_http_resp_timeout(self, resp, ts):
		print '*** TIMED OUT (%us): %s' % (ts - too_old.ts, too_old)

def cookies_check(req):
	cookies = req.each_cookie()
	usernames = kv_kgrep(cookies, 'user(?:name)?|uname|uid', re.I)
	passwords = kv_kgrep(cookies, 'p(?:ass)wo?r?d|pass', re.I)
	passwords += kv_vgrep(cookies, 'p(?:ass)?wo?r?d|pass', re.I)
	if usernames: print 'Cookie plaintext usernames=', usernames
	if passwords: print 'Cookie plaintext passwords=', passwords

def on_http_req(req, opts, reqcache, fd):
	print >> fd, req.dump(opts, reqcache)
	#print >> fd, 'Headers:', req.headers
	if req.cookies():
		print >> fd, 'Cookies:', req.each_cookie()
		cookies_check(req)

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
				act.on_http_resp(resp, req, opts, reqcache, fd)
		else:
			req = HTTP_Req(s, ts)
			reqcache.add(ip, tcp, req)
			on_http_req(req, opts, reqcache, fd)
	except HTTP_NotHTTP:
		pass
		"""
		# check closed connections, toss out associated requests
		if tcp.flags & const.tcp.TH_RST:
			# RST: reset connection
			# is unusual, can come from either end...
			# we can either look up both possibilities, or just wait
			# for a request to timeout...
			print '*** RST', ip, tcp
			print 'map before', reqcache.map
			req = reqcache.get(ip, tcp, False)
			if req:
				reqcache.remove(req)
			print 'map after', reqcache.map
		if tcp.flags & const.tcp.TH_FIN:
			if tcp.flags & const.tcp.TH_ACK:
				print '*** FIN ACK', ip, tcp
				req = reqcache.get(ip, tcp)
				if req:
					reqcache.remove(req)
			else:
				print '*** FIN', ip, tcp
		"""

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

