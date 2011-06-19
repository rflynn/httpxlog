#!/usr/bin/env python

"""
external http logging by packet sniffing TCP/IP
this approach allows us several advantages over built-in httpd logging:
	* multiple httpds at once
	* availablility of performance data that is not available in standard logs, such as:
		* latency: time between request and initial response
		* queue: number of outstanding requests
	* flexibility; use to monitor servers' or clients' perspective

Author: Ryan Flynn <parseerror@gmail.com>

Caveats:
	* assumes Ethernet

TODO:
	* support apache CustomLog log format: http://httpd.apache.org/docs/1.3/mod/mod_log_config.html#formats
"""

import pycap.capture as cap
import pycap.constants as const
import pycap.protocol as prot
import re
from optparse import OptionParser

from http import HTTP_Req, HTTP_Resp, HTTP_NotHTTP, HTTP_ReqCache
from util import spl, flatten, dict1, kv_kgrep, kv_vgrep, time2utcstr

ETH_MTU = 1500

class Action:

	_instance = None

	def __init__(self):
		pass

	@staticmethod
	def instance():
		if not Action._instance:
			Action._instance = Action()
		return Action._instance

	def on_http_req(self, req, opts, reqcache):
		url = req.geturl(opts)
		ref = req.referer(url)
		print >> opts.logfd, '%s %s %s %s queue=%u' % (
			time2utcstr(req.ts), req.method, ref, url, len(reqcache))

	def on_http_resp(self, req, opts, reqcache):
		resp = req.resp
		latency = max(0.001, resp.ts_start - req.ts)
		totaltime = max(0.001, resp.ts_last - req.ts)
		sizekb = resp.size / 1024.0
		rate = sizekb / totaltime
		url = req.geturl(opts)
		ref = req.referer(url)
		print >> opts.logfd, \
			'%s %s %s %s complete=%.3fs latency=%.3fs size=%.1fK rate=%.1fK/s queue=%u' % (
			time2utcstr(resp.ts_last), resp.code, ref, url, totaltime, latency, sizekb, rate, len(reqcache))

	def on_http_resp_timeout(self, resp, ts):
		print '%.2f TIMEOUT (%us): %s' % (ts, ts - resp.ts, resp)

def cookies_check(req):
	"""scan plaintext cookies for potentially sensitive information"""
	cookies = req.each_cookie()
	usernames = kv_kgrep(cookies, 'user(?:name)?|uname|uid', re.I)
	passwords = kv_kgrep(cookies, 'p(?:ass)wo?r?d|pass', re.I)
	passwords += kv_vgrep(cookies, 'p(?:ass)?wo?r?d|pass', re.I)
	if usernames: print 'Cookie plaintext usernames=', usernames
	if passwords: print 'Cookie plaintext passwords=', passwords

# TODO: refactor parameters
def on_tcp(ip, tcp, s, ts, reqcache, opts):
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
				Action.instance().on_http_resp(req, opts, reqcache)
		else:
			req = HTTP_Req(s, ts)
			reqcache.add(ip, tcp, req)
			Action.instance().on_http_req(req, opts, reqcache)
	except HTTP_NotHTTP:
		pass

if __name__ == '__main__':

	import sys
	import signal
	import time
	import os

	parser = OptionParser()
	# TODO: capture on non-default interface
	parser.add_option('--include-query', action='store_true', default=False,
		help='should URL include querystring http://foo vs. http://foo?query')
	parser.add_option('-i', '--interface', action='store', dest='interface',
		help='select interface to listen on. default chosen by libpcap')
	Opts, Args = parser.parse_args()
	Opts.logfd = sys.stdout

	act = Action.instance()
	reqcache = HTTP_ReqCache(act)

	# timeout requests from the cache on a regular basis
	def check_cache(signum, _):
		reqcache.check(time.time())
	signal.signal(signal.SIGALRM, check_cache)
	signal.setitimer(signal.ITIMER_REAL, reqcache.max_age_sec, 1)

	try:
		capargs = []
		if Opts.interface:
			print 'listening on %s...' % Opts.interface
			capargs.append(Opts.interface)
		p = cap.capture(*capargs)
	except Exception as e:
		print e
		if 'no suitable device found' in str(e):
			if not hasattr(os, 'geteuid') or os.geteuid() != 0:
				print >> sys.stderr, 'try running as root'
		exit(1)
	try:
		while True:
			packet = p.next()
			# we assume HTTP will be: eth:ip:tcp:http:timestamp
			if not packet or len(packet) != 5:
				continue
			# NOTE: this is fragile, there are other possible packet
			# scenarios (Teredo) that will break this
			eth, ip, tcp, s, ts = packet
			if type(s) != str or type(tcp) != prot.tcp or type(ip) != prot.ip:
				continue
			# number of ethernet payload bytes for calculating MTU
			on_tcp(ip, tcp, s, ts, reqcache, Opts)
	except KeyboardInterrupt, e:
		pass

