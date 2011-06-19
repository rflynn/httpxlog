# ex: set tw=78 ts=8 noet:

External HTTP logging for servers and/or clients
Aggregate multiple web servers into one log, access to more performance data

Depends on...
	pycap: http://pycap.sourceforge.net/ 
		sudo easy_install pycap
		...which depends on
			libpcap: http://www.tcpdump.org/#latest-release
 			libnet: http://libnet.sourceforge.net/
			sudo apt-get install libpcap-dev libnet1-dev
			
	python: http://python.org/
			sudo apt-get install python

Example:

from a client's perspective:

$ sudo ./httpxlog.py
2011-06-19 16:44:07.160997 GET http://slashdot.org/ http://slashdot.org/ queue=1
2011-06-19 16:44:08.526506 200 http://slashdot.org/ http://slashdot.org/ complete=1.366s latency=1.225s size=54.1K rate=39.6K/s queue=0
2011-06-19 16:44:08.640189 GET http://slashdot.org/ http://jlinks.industrybrains.com/jsct queue=1
2011-06-19 16:44:08.779778 GET http://slashdot.org/ http://www.google-analytics.com/__utm.gif queue=2
2011-06-19 16:44:08.791952 200 http://slashdot.org/ http://www.google-analytics.com/__utm.gif complete=0.012s latency=0.012s size=0.3K rate=26.5K/s queue=1
2011-06-19 16:44:08.818585 200 http://slashdot.org/ http://jlinks.industrybrains.com/jsct complete=0.178s latency=0.089s size=6.6K rate=36.9K/s queue=0
2011-06-19 16:44:09.301020 GET http://slashdot.org/ http://b.scorecardresearch.com/b queue=1
2011-06-19 16:44:09.456040 204 http://slashdot.org/ http://b.scorecardresearch.com/b complete=0.155s latency=0.155s size=0.5K rate=2.9K/s queue=0

