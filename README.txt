# ex: set tw=78 ts=8 noet:

Trace URL 'Referer's on the wire

Depends on...
	python
	pycap http://pycap.sourceforge.net/ (depends on libpcap and libnet)

Example:

$ sudo ./urlref.py &
[1] 6793
$ wget -nH -nd -p http://www.reddit.com/ --quiet -U "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"
http://www.reddit.com/ http://www.reddit.com/static/jquery.json.js 1307589905.36
http://www.reddit.com/ http://www.reddit.com/static/jquery.reddit.js 1307589905.37
http://www.reddit.com/ http://www.reddit.com/static/reddit.js 1307589905.41
http://www.reddit.com/ http://www.reddit.com/static/reddit.css 1307589905.46
...

