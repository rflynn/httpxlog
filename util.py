#!/usr/bin/env python

"""
urlref utility functions
"""

import re
from collections import defaultdict
from itertools import chain

def spl(s, c): return tuple(s.split(c, 1)) if c in s else (s,'')
def flatten(l): return list(chain.from_iterable(l))
def dict1(l):
	d = defaultdict(list)
	kv = [(x[0].lower(), '' if len(x) == 1 else x[1]) for x in l]
	for k,v in kv:
		d[k].append(v)
	return dict(d)
def kv_grep(kvs, nth, pattern, opts):
	"""given a list of tuples, return all [k,...] where k[nth] match pattern"""
	return list(filter(lambda kv: re.search(pattern, kv[nth], opts), kvs))
def kv_kgrep(kvs, pattern, opts): return kv_grep(kvs, 0, pattern, opts)
def kv_vgrep(kvs, pattern, opts): return kv_grep(kvs, 1, pattern, opts)

