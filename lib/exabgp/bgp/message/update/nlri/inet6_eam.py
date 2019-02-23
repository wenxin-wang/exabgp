# encoding: utf-8
"""
inet.py

Created by Thomas Mangin on 2014-06-27.
Copyright (c) 2009-2017 Exa Networks. All rights reserved.
License: 3-clause BSD. (See the COPYRIGHT file)
"""

from exabgp.protocol.ip import NoNextHop
from exabgp.protocol.family import AFI
from exabgp.protocol.family import SAFI
from exabgp.bgp.message import OUT
from exabgp.bgp.message.update.nlri.nlri import NLRI
from exabgp.bgp.message.update.nlri.eam import EAM
from exabgp.bgp.message.update.nlri.qualifier import PathInfo

@NLRI.register(AFI.ipv6,SAFI.eam)
class INET6EAM (NLRI):
	__slots__ = ['path_info','eam','nexthop','labels','rd']

	def __init__ (self, afi, safi, action=OUT.UNSET):
		NLRI.__init__(self,afi,safi,action)
		self.path_info = PathInfo.NOPATH
		self.eam = EAM.NOEAM
		self.nexthop = NoNextHop

	def __len__ (self):
		return len(self.eam) + len(self.path_info)

	def __str__ (self):
		return self.extensive()

	def __repr__ (self):
		return self.extensive()

	def feedback (self, action):
		if self.nexthop is None and action == OUT.ANNOUNCE:
			return 'inet nlri next-hop missing'
		return ''

	def pack_nlri (self, negotiated=None):
		addpath = self.path_info.pack() if negotiated and negotiated.addpath.send(self.afi,self.safi) else b''
		return addpath + self.eam.pack_nlri()

	def _wwx_prefix (self):
		return "%s%s" % (self.eam,str(self.path_info))

	def extensive (self):
		return "%s%s" % (self._wwx_prefix(),'' if self.nexthop is NoNextHop else ' next-hop %s' % self.nexthop)

	def _internal (self, announced=True):
		return [self.path_info.json()]

	# The announced feature is not used by ExaBGP, is it by BAGPIPE ?

	def json (self, announced=True, compact=False):
		internal = ", ".join([_ for _ in self._internal(announced) if _])
		if internal:
			return '{ "nlri": "%s", %s }' % (self.eam,internal)
		if compact:
			return '"%s"' % self.eam
		return '{ "nlri": "%s" }' % (self.eam)

	@classmethod
	def _pathinfo (cls, data, addpath):
		if addpath:
			return PathInfo(data[:4]),data[4:]
		return PathInfo.NOPATH, data

	# @classmethod
	# def unpack_inet (cls, afi, safi, data, action, addpath):
	# 	pathinfo, data = cls._pathinfo(data,addpath)
	# 	nlri,data = cls.unpack_range(data,action,addpath)
	# 	nlri.path_info = pathinfo
	# 	return nlri,data

	@classmethod
	def unpack_nlri (cls, afi, safi, bgp, action, addpath):
		nlri = cls(afi,safi,action)

		if addpath:
			nlri.path_info = PathInfo(bgp[:4])
			bgp = bgp[4:]

		nlri.eam,bgp = EAM.unpack(bgp)
		return nlri,bgp
