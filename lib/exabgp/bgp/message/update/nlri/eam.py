# encoding: utf-8
"""
cidr.py

Created by Wenxin Wang on 2019-02-01.
"""

from exabgp.protocol.family import AFI
from exabgp.protocol.ip import IP
from exabgp.util import ordinal
from exabgp.util import padding
from exabgp.bgp.message.notification import Notify
from exabgp.bgp.message.update.nlri.cidr import CIDR


class EAM (object):
	EOR = False
	# __slots__ = ['packed','mask','_ip']

	def __init__ (self, cidr4, cidr6):
		self._cidr4 = cidr4
		self._cidr6 = cidr6

	def __repr__ (self):
		return "%s %s" % (self._cidr4,self._cidr6)

	def pack_nlri (self):
		return self._cidr4.pack_nlri() + self._cidr6.pack_nlri()

	@staticmethod
	def _decode_mask (bgp, msg):
		if not len(bgp):
			raise Notify(3,10,msg)

		mask = ordinal(bgp[0])
		size = CIDR.size(mask)

		if len(bgp) < size+1:
			raise Notify(3,10,msg)

		return mask,size

	@staticmethod
	def decode (bgp):
		mask,size = EAM._decode_mask(bgp, 'could not decode CIDR4')
		addr4,mask4 = bgp[1:size+1] + padding(IP.length(AFI.ipv4)-size), mask
		bgp = bgp[size+1:]
		mask,size = EAM._decode_mask(bgp, 'could not decode CIDR6')
		addr6,mask6 = bgp[1:size+1] + padding(IP.length(AFI.ipv6)-size), mask

		return addr4,mask4,addr6,mask6,bgp[size+1:]

		# data = bgp[1:size+1] + '\x0\x0\x0\x0'
		# return data[:4], mask

	@classmethod
	def unpack (cls, data):
		addr4,mask4,addr6,mask6,bgp = cls.decode(data)
		return cls(CIDR(addr4,mask4),CIDR(addr6,mask6)),bgp

	def __len__ (self):
		return len(self._cidr4) + len(self._cidr4)

	def __hash__ (self):
		return hash(self.pack_nlri())

EAM.NOEAM = EAM(CIDR('',0), CIDR('',0))
