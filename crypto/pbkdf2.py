#!/usr/bin/env python   

# A simple implementation of pbkdf2 using stock python modules. See RFC2898
# for details. Basically, it derives a key from a password and salt.

# (c) 2004 Matt Johnston <matt @ ucc asn au>
# This code may be freely used, distributed, relicensed, and modified for any
# purpose.

# Revision history
# v0.1  October 2004    - Initial release
# v0.2  8 March 2007    - Make usable with hashlib in Python 2.5 and use
# v0.3  ""                 the correct digest_size rather than always 20
# v0.4  13 March 2009   - Mention distribution and relicensing in the copyright

import sys
import hmac
from binascii import hexlify, unhexlify
from struct import pack
try:
	# only in python 2.5
	import hashlib
	sha = hashlib.sha1
	md5 = hashlib.md5
	sha256 = hashlib.sha256
except ImportError:
	# fallback
	import sha
	import md5

# this is what you want to call.
def pbkdf2( password, salt, itercount, keylen, hashfn = sha ):
	try:
		# depending whether the hashfn is from hashlib or sha/md5
		digest_size = hashfn().digest_size
	except TypeError:
		digest_size = hashfn.digest_size
	# l - number of output blocks to produce
	l = keylen / digest_size
	if keylen % digest_size != 0:
		l += 1

	h = hmac.new( password, None, hashfn )

	T = ""
	for i in range(1, l+1):
		T += pbkdf2_F( h, salt, itercount, i )

	return T[0: keylen]

def xorstr( a, b ):
	if len(a) != len(b):
		raise "xorstr(): lengths differ"

	ret = ''
	for i in range(len(a)):
		ret += chr(ord(a[i]) ^ ord(b[i]))

	return ret

def prf( h, data ):
	hm = h.copy()
	hm.update( data )
	return hm.digest()

# Helper as per the spec. h is a hmac which has been created seeded with the
# password, it will be copy()ed and not modified.
def pbkdf2_F( h, salt, itercount, blocknum ):
	U = prf( h, salt + pack('>i',blocknum ) )
	T = U

	for i in range(2, itercount+1):
		U = prf( h, U )
		T = xorstr( T, U )

	return T

		
def test():
	# test vector from rfc3211
	password = 'password'
	salt = unhexlify( '1234567878563412' )
	password = 'All n-entities must communicate with other n-entities via n-1 entiteeheehees'
	itercount = 500
	keylen = 16
	ret = pbkdf2( password, salt, itercount, keylen )
	hexret = ' '.join(map(lambda c: '%02x' % ord(c), ret)).upper()
	print "key:      %s" % hexret
	print "expected: 6A 89 70 BF 68 C9 2C AE A8 4A 8D F2 85 10 85 86"
	
	# from botan
	password = unhexlify('6561696D72627A70636F706275736171746B6D77')
	expect = 'C9A0B2622F13916036E29E7462E206E8BA5B50CE9212752EB8EA2A4AA7B40A4CC1BF'
	salt = unhexlify('45248F9D0CEBCB86A18243E76C972A1F3B36772A')
	keylen = 34
	itercount = 100
	ret = pbkdf2( password, salt, itercount, keylen )
	hexret = hexlify(ret).upper()
	print "key:      %s" % hexret
	print "expected: %s" % expect
	
	

if __name__ == '__main__':
	test()