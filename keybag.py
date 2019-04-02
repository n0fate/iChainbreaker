from crypto.aes import AESdecryptCBC
from crypto.aes import AESencryptCBC
from crypto.aeswrap import AESUnwrap
import hmac
from crypto.pbkdf2 import pbkdf2
import hashlib

sha256 = hashlib.sha256
sha1 = hashlib.sha1

import sys
import struct
import uuid
from binascii import hexlify, unhexlify

from ctypes import *

KEYBAG_DATA = '>4sI'
KEYBAG_DATA_SIZE = 8
KEYBAG_HEADER = '>4sII4sII4sI16s4sI40s4sII4sI20s4sII'
KEYBAG_HEADER_SIZE = 148
KEYBAG_SIGN = '>4sI20s'
KEYBAG_SIGN_SIZE = 28

class _tlvint(BigEndianStructure):
    _fields_ = [
            ("type", c_char*4),
            ("length", c_uint32),
            ("value", c_uint32)
        ]

class _tlvuuid(BigEndianStructure):
    _fields_ = [
            ("type", c_char*4),
            ("length", c_uint32),
            ("value", c_ubyte*16)
        ]

class _tlvsalt(BigEndianStructure):
    _fields_ = [
            ("type", c_char*4),
            ("length", c_uint32),
            ("value", c_ubyte*20)
        ]

class _tlvhmac(BigEndianStructure):
    _fields_ = [
            ("type", c_char*4),
            ("length", c_uint32),
            ("value", c_ubyte*40)
        ]

class _keybag_sign(BigEndianStructure):
    _fields_ = [
            ("type", c_char*4),
            ("length", c_uint32),
            ("value", c_ubyte*20)
        ]

class _keybag_header(BigEndianStructure):
    _fields_ = [
            ("vers", _tlvint),
            ("type", _tlvint),
            ("uuid", _tlvuuid),
            ("hmck", _tlvhmac),
            ("wrap", _tlvint),
            ("salt", _tlvsalt),
            ("iter", _tlvint)
        ]

class _keybag_data(BigEndianStructure):
    _fields_ = [
        ("data", c_char*4),
        ("datasize", c_uint32)
        ]

def _memcpy(buf, fmt):
    return cast(c_char_p(buf), POINTER(fmt)).contents

def tlvs(data):
    '''TLVs parser generator'''
    while data:
        try:
            type, length = struct.unpack('!4sI', data[:8])
            value = struct.unpack('!%is'%length, data[8:8+length])[0]
        except:
            print "Unproper TLV structure found: ", (data,)
            break
        yield type, value
        data = data[8+length:]


# 'kc_parse_keyclass' in binary named 'secd'
def get_class_name(classnum):
    if classnum == 1:
        return 'NSFileProtectionComplete'
    elif classnum == 2:
        return 'NSFileProtectionCompleteUnlessOpen'
    elif classnum == 3:
        return 'NSFileProtectionCompleteUtilUserAuthentication'
    elif classnum == 4:
        return 'NSFileProtectionNone'
    elif classnum == 5:
        return 'NSFileProtectionRecovery'
    elif classnum == 6:
        return 'kSecAttrAccessibleWhenUnlocked'
    elif classnum == 7:
        return 'kSecAttrAccessibleAfterFirstUnlock'
    elif classnum == 8:
        return 'kSecAttrAccessibleAlways'
    elif classnum == 9:
        return 'kSecAttrAccessibleWhenUnlockedThisDeviceOnly'
    elif classnum == 10:
        return 'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly'
    elif classnum == 11:
        return 'kSecAttrAccessibleAlwaysThisDeviceOnly'
    elif classnum == 12:
        return 'kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly'
    else:
        return 'unknown'


def get_key_type(keytypenum):
    if keytypenum == 0:
        return 'AES with GCM'
    elif keytypenum == 1:
        return 'Curve25519'
    else:
        return 'unknown'


def get_wrap_name(wrapnum):
    if wrapnum == 1:
        return 'AES encrypted with device key'
    elif wrapnum == 3:
        return 'Wrapped key after AES encrypted with device key'
    else:
        return 'unknown'


class Keybag():
    def __init__(self, filepath):
        self.devicekey = ''
        self.endofdata = 0

        self.keybag = {}

        self.keyring = {}   # Password Set

        try:
            fhandle = open(filepath, 'rb')
        except:
            print '[-] Keybag open failed'
            sys.exit()
        self.fbuf = fhandle.read()
        fhandle.close()

    def Decryption(self):

        if self.keybag['version'] >= 5:
            wrap_iv_digest = sha256(struct.pack('<ll', 0, 5))
            wrap_iv_digest.update(unhexlify(self.keybag['salt']))
            key_store_wrap_iv = wrap_iv_digest.digest()[:16]

        dict = {}
        for type, data in tlvs(self.fbuf[KEYBAG_DATA_SIZE+KEYBAG_HEADER_SIZE:self.endofdata]):
            #if type == 'UUID':
                #print '%s : %s'%(type, uuid.UUID(bytes=data) )
            if type == 'CLAS':
                #print ' [-] %s : %s %d'%(type, get_class_name(int(hexlify(data), 16) ), int(hexlify(data), 16))
                dict['CLAS'] = int(hexlify(data), 16)
            elif type == 'WRAP':
                #print ' [-] %s : %s'%(type, get_wrap_name(int(hexlify(data), 16) ))
                dict['WRAP'] = int(hexlify(data), 16)
            elif type == 'KTYP':
                #print ' [-] %s : %s'%(type, get_key_type(int(hexlify(data), 16) ))
                dict['KTYP'] = int(hexlify(data), 16)
            elif type == 'WPKY':
                decryptedkey = ''
                
                if dict['WRAP'] == 1:
                    decryptedkey = AESdecryptCBC(data, self.devicekey)
                    #print ' [-] Decrypted Key : %s'%hexlify(decryptedkey)
                elif dict['WRAP'] == 3:
                    if self.keybag['version'] >= 5:
                        data = AESdecryptCBC(data[:32], self.devicekey, key_store_wrap_iv) + data[32:40]

                    try:
                        unwrapped = AESUnwrap(self.passcodekey, data)
                    except ValueError:
                        print '[!] Invalid Password. Enter the valid user password'
                        sys.exit()

                    if self.keybag['version'] >= 5:
                        decryptedkey = unwrapped
                    else:
                        decryptedkey = AESdecryptCBC(unwrapped, self.devicekey)
                        #print ' [-] Decrypted Key : %s'%hexlify(decryptedkey)

                self.keyring[dict['CLAS']] = decryptedkey  # Key

    def GetKeybyClass(self, classnum):
        key = ''
        try:
            key = self.keyring[classnum]
        except:
            key = ''
        return key

    def load_keybag_header(self):
        keybag_data = _memcpy(self.fbuf[:sizeof(_keybag_data)], _keybag_data)
        endofdata = sizeof(keybag_data) + keybag_data.datasize
        self.endofdata = endofdata

        self.keybag['data'] = self.fbuf[sizeof(_keybag_data):endofdata]

        keybag_sign = _memcpy(self.fbuf[endofdata:endofdata+sizeof(_keybag_sign)], _keybag_sign)
        self.keybag['sign'] = hexlify(keybag_sign.value)

        keybag_header = _memcpy(self.fbuf[sizeof(_keybag_data):sizeof(_keybag_data)+sizeof(_keybag_header)], _keybag_header)

        #if keybag_header[0] == 'VERS':
        self.keybag['version'] = keybag_header.vers.value

        #if keybag_header[3] == 'TYPE':
        self.keybag['type'] = keybag_header.type.value

        #if keybag_header[6] == 'UUID':
        self.keybag['uuid'] = keybag_header.uuid.value

        #if keybag_header[9] == 'HMCK':
        self.keybag['hmck'] = hexlify(keybag_header.hmck.value)

        #if keybag_header[12] == 'WRAP':
        self.keybag['wrap'] = get_wrap_name(keybag_header.wrap.value)

        #if keybag_header[15] == 'SALT':
        self.keybag['salt'] = hexlify(keybag_header.salt.value)

        #if keybag_header[18] == 'ITER':
        self.keybag['iter'] = keybag_header.iter.value

    def get_keybag_type(self, typenum):
        if typenum == 0:
            return 'System Keybag'
        elif typenum == 1:
            return 'Backup Keybag'
        elif typenum == 2:
            return 'Escrow Keybag'
        elif typenum == 3:
            return 'iCloud Keybag'

    def get_wrap_type(self, wraptype):
        if wraptype == 0:
            return 'Wrapped key after AES encrypted with device key'
        elif wraptype == 1:
            return 'AES encrypted with device key'

    def debug_print_header(self):
        print '[+] Keybag Header'
        print ' [-] versions : %d'%self.keybag['version']
        print ' [-] type : %s'%self.get_keybag_type(self.keybag['type'])
        print ' [-] uuid : %s'%uuid.UUID(bytes=str(bytearray(self.keybag['uuid'])))
        print ' [-] hmac key : %s'%self.keybag['hmck']
        print ' [-] wrap : %s'%(self.get_wrap_type(self.keybag['wrap']))
        print ' [-] salt : %s'%self.keybag['salt']
        print ' [-] iteration count : %d'%self.keybag['iter']
        print ' [-] Signature : %s'%(self.keybag['sign'])

    def generatepasscodekey(self, passcode):
        passcodekey_prf = pbkdf2(passcode, unhexlify(self.keybag['salt']), 1, 32, sha1)
        #print 'The PRF passcode key is %s'%hexlify(passcodekey_prf)
        self.passcodekey = self.tangle_with_hardware(passcodekey_prf, 32, self.keybag['iter'])
        return self.passcodekey

    def xor(self, data, key):
        index = len(data) % 4
        size = (4, 1, 2, 1)[index]
        type = ('L', 'B', 'H', 'B')[index]
        key_len = len(key)/size
        data_len = len(data)/size
        key_fmt = "<" + str(key_len) + type
        data_fmt = "<" + str(data_len) + type

        key_list = struct.unpack(key_fmt, key)
        data_list = struct.unpack(data_fmt, data)

        result = []
        for i in range(data_len):
            result.append (key_list[i % key_len] ^ data_list[i])

        return struct.pack(data_fmt, *result)

    def fill_buffer(self, BufSize, PRFKey, PRFKeyLen, xorKey):
        NewHeap = ''
        NewXorKey = xorKey
        Count = 0
        while Count < BufSize:
            xoredPRFKey = ''

            for inOffset in range(0, PRFKeyLen, 4):
                xoredPRFKey += self.xor(PRFKey[inOffset:inOffset+4], struct.pack('i', NewXorKey))
            NewXorKey += 1
            NewHeap += xoredPRFKey
            Count += PRFKeyLen
        return NewXorKey, NewHeap

    def hw_crypt_aligned(self, EncryptMethod, Unknown, filled_buf, BufSize, Version):
        encrypted_buf = AESencryptCBC(filled_buf, self.devicekey)
        return encrypted_buf

    def xor_buffer(self, encryptedbuf, BUFSize, passcodePRFKey, Count):
        KeySize = 32
        NewHeap = passcodePRFKey
        sCount = 0
        while sCount < Count:
            NewHeap = self.xor(NewHeap, encryptedbuf[sCount*KeySize:sCount*KeySize+KeySize])
            sCount += 1
        return NewHeap

    # tangle with hardware
    def tangle_with_hardware(self, PRFKey, PRFKeyLen, itercount):
        DERIVATION_BUFFER_SIZE = 4096
        nBlock = DERIVATION_BUFFER_SIZE / PRFKeyLen    # 4096 / 32 = 128
        xorkey = 1
        passcodePRFKey = PRFKey

        while itercount > 0:
            newxorkey, filled_buf = self.fill_buffer(DERIVATION_BUFFER_SIZE, PRFKey, PRFKeyLen, xorkey)
            xorkey = newxorkey

            encrypted_buf = self.hw_crypt_aligned(1, 0, filled_buf, DERIVATION_BUFFER_SIZE, 2)

            Count = nBlock
            if Count >= itercount:
                Count = itercount
            passcodePRFKey = self.xor_buffer(encrypted_buf, PRFKeyLen*nBlock, passcodePRFKey, Count)
            
            itercount -= Count
        return passcodePRFKey

    # 16bit input -> 32bit output
    # Code : AppleKeyStore.kext -> AppleKeyStore::device_key_init()
    def device_key_init(self, IOPlatformUUID):
        salt = ''
        self.devicekey = pbkdf2(IOPlatformUUID, salt, 50000, 32, sha256)
        return self.devicekey

    def device_key_validation(self):
        if self.devicekey == '':
            return False

        if self.keybag['sign']:
            hmackey = AESUnwrap(self.devicekey, unhexlify(self.keybag['hmck']))
            sigcheck = hmac.new(key=hmackey, msg=self.keybag['data'], digestmod=sha1).digest()
            if hexlify(sigcheck) != self.keybag['sign']:
                return False
        else:
            return False
        return True


def main():
    try:
        if len(sys.argv) != 3:
            print 'Debug error'
            sys.exit()

    except IndexError:
        print 'Debug error'
        sys.exit()

    try:
        f = open(sys.argv[1], 'rb')
    except IOError:
        print '[+] WARNING!! Can not open keybag.'
        sys.exit()


    keybag = Keybag(sys.argv[1])
    keybag.load_keybag_header()
    keybag.debug_print_header()
    devicekey = keybag.device_key_init(sys.argv[2])
    print 'device key is %s'%hexlify(devicekey)

    keybag.device_key_validation()


    keybag.generatepasscodekey(sys.argv[3])

if __name__ == "__main__":
    main()
