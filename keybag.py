from crypto.aes import AESdecryptCBC
from crypto.aes import AESencryptCBC
from crypto.aeswrap import aes_unwrap_key
import hmac
from crypto.pbkdf2 import pbkdf2
import hashlib

sha256 = hashlib.sha256
sha1 = hashlib.sha1

import sys
import struct
import uuid
from binascii import hexlify, unhexlify

KEYBAG_DATA = '>4sI'
KEYBAG_DATA_SIZE = 8
KEYBAG_HEADER = '>4sII4sII4sI16s4sI40s4sII4sI20s4sII'
KEYBAG_HEADER_SIZE = 148
KEYBAG_SIGN = '>4sI20s'
KEYBAG_SIGN_SIZE = 28


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
        self.filepath = filepath
        self.fileoffset = 0
        self.fhandle = ''

        self.masterkey = ''
        self.devicekey = ''

        self.keybag = {'version':0, 'type':0, 'uuid':'', 'hmck':'', 'wrap':'', 'salt':'', 'iter':0, 'sign':''}

        self.sign_offset = 0

        self.keyring = {}   # Password Set

        try:
            self.fhandle = open(self.filepath, 'rb')
        except:
            print '[-] Keybag open failed'
        self.fbuf = self.fhandle.read()

    def Decryption(self):
        dict = {}
        for type, data in tlvs(self.fbuf[KEYBAG_DATA_SIZE+KEYBAG_HEADER_SIZE:self.sign_offset]):
            #if type == 'UUID':
                #print '%s : %s'%(type, uuid.UUID(bytes=data) )
            if type == 'CLAS':
                #print ' [-] %s : %s'%(type, get_class_name(int(hexlify(data), 16) ))
                dict['CLAS'] = int(hexlify(data), 16)
            elif type == 'WRAP':
                #print '%s : %s'%(type, get_wrap_name(int(hexlify(data), 16) ))
                dict['WRAP'] = int(hexlify(data), 16)
            #elif type == 'KTYP':
                #print '%s : %s'%(type, get_key_type(int(hexlify(data), 16) ))
            elif type == 'WPKY':
                decryptedkey = ''
                
                if dict['WRAP'] == 1:
                    decryptedkey = AESdecryptCBC(data, self.devicekey)
                    #print ' [-] Decrypted Key : %s'%hexlify(decryptedkey)
                elif dict['WRAP'] == 3:
                    try:
                        unwrapped = aes_unwrap_key(self.passcodekey, data)
                    except ValueError:
                        print '[!] Invalid Password. Enter the valid user password'
                        sys.exit()
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
        data_header = struct.unpack(KEYBAG_DATA, self.fbuf[:KEYBAG_DATA_SIZE])

        self.keybag['data'] = self.fbuf[KEYBAG_DATA_SIZE:KEYBAG_DATA_SIZE+data_header[1]]

        self.sign_offset = KEYBAG_DATA_SIZE + data_header[1]

        SignLength = struct.unpack('>I', self.fbuf[self.sign_offset:self.sign_offset+4])[0]
        self.keybag['sign'] = self.fbuf[self.sign_offset+4:self.sign_offset+4+SignLength]

        keybag_header = struct.unpack(KEYBAG_HEADER, self.fbuf[KEYBAG_DATA_SIZE:KEYBAG_DATA_SIZE+KEYBAG_HEADER_SIZE])

        if keybag_header[0] == 'VERS':
            self.keybag['version'] = keybag_header[2]

        if keybag_header[3] == 'TYPE':
            self.keybag['type'] = keybag_header[5]

        if keybag_header[6] == 'UUID':
            self.keybag['uuid'] = uuid.UUID(bytes=keybag_header[8])

        if keybag_header[9] == 'HMCK':
            self.keybag['hmck'] = hexlify(keybag_header[11])

        if keybag_header[12] == 'WRAP':
            self.keybag['wrap'] = get_wrap_name(keybag_header[14])

        if keybag_header[15] == 'SALT':
            self.keybag['salt'] = hexlify(keybag_header[17])

        if keybag_header[18] == 'ITER':
            self.keybag['iter'] = keybag_header[20]

        sign = struct.unpack(KEYBAG_SIGN, self.fbuf[self.sign_offset:])
        self.keybag['sign'] = hexlify(sign[2])

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
            return 'unknown'
        elif wraptype == 1:
            return 'AES encrypted with device key'

    def debug_print_header(self):
        print '[+] Header'
        print ' [-] versions : %d'%self.keybag['version']
        print ' [-] type : %s'%self.get_keybag_type(self.keybag['type'])
        print ' [-] UUID : %s'%self.keybag['uuid']
        print ' [-] HMCK : %s'%self.keybag['hmck']
        print ' [-] WRAP : %s'%(self.get_wrap_type(self.keybag['wrap']))
        print ' [-] SALT : %s'%self.keybag['salt']
        print ' [-] Iteration Count : %d'%self.keybag['iter']

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
            hmackey = aes_unwrap_key(self.devicekey, unhexlify(self.keybag['hmck']))
            sigcheck = hmac.new(key=hmackey, msg=self.keybag['data'], digestmod=sha1).digest()
            if hexlify(sigcheck) != self.keybag['sign']:
                return False
        else:
            return False
        return True


def main():
    try:
        if len(sys.argv) != 2:
            print 'index error'
            sys.exit()

    except IndexError:
        print 'index error'
        sys.exit()

    try:
        f = open(sys.argv[1], 'rb')
    except IOError:
        print '[+] WARNING!! Can not open keybag.'
        sys.exit()


    keybag = Keybag(sys.argv[1])
    keybag.load_keybag_header()
    keybag.debug_print_header()
    devicekey = keybag.device_key_init(uuid.UUID(sys.argv[2]).bytes)
    print 'device key is %s'%hexlify(devicekey)

    keybag.device_key_validation()


    keybag.generatepasscodekey(sys.argv[3])

if __name__ == "__main__":
    main()
