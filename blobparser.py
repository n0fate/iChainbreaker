from pyasn1.codec.der import decoder
from pyasn1 import debug
import datetime

# Reference : https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55044/lib/SecItem.h
# Reference : https://opensource.apple.com/source/Security/Security-57740.51.3/OSX/sec/Security/SecItemConstants.c.auto.html

AUTH_TYPE = {
    'ntlm': 'NTLM',
    'msna': 'MSN',
    'dpaa': 'DPA',
    'rpaa': 'RPA',
    'http': 'HTTPBasic',
    'httd': 'HTTPDigest',
    'form': 'HTMLForm',
    'dflt': 'Default',
    '': 'Any',
    '\x00\x00\x00\x00': 'Any'
}

PROTOCOL_TYPE = {
    'ftp ': 'FTP',
    'ftpa': 'FTPAccount',
    'http': 'HTTP',
    'irc ': 'IRC',
    'nntp': 'NNTP',
    'pop3': 'POP3',
    'smtp': 'SMTP',
    'sox ': 'SOCKS',
    'imap': 'IMAP',
    'ldap': 'LDAP',
    'atlk': 'AppleTalk',
    'afp ': 'AFP',
    'teln': 'Telnet',
    'ssh ': 'SSH',
    'ftps': 'FTPS',
    'htps': 'HTTPS',
    'htpx': 'HTTPProxy',
    'htsx': 'HTTPSProxy',
    'ftpx': 'FTPProxy',
    'cifs': 'CIFS',
    'smb ': 'SMB',
    'rtsp': 'RTSP',
    'rtsx': 'RTSPProxy',
    'daap': 'DAAP',
    'eppc': 'EPPC',
    'ipp ': 'IPP',
    'ntps': 'NNTPS',
    'ldps': 'LDAPS',
    'tels': 'TelnetS',
    'imps': 'IMAPS',
    'ircs': 'IRCS',
    'pops': 'POP3S',
    'cvsp': 'CVS server',
    'svn ': 'SVN server',
    'AdIM': 'Adium Messenger',
    'pops': 'POP3',
    '0': 'Any'
}


# http://www.opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55035/lib/SecItemConstants.c
SEC_CONST_DECL = {
    'cdat': 'Creation Date',
    'mdat': 'Modification Date',
    'labl': 'Label',
    'data': 'EncryptedData',
    'agrp': 'AccessGroup',
    'pdmn': 'Accessible',
    'sync': 'Sync',
    'tomb': 'UnAvailiable(guess)',
    'v_Data': 'Data',
    'crtr': 'KeyCreator',
    'alis': 'Alias',
    'desc': 'Description',
    'icmt': 'Comment',
    'type': 'Type',
    'invi': 'Invisible',
    'nega': 'Negative',
    'cusi': 'CUSI',
    'prot': 'Proto',
    'scrp': 'Script Code',
    'acct': 'Account',
    'svce': 'Service',
    'gena': 'General',
    'sdmn': 'Security Domain',
    'srvr': 'Server',
    'ptcl': 'Protocol',
    'atyp': 'Authentication Type',
    'port': 'Port',
    'path': 'Path',
    # cert only
    'ctyp': 'certificate Type',
    'cenc': 'Certificate Encoding',
    'subj': 'Subject',
    'issr': 'Issuer',
    'slnr': 'SerialNumber',
    'skid': 'SubjectKeyID',
    'pkhh': 'PublicKeyHash',
    'atag': 'ApplicationTag',
    'bsiz': 'KeySizeinBits',
    'esiz': 'kSecAttrEffectiveKeySize',
    'sdat': 'StartDate',
    'edat': 'EndDate',
    'sens': 'IsSensitive',
    'asen': 'WasAlwaysSensitive',
    'extr': 'IsExtractable',
    'next': 'WasNeverExtractable',
    'encr': 'CanEncrypt',
    'decr': 'CanDecrypt',
    'drve': 'CanDerive',
    'sign': 'CanSign',
    'vrfy': 'CanVerify',
    'snrc': 'CanSignRecover',
    'vyrc': 'CanVerifyRecover',
    'wrap': 'CanWrap',
    'unwp': 'CanUnwrap',
    'crle': 'CRLEncoding',
    'crlt': 'CRLType',
    'kcls': 'KeyClass',
    'klbl': 'ApplicationLabel',
    'perm': 'IsPermanent',
    'priv': 'IsPrivate',
    'modi': 'IsModifiable',
    'musr': 'MUSR',     # unknown
    'vwht': 'VWHT',      # unknown
    'TamperCheck': 'TamperCheck',
}

# http://www.opensource.apple.com/source/Security/Security-55179.13/sec/Security/SecItemConstants.c
kSecAttrAccessible = {
    'ak': 'AccessibleWhenUnlocked',
    'ck': 'AccessibleAfterFirstUnlock',
    'dk': 'AccessibleAlways',
    'aku': 'AccessibleWhenUnlockedThisDeviceOnly',
    'cku': 'AccessibleAfterFirstUnlockThisDeviceOnly',
    'dku': 'AccessibleAlwaysThisDeviceOnly',
    'akpu': 'kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly'
}

# https://opensource.apple.com/source/libsecurity_cssm/libsecurity_cssm-32993/lib/cssmtype.h
# CSSM_ALGORITHMS
kSecAttrKeyType = {
    0: 'CSSM_ALGID_NONE',
    14: 'CSSM_ALGID_DES',
    23: 'CSSM_ALGID_RC2',
    25: 'CSSM_ALGID_RC4',
    42: 'CSSM_ALGID_RSA',
    43: 'CSSM_ALGID_DSA',
    56: 'CSSM_ALGID_ConcatBaseAndKey',
    73: 'CSSM_ALGID_ECDSA',
    77: 'CSSM_ALGID_3DES',
    2147483649: 'CSSM_ALGID_LAST'
}


class BlobParser:
    def __init__(self):
        self.datadict = {}

    def GetColumnFullName(self, data):
        try:
            return SEC_CONST_DECL[data]
        except KeyError:
            return 'Unknown field %r' % data

    def GetProtoFullName(self, data):
        try:
            return PROTOCOL_TYPE[data]
        except KeyError:
            return 'Unknown Value'

    def GetAuthType(self, data):
        try:
            return AUTH_TYPE[data]
        except KeyError:
            return 'Unknown Value'

    def GetAccessibleName(self, data):
        try:
            return kSecAttrAccessible[data]
        except KeyError:
            return 'Unknown Value'

    def Getdate(self, data):
        try:
            return datetime.datetime.strptime(data.split('.')[0], '%Y%m%d%H%M%S')
        except ValueError:
            return datetime.datetime.strptime(data.split('.')[0], '%Y%m%d%H%M%S')

    def GetKeyType(self, data):
        return kSecAttrKeyType[data]

    def ParseIt(self, data, tblname, export):
        record = {}
        #debug.setLogger(debug.Debug('all'))
        Decoded, _ = decoder.decode(data)
        count = 0
        while 1:
            try:
                seq = Decoded.getComponentByPosition(count)
                k = seq.getComponentByPosition(0)
                data = '%s' % seq.getComponentByPosition(1)
            except:
                #print ' [-] Decrypted', count, 'items in', tblname
                break

            if k == 'atyp':
                data = self.GetAuthType(data)
            elif k == 'pdmn':
                data = self.GetAccessibleName(data)
            elif k == 'cdat' or k == 'mdat':
                data = self.Getdate(data)
            elif k == 'ptcl':
                data = self.GetProtoFullName(data)
            elif k == 'klbl':
                data = data.encode('hex')

            if export == 0:
                k = self.GetColumnFullName('%s'%k)
            record[k] = data
            count += 1

        return record

