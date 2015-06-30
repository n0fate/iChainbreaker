from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.ber.decoder import decode as ber_decode
import datetime

# it's test code. Do not trust result. ;p

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
    '\x00\x00\x00\x00': 'Any'
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
    'modi': 'IsModifiable'

}

# http://www.opensource.apple.com/source/Security/Security-55179.13/sec/Security/SecItemConstants.c
kSecAttrAccessible = {
    'ak': 'AccessibleWhenUnlocked',
    'ck': 'AccessibleAfterFirstUnlock',
    'dk': 'AccessibleAlways',
    'aku': 'AccessibleWhenUnlockedThisDeviceOnly',
    'cku': 'AccessibleAfterFirstUnlockThisDeviceOnly',
    'dku': 'AccessibleAlwaysThisDeviceOnly'
}

kSecAttrKeyType = {
    14: 'DES',
    23: 'RC2',
    25: 'RC4',
    42: 'RSA',
    43: 'DSA',
    56: 'CAST',
    73: 'ECDSA',
    77: '3DES',
    2147483649: 'AES'
}


class BlobParser:
    def __init__(self):
        self.datadict = {}

    def GetColumnFullName(self, data):
        return SEC_CONST_DECL[data]

    def GetProtoFullName(self, data):
        return PROTOCOL_TYPE[data]

    def GetAuthType(self, data):
        return AUTH_TYPE[data]

    def GetAccessibleName(self, data):
        return kSecAttrAccessible[data]

    def Getdate(self, data):
        return datetime.datetime.strptime(data, '%Y%m%d%H%M%S.%fZ')

    def GetKeyType(self, data):
        return kSecAttrKeyType[data]

    def ParseIt(self, data, tblname, export):
        record = {}
        Decoded = der_decode(data)[0]

        for k, v in Decoded: #self.datadict.items():
            data = '%s'%v
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

        return record

