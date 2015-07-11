import os
import uuid
import argparse

from binascii import hexlify
import sys
from keybag import Keybag
from blobparser import BlobParser
import sqlite3 as lite
from hexdump import hexdump

from exportDB import ExporySQLiteDB

from crypto.aeswrap import aes_unwrap_key
from crypto.gcm import gcm_decrypt
from ctypes import *

class _EncryptedBlobHeader(LittleEndianStructure):
    _fields_ = [
        ('version', c_uint32),
        ('clas', c_uint32),
        ('length', c_uint32)
    ]
def _memcpy(buf, fmt):
    return cast(c_char_p(buf), POINTER(fmt)).contents


def GetTableFullName(table):
    if table == 'genp':
        return 'Generic Password'
    elif table == 'inet':
        return 'Internet Password'
    elif table == 'cert':
        return 'Certification'
    elif table == 'keys':
        return 'Keys'
    else:
        return 'Unknown'

def main():


    parser = argparse.ArgumentParser(description='Tool for iCloud Keychain Analysis by @n0fate')
    parser.add_argument('-p', '--path', nargs=1, help='iCloud Keychain Path(~/Library/Keychains/[UUID]/)', required=True)
    parser.add_argument('-k', '--key', nargs=1, help='User Password', required=True)
    parser.add_argument('-x', '--exportfile', nargs=1, help='Write a decrypted contents to SQLite file (optional)', required=False)

    args = parser.parse_args()

    Pathoficloudkeychain = args.path[0]

    if os.path.isdir(Pathoficloudkeychain) is False:
        print '[!] Path is not directory'
        parser.print_help()
        sys.exit()

    if os.path.exists(Pathoficloudkeychain) is False:
        print '[!] Path is not exists'
        parser.print_help()
        sys.exit()

    export = 0
    if args.exportfile is not None:

        if os.path.exists(args.exportfile[0]):
            print '[*] Export DB File is exists.'
            sys.exit()
        export = 1

    # Start to analysis
    print 'Tool for iCloud Keychain Analysis by @n0fate'

    MachineUUID = os.path.basename(os.path.normpath(Pathoficloudkeychain))
    PathofKeybag = os.path.join(Pathoficloudkeychain, 'user.kb')
    PathofKeychain = os.path.join(Pathoficloudkeychain, 'keychain-2.db')

    print '[*] UUID : %s'%MachineUUID
    print '[*] Keybag : %s'%PathofKeybag
    print '[*] iCloud Keychain File : %s'%PathofKeychain

    if os.path.exists(PathofKeybag) is False or os.path.exists(PathofKeychain) is False:
        print '[!] Can not found KeyBag or iCloud Keychain File'
        sys.exit()

    keybag = Keybag(PathofKeybag)
    keybag.load_keybag_header()
    keybag.debug_print_header()

    devicekey = keybag.device_key_init(uuid.UUID(MachineUUID).bytes)
    print '[*] The Device key : %s'%hexlify(devicekey)

    bresult = keybag.device_key_validation()

    if bresult == False:
        print '[!] Device Key validation : Failed. Maybe Invalid PlatformUUID'
        return
    else:
        print '[*] Device Key validation : Pass'

    passcodekey = keybag.generatepasscodekey(args.key[0])

    print '[*] The passcode key : %s'%hexlify(passcodekey)

    keybag.Decryption()

    con = lite.connect(PathofKeychain)
    con.text_factory = str
    cur = con.cursor()
    
    tablelist = ['genp', 'inet', 'cert', 'keys']

    if export:
        # Create DB
        exportDB = ExporySQLiteDB()
        exportDB.createDB(args.exportfile[0])
        print '[*] Export DB Name : %s'%args.exportfile[0]


    for tablename in tablelist:
        if export is not 1:
            print '[+] Table Name : %s'%GetTableFullName(tablename)
        try:
            cur.execute("SELECT data FROM %s"%tablename)
        except lite.OperationalError:
            continue

        if export:
            # Get Table Schema
            sql = con.execute("pragma table_info('%s')"%tablename).fetchall()

            # Create a table
            exportDB.createTable(tablename, sql)

        for data, in cur:
            encblobheader = _memcpy(data[:sizeof(_EncryptedBlobHeader)], _EncryptedBlobHeader)
            encblobheader.clas &= 0x0F

            wrappedkey = data[sizeof(_EncryptedBlobHeader):sizeof(_EncryptedBlobHeader)+encblobheader.length]
            encrypted_data = data[sizeof(_EncryptedBlobHeader)+encblobheader.length:-16]

            key = keybag.GetKeybyClass(encblobheader.clas)

            if key == '':
                print '[!] Could not found any key at %d'%encblobheader.clas
                continue

            unwrappedkey = aes_unwrap_key(key, wrappedkey)
            decrypted = gcm_decrypt(unwrappedkey, "", encrypted_data, "", data[-16:])

            if len(decrypted) is 0:
                continue
            
            if export is 0:
                print '[+] DECRYPTED INFO'
            
            blobparse = BlobParser()
            record = blobparse.ParseIt(decrypted, tablename, export)

            if export is 0:
                for k, v in record.items():
                    if k == 'Data':
                        print ' [-]', k
                        hexdump(v)
                    elif k == 'Type' and GetTableFullName(tablename) == 'Keys':
                        print ' [-]', k, ':', blobparse.GetKeyType(int(v))
                    else:
                        print ' [-]', k, ':', v
                print ''
            else:   # export is 1
                record_lst = []
                for k, v in record.items():
                    record_lst.append([k,v])

                exportDB.insertData(tablename, record_lst)

    if export:
        exportDB.commit()
        exportDB.close()

    cur.close()
    con.close()

if __name__ == "__main__":
    main()
