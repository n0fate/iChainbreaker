import struct

from biplist import readPlistFromString

from crypto.aeswrap import AESUnwrap
from crypto.gcm import gcm_decrypt
from itemv7_pb2 import ItemV7Protobuf


def ns_keyed_unarchiver(plist):
    """
    Convert parsed NSKeyedArchiver plist to Python dict.

    Supports only a very small subset of NSKeyedArchiver functionality.
    """
    if plist['$version'] != 100000:
        raise ValueError()
    if plist['$archiver'] != 'NSKeyedArchiver':
        raise ValueError()

    objs = plist['$objects']

    root_index = plist['$top']['root'].integer
    root_info = objs[root_index]

    class_info = objs[root_info['$class'].integer]
    ret = {'$class': class_info['$classname']}

    for arg_name, uid_ref in root_info.items():
        if arg_name == '$class':
            continue

        index = uid_ref.integer
        ret[arg_name] = objs[index]
    return ret

class ItemV7(object):
    "Keychain item in V7 format, with parsing and decryption support."

    def __init__(self, data):
        "Create a new ItemV7 from binary data"
        self.data = data
        self.version = struct.unpack("<L", data[:4])[0]
        if self.version != 7:
            raise Exception("This parser is for version 7, not {}".format(self.version))
        self.protobuf_item = ItemV7Protobuf()
        self.protobuf_item.ParseFromString(data[4:])

        self.keyclass = self.protobuf_item.keyclass
        self.encrypted_secret_data_wrapped_key = self.protobuf_item.encryptedSecretData.wrappedKey.wrappedKey

    def decrypt_secret_data(self, class_key):
        key = AESUnwrap(class_key, self.encrypted_secret_data_wrapped_key)
        if not key:
            raise ValueError("Failed to unwrap key. Bad class key?")

        plist = readPlistFromString(self.protobuf_item.encryptedSecretData.ciphertext)
        authenticated = ns_keyed_unarchiver(plist)
        decrypted = gcm_decrypt(key,
                                authenticated['SFInitializationVector'],
                                authenticated['SFCiphertext'], '',
                                authenticated['SFAuthenticationCode'])

        if not decrypted:
            raise ValueError("Failed to decrypt")

        return decrypted

    def decrypt_metadata(self, metadata_class_key):
        wrapped_plist = readPlistFromString(self.protobuf_item.encryptedMetadata.wrappedKey)
        wrapped_sf_params = ns_keyed_unarchiver(wrapped_plist)

        metadata_key = gcm_decrypt(metadata_class_key,
                                wrapped_sf_params['SFInitializationVector'],
                                wrapped_sf_params['SFCiphertext'], '',
                                wrapped_sf_params['SFAuthenticationCode'])

        if not metadata_key:
            raise ValueError("Failed to decrypt metadata key")

        ciphertext = ns_keyed_unarchiver(readPlistFromString(
            self.protobuf_item.encryptedMetadata.ciphertext))

        metadata =  gcm_decrypt(metadata_key,
                                ciphertext['SFInitializationVector'],
                                ciphertext['SFCiphertext'], '',
                                ciphertext['SFAuthenticationCode'])

        if not metadata:
            raise ValueError("Failed to decrypt metadata")

        return metadata
