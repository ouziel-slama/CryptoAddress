import ctypes
import ctypes.util
from base58 import base58_check_decode, base58_check_encode, rhash, dhash, base58_get_version
from hashlib import sha256
from base64 import b64decode
from re import match

ssl = ctypes.cdll.LoadLibrary (ctypes.util.find_library ('ssl') or 'libeay32')

# this specifies the curve used with ECDSA.
NID_secp256k1 = 714 # from openssl/obj_mac.h

POINT_CONVERSION_COMPRESSED = 2
POINT_CONVERSION_UNCOMPRESSED = 4

BITCOIN_MAGIC = "\x18Bitcoin Signed Message:\n"
TERRACOIN_MAGIC = "\x1ATerracoin Signed Message:\n"

# Thx to Sam Devlin for the ctypes magic 64-bit fix.
def check_result (val, func, args):
    if val == 0:
        raise ValueError
    else:
        return ctypes.c_void_p (val)

ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
ssl.EC_KEY_new_by_curve_name.errcheck = check_result

class CryptoAddress:

    def __init__(self, privkey=None, privkey_format='base58', passphrase=None, version=0, eckey=None, compressed=False):   
        if eckey is not None:
            self.eckey = eckey
        else:     
            self.eckey = ssl.EC_KEY_new_by_curve_name(NID_secp256k1)
        self.eckey_group = ssl.EC_KEY_get0_group(self.eckey)
        self.version = version
        self.compressed = compressed
        compression = (POINT_CONVERSION_COMPRESSED if self.compressed else POINT_CONVERSION_UNCOMPRESSED)
        ssl.EC_KEY_set_conv_form(self.eckey, compression)
        if eckey is None:
            if passphrase is not None:
                privkey = CryptoAddress.passphrase_to_private_key(passphrase)
                self.set_private_key(privkey, format='256-bit')
            elif privkey is not None:
                self.set_private_key(privkey, format=privkey_format)
            else:
                ssl.EC_KEY_generate_key(self.eckey)

    def __del__(self):
        if ssl:
            ssl.EC_KEY_free(self.eckey)
        self.eckey = None

    @staticmethod
    def passphrase_to_private_key(passphrase, rounds=1):
        private_key = passphrase.encode('utf8')
        for i in xrange(rounds):
            private_key = sha256(private_key).digest()
        return private_key.encode('hex')

    def set_private_key(self, key, format='base58'):
        if format=='base58':
            key = base58_check_decode(key, 128+self.version)          
        else:            
            key.decode('hex')
        self.compressed = len(key) == 33
        key = key[0:32]
        privkey = ssl.BN_bin2bn(key, len(key), ssl.BN_new())
        pubkey = ssl.EC_POINT_new(self.eckey_group)
        ssl.EC_POINT_mul(self.eckey_group, pubkey, privkey, None, None, None)
        ssl.EC_KEY_set_private_key(self.eckey, privkey)
        ssl.EC_KEY_set_public_key(self.eckey, pubkey)

    def get_private_key(self, format='base58'):                    
        bn = ssl.EC_KEY_get0_private_key(self.eckey);
        bytes = (ssl.BN_num_bits(bn) + 7) / 8
        mb = ctypes.create_string_buffer(bytes)
        n = ssl.BN_bn2bin(bn, mb);
        if format=='base58':
            payload = mb.raw
            if self.compressed:
                payload = mb.raw + chr(1)
            return base58_check_encode(payload, 128+self.version)
        return mb.raw.encode('hex')

    def get_public_key(self, encode='hex'):
        size = ssl.i2o_ECPublicKey(self.eckey, 0)
        mb = ctypes.create_string_buffer(size)
        ssl.i2o_ECPublicKey(self.eckey, ctypes.byref(ctypes.pointer(mb)))
        return mb.raw.encode('hex') if encode=='hex' else mb.raw 

    def get_address(self):
        pubkey = self.get_public_key(encode='raw')
        hash160 = rhash(pubkey) 
        addr = base58_check_encode(hash160, self.version)
        return addr

    def to_json(self):
        return {
            "address": self.get_address(),
            "public_key": self.get_public_key(),
            "private_key": {
                'base58': self.get_private_key(),
                '256-bit': self.get_private_key(format='256-bit')
            }
        }

    @staticmethod
    def verify_address(address, version=0):
        address = address.strip()
        if match(r"[a-zA-Z1-9]{27,35}$", address) is None:
            return False
        return base58_get_version(address)==version

    @staticmethod
    def verify_public_key(pubkey):
        hash160 = rhash(pubkey.decode('hex')) 
        addr = base58_check_encode(hash160, version=0)
        return CryptoAddress.verify_address(addr)

    @staticmethod
    def verify_message(address, signature, message):
        eckey = ssl.EC_KEY_new_by_curve_name (NID_secp256k1)
        message = BITCOIN_MAGIC + chr(len(message)) + message
        hash = dhash(message)

        sig = b64decode(signature)
        if len(sig) != 65:
            raise BaseException("Wrong encoding")
        nV = ord(sig[0])
        if nV < 27 or nV >= 35:
            return False
        if nV >= 31:
            ssl.EC_KEY_set_conv_form(eckey, POINT_CONVERSION_COMPRESSED)
            nV -= 4
        
        r = ssl.BN_bin2bn (sig[1:33], 32, ssl.BN_new())
        s = ssl.BN_bin2bn (sig[33:], 32, ssl.BN_new())
        msg = hash
        msglen = len(hash)
        recid = nV - 27
        check = False
        #ECDSA_SIG_recover_key_GFp(eckey, r, s, msg, msglen, recid, check)
        n = 0
        i = recid / 2
        group = ssl.EC_KEY_get0_group(eckey)
        ctx = ssl.BN_CTX_new()
        ssl.BN_CTX_start(ctx)
        order = ssl.BN_CTX_get(ctx)
        ssl.EC_GROUP_get_order(group, order, ctx)
        x = ssl.BN_CTX_get(ctx)
        ssl.BN_copy(x, order);
        ssl.BN_mul_word(x, i);
        ssl.BN_add(x, x, r)
        field = ssl.BN_CTX_get(ctx)
        ssl.EC_GROUP_get_curve_GFp(group, field, None, None, ctx)

        if (ssl.BN_cmp(x, field) >= 0):
            return False

        R = ssl.EC_POINT_new(group)
        ssl.EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)

        if check:
            O = ssl.EC_POINT_new(group)
            ssl.EC_POINT_mul(group, O, None, R, order, ctx)
            if ssl.EC_POINT_is_at_infinity(group, O):
                return False

        Q = ssl.EC_POINT_new(group)
        n = ssl.EC_GROUP_get_degree(group)
        e = ssl.BN_CTX_get(ctx)
        ssl.BN_bin2bn(msg, msglen, e)
        if 8 * msglen > n: ssl.BN_rshift(e, e, 8 - (n & 7))

        zero = ssl.BN_CTX_get(ctx)
        ssl.BN_set_word(zero, 0)
        ssl.BN_mod_sub(e, zero, e, order, ctx)
        rr = ssl.BN_CTX_get(ctx);
        ssl.BN_mod_inverse(rr, r, order, ctx)
        sor = ssl.BN_CTX_get(ctx)
        ssl.BN_mod_mul(sor, s, rr, order, ctx)
        eor = ssl.BN_CTX_get(ctx)
        ssl.BN_mod_mul(eor, e, rr, order, ctx)
        ssl.EC_POINT_mul(group, Q, eor, R, sor, ctx)
        ssl.EC_KEY_set_public_key(eckey, Q)

        eckey = CryptoAddress(eckey=eckey, compressed=True)
        addr = eckey.get_address()
        #print "addr: %s\n" % addr
        return (address == addr)

    @staticmethod
    def add_public_keys(pubkey1_hex, pubkey2_hex, version=0):
        eckey = ssl.EC_KEY_new_by_curve_name(NID_secp256k1)
        group = ssl.EC_KEY_get0_group(eckey)
        pubkey1_point = ssl.EC_POINT_hex2point(group, pubkey1_hex, None, None)
        pubkey2_point = ssl.EC_POINT_hex2point(group, pubkey2_hex, None, None)
        ssl.EC_POINT_add(group, pubkey1_point, pubkey1_point, pubkey2_point, None)
        ssl.EC_KEY_set_public_key(eckey, pubkey1_point)
        eckey = CryptoAddress(eckey=eckey)
        pubkey, addr =  get_pubkey_and_address(eckey, version)
        return {
            'public_key': eckey.get_public_key(),
            'address': eckey.get_address()
        }


    