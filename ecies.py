# Simple ECIES encryption/decryption and signing library
# Source mainly extracted from https://github.com/spesmilo/electrum/blob/master/lib/bitcoin.py

import binascii
import hmac
import hashlib
import base64
import ecdsa

from ecdsa.ecdsa import curve_secp256k1, generator_secp256k1
from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point
from ecdsa.util import string_to_number, number_to_string

# AES encryption
try:
    from Cryptodome.Cipher import AES
except:
    AES = None

# backwards compat
# extended WIF for segwit (used in 3.0.x; but still used internally)
# the keys in this dict should be a superset of what Imported Wallets can import
SCRIPT_TYPES = {
    'p2pkh':0,
    'p2wpkh':1,
    'p2wpkh-p2sh':2,
    'p2sh':5,
    'p2wsh':6,
    'p2wsh-p2sh':7
}

# For Komodo
WIF_PREFIX = 0xBC

# For BitCoin
# WIF_PREFIX = 0x80

b58chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
assert len(b58chars) == 58

__b43chars = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:'
assert len(__b43chars) == 43


class Msqr(object):
    @staticmethod
    def modular_sqrt(a, p):
        """ Find a quadratic residue (mod p) of 'a'. p
        must be an odd prime.
        Solve the congruence of the form:
        x^2 = a (mod p)
        And returns x. Note that p - x is also a root.
        0 is returned is no square root exists for
        these a and p.
        The Tonelli-Shanks algorithm is used (except
        for some simple cases in which the solution
        is known from an identity). This algorithm
        runs in polynomial time (unless the
        generalized Riemann hypothesis is false).
        """
        # Simple cases
        #
        if Msqr.legendre_symbol(a, p) != 1:
            return 0
        elif a == 0:
            return 0
        elif p == 2:
            return p
        elif p % 4 == 3:
            return pow(a, (p + 1) // 4, p)
    
        # Partition p-1 to s * 2^e for an odd s (i.e.
        # reduce all the powers of 2 from p-1)
        #
        s = p - 1
        e = 0
        while s % 2 == 0:
            s //= 2
            e += 1
    
        # Find some 'n' with a legendre symbol n|p = -1.
        # Shouldn't take long.
        #
        n = 2
        while Msqr.legendre_symbol(n, p) != -1:
            n += 1
    
        # Here be dragons!
        # Read the paper "Square roots from 1; 24, 51,
        # 10 to Dan Shanks" by Ezra Brown for more
        # information
        #
    
        # x is a guess of the square root that gets better
        # with each iteration.
        # b is the "fudge factor" - by how much we're off
        # with the guess. The invariant x^2 = ab (mod p)
        # is maintained throughout the loop.
        # g is used for successive powers of n to update
        # both a and b
        # r is the exponent - decreases with each update
        #
        x = pow(a, (s + 1) // 2, p)
        b = pow(a, s, p)
        g = pow(n, s, p)
        r = e
    
        while True:
            t = b
            m = 0
            for m in range(r):
                if t == 1:
                    break
                t = pow(t, 2, p)
    
            if m == 0:
                return x
    
            gs = pow(g, 2 ** (r - m - 1), p)
            g = (gs * gs) % p
            x = (x * gs) % p
            b = (b * g) % p
            r = m

    @staticmethod
    def legendre_symbol(a, p):
        """ Compute the Legendre symbol a|p using
        Euler's criterion. p is a prime, a is
        relatively prime to p (if p divides
        a, then a|p = 0)
        Returns 1 if a has a square root modulo
        p, -1 otherwise.
        """
        ls = pow(a, (p - 1) // 2, p)
        return -1 if ls == p - 1 else ls


class MyVerifyingKey(ecdsa.VerifyingKey):
    @classmethod
    def from_signature(klass, sig, recid, h, curve):
        """ See http://www.secg.org/download/aid-780/sec1-v2.pdf, chapter 4.1.6 """
        from ecdsa import util, numbertheory
        curveFp = curve.curve
        G = curve.generator
        order = G.order()
        # extract r,s from signature
        r, s = util.sigdecode_string(sig, order)
        # 1.1
        x = r + (recid//2) * order
        # 1.3
        alpha = ( x * x * x  + curveFp.a() * x + curveFp.b() ) % curveFp.p()
        beta = Msqr.modular_sqrt(alpha, curveFp.p())
        y = beta if (beta - recid) % 2 == 0 else curveFp.p() - beta
        # 1.4 the constructor checks that nR is at infinity
        R = Point(curveFp, x, y, order)
        # 1.5 compute e from message:
        e = string_to_number(h)
        minus_e = -e % order
        # 1.6 compute Q = r^-1 (sR - eG)
        inv_r = numbertheory.inverse_mod(r,order)
        Q = inv_r * ( s * R + minus_e * G )
        return klass.from_public_point( Q, curve )

class MySigningKey(ecdsa.SigningKey):
    """Enforce low S values in signatures"""

    def sign_number(self, number, entropy=None, k=None):
        curve = SECP256k1
        G = curve.generator
        order = G.order()
        r, s = ecdsa.SigningKey.sign_number(self, number, entropy, k)
        if s > order//2:
            s = order - s
        return r, s

class EC_KEY(object):

    def __init__(self, k):
        secret = string_to_number(k)
        self.pubkey = ecdsa.ecdsa.Public_key( generator_secp256k1, generator_secp256k1 * secret )
        self.privkey = ecdsa.ecdsa.Private_key( self.pubkey, secret )
        self.secret = secret

    def get_public_key(self, compressed=True):
        return EC_KEY.bh2u(EC_KEY.point_to_ser(self.pubkey.point, compressed))

    def sign(self, msg_hash):
        private_key = MySigningKey.from_secret_exponent(self.secret, curve = SECP256k1)
        public_key = private_key.get_verifying_key()
        signature = private_key.sign_digest_deterministic(msg_hash, hashfunc=hashlib.sha256, sigencode = ecdsa.util.sigencode_string)
        assert public_key.verify_digest(signature, msg_hash, sigdecode = ecdsa.util.sigdecode_string)
        return signature

    def sign_message(self, message, is_compressed):
        message = EC_KEY.to_bytes(message, 'utf8')
        signature = self.sign(EC_KEY.Hash(EC_KEY.msg_magic(message)))
        for i in range(4):
            sig = bytes([27 + i + (4 if is_compressed else 0)]) + signature
            try:
                self.verify_message(sig, message)
                return sig
            except Exception as e:
                print(e)
                continue
        else:
            raise Exception("error: cannot sign message")

    def verify_message(self, sig, message):
        EC_KEY.assert_bytes(message)
        h = EC_KEY.Hash(EC_KEY.msg_magic(message))
        public_key, compressed = EC_KEY.pubkey_from_signature(sig, h)
        # check public key
        if EC_KEY.point_to_ser(public_key.pubkey.point, compressed) != EC_KEY.point_to_ser(self.pubkey.point, compressed):
            raise Exception("Bad signature")
        # check message
        public_key.verify_digest(sig[1:], h, sigdecode = ecdsa.util.sigdecode_string)

    @staticmethod
    def pubkey_from_signature(sig, h):
        if len(sig) != 65:
            raise Exception("Wrong encoding")
        nV = sig[0]
        if nV < 27 or nV >= 35:
            raise Exception("Bad encoding")
        if nV >= 31:
            compressed = True
            nV -= 4
        else:
            compressed = False
        recid = nV - 27
        return MyVerifyingKey.from_signature(sig[1:], recid, h, curve = SECP256k1), compressed

    @staticmethod
    def sha256(x):
        x = EC_KEY.to_bytes(x, 'utf8')
        return bytes(hashlib.sha256(x).digest())

    @staticmethod
    def Hash(x):
        x = EC_KEY.to_bytes(x, 'utf8')
        out = bytes(EC_KEY.sha256(EC_KEY.sha256(x)))
        return out

    @staticmethod
    def msg_magic(message):
        length = bytes.fromhex(EC_KEY.var_int(len(message)))
        return b"\x18Bitcoin Signed Message:\n" + length + message

    @staticmethod
    def rev_hex(s):
        return EC_KEY.bh2u(bytes.fromhex(s)[::-1])

    @staticmethod
    def int_to_hex(i, length=1):
        if not isinstance(i, int):
            raise TypeError('{} instead of int'.format(i))
        if i < 0:
            # two's complement
            i = pow(256, length) + i
        s = hex(i)[2:].rstrip('L')
        s = "0"*(2*length - len(s)) + s
        return EC_KEY.rev_hex(s)
    
    @staticmethod
    def var_int(i):
        # https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
        if i<0xfd:
            return EC_KEY.int_to_hex(i)
        elif i<=0xffff:
            return "fd"+EC_KEY.int_to_hex(i,2)
        elif i<=0xffffffff:
            return "fe"+EC_KEY.int_to_hex(i,4)
        else:
            return "ff"+EC_KEY.int_to_hex(i,8)
    
    @staticmethod
    def bh2u(x):
        """
        str with hex representation of a bytes-like object
        >>> x = bytes((1, 2, 10))
        >>> bh2u(x)
        '01020A'
        :param x: bytes
        :rtype: str
        """
        return binascii.hexlify(x).decode('ascii')

    @staticmethod
    def strip_PKCS7_padding(data):
        EC_KEY.assert_bytes(data)
        if len(data) % 16 != 0 or len(data) == 0:
            raise Exception("invalid length")
        padlen = data[-1]
        if padlen > 16:
            raise Exception("invalid padding byte (large)")
        for i in data[-padlen:]:
            if i != padlen:
                raise Exception("invalid padding byte (inconsistent)")
        return data[0:-padlen]

    @staticmethod
    def aes_decrypt_with_iv(key, iv, data):
        EC_KEY.assert_bytes(key, iv, data)
        if AES:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            data = cipher.decrypt(data)
        else:
            aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
            aes = pyaes.Decrypter(aes_cbc, padding=pyaes.PADDING_NONE)
            data = aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer
        return EC_KEY.strip_PKCS7_padding(data)
    
    @staticmethod
    def to_bytes(something, encoding='utf8'):
        """
        cast string to bytes() like object, but for python2 support it's bytearray copy
        """
        if isinstance(something, bytes):
            return something
        if isinstance(something, str):
            return something.encode(encoding)
        elif isinstance(something, bytearray):
            return bytes(something)
        else:
            raise TypeError("Not a string or bytes like object")
    
    @staticmethod
    def assert_bytes(*args):
        """
        porting helper, assert args type
        """
        try:
            for x in args:
                assert isinstance(x, (bytes, bytearray))
        except:
            print('assert bytes failed', list(map(type, args)))
            raise
    @staticmethod
    def ser_to_point(aser):
        curve = curve_secp256k1
        generator = generator_secp256k1
        _r  = generator.order()
        assert aser[0] in [0x02, 0x03, 0x04]
        if aser[0] == 0x04:
            return Point( curve, string_to_number(aser[1:33]), string_to_number(aser[33:]), _r )
        Mx = string_to_number(aser[1:])
        return Point( curve, Mx, EC_KEY.ECC_YfromX(Mx, curve, aser[0] == 0x03)[0], _r )

    @staticmethod
    def point_to_ser(P, comp=True ):
        if comp:
            return bytes.fromhex( ('%02x'%(2+(P.y()&1)))+('%064x'%P.x()) )
        return bytes.fromhex( '04'+('%064x'%P.x())+('%064x'%P.y()) )

    @staticmethod
    def ECC_YfromX(x,curved=curve_secp256k1, odd=True):
        _p = curved.p()
        _a = curved.a()
        _b = curved.b()
        for offset in range(128):
            Mx = x + offset
            My2 = pow(Mx, 3, _p) + _a * pow(Mx, 2, _p) + _b % _p
            My = pow(My2, (_p+1)//4, _p )
    
            if curved.contains_point(Mx,My):
                if odd == bool(My&1):
                    return [My,offset]
                return [_p-My,offset]
        raise Exception('ECC_YfromX: No Y found')
   
    @staticmethod
    def aes_encrypt_with_iv(key, iv, data):
        EC_KEY.assert_bytes(key, iv, data)
        data = EC_KEY.append_PKCS7_padding(data)
        if AES:
            e = AES.new(key, AES.MODE_CBC, iv).encrypt(data)
        else:
            aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
            aes = pyaes.Encrypter(aes_cbc, padding=pyaes.PADDING_NONE)
            e = aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer
        return e

    @staticmethod
    def append_PKCS7_padding(data):
        EC_KEY.assert_bytes(data)
        padlen = 16 - (len(data) % 16)
        return data + bytes([padlen]) * padlen

    @staticmethod
    def base_decode(v, length, base):
        """ decode v into a string of len bytes."""
        # assert_bytes(v)
        v = EC_KEY.to_bytes(v, 'ascii')
        if base not in (58, 43):
            raise ValueError('not supported base: {}'.format(base))
        chars = b58chars
        if base == 43:
            chars = b43chars
        long_value = 0
        for (i, c) in enumerate(v[::-1]):
            digit = chars.find(bytes([c]))
            if digit == -1:
                raise ValueError('Forbidden character {} for base {}'.format(c, base))
            long_value += digit * (base**i)
        result = bytearray()
        while long_value >= 256:
            div, mod = divmod(long_value, 256)
            result.append(mod)
            long_value = div
        result.append(long_value)
        nPad = 0
        for c in v:
            if c == chars[0]:
                nPad += 1
            else:
                break
        result.extend(b'\x00' * nPad)
        if length is not None and len(result) != length:
            return None
        result.reverse()

        return bytes(result)

    @staticmethod
    def base_encode(v, base=58):
        """ encode v, which is a string of bytes, to base58."""
        EC_KEY.assert_bytes(v)
        if base not in (58, 43):
            raise ValueError('not supported base: {}'.format(base))
        chars = b58chars
        if base == 43:
            chars = __b43chars
        long_value = 0
        for (i, c) in enumerate(v[::-1]):
            long_value += (256**i) * c
        result = bytearray()
        while long_value >= base:
            div, mod = divmod(long_value, base)
            result.append(chars[mod])
            long_value = div
        result.append(chars[long_value])
        # Bitcoin does a little leading-zero-compression:
        # leading 0-bytes in the input become leading-1s
        nPad = 0
        for c in v:
            if c == 0x00:
                nPad += 1
            else:
                break
        result.extend([chars[0]] * nPad)
        result.reverse()
        return result.decode('ascii')
    
    @staticmethod
    def EncodeBase58Check(vchIn):
        hash = EC_KEY.Hash(vchIn)
        return EC_KEY.base_encode(vchIn + hash[0:4], base=58)
    
    @staticmethod
    def DecodeBase58Check(psz):
        vchRet = EC_KEY.base_decode(psz, None, base=58)
        key = vchRet[0:-4]
        csum = vchRet[-4:]
        hash = EC_KEY.Hash(key)
        cs32 = hash[0:4]
        if cs32 != csum:
            raise Exception('Invalid checksum: expected {}, actual {}'.format(EC_KEY.bh2u(cs32), EC_KEY.bh2u(csum)))
        else:
            return key

    @staticmethod
    def inv_dict(d):
        return {v: k for k, v in d.items()}

    @staticmethod
    def deserialize_privkey(key):
        txin_type = None
        if ':' in key:
            txin_type, key = key.split(sep=':', maxsplit=1)
            if txin_type not in SCRIPT_TYPES:
                raise Exception('unknown script type: {}'.format(txin_type))
        try:
            vch = EC_KEY.DecodeBase58Check(key)
        except BaseException:
            neutered_privkey = str(key)[:3] + '..' + str(key)[-2:]
            raise Exception("cannot deserialize privkey {}"
                                   .format(neutered_privkey))
    
        if txin_type is None:
            # keys exported in version 3.0.x encoded script type in first byte
            txin_type = EC_KEY.inv_dict(SCRIPT_TYPES)[vch[0] - WIF_PREFIX]
        else:
            # all other keys must have a fixed first byte
            if vch[0] != WIF_PREFIX:
                raise Exception('invalid prefix ({}) for WIF key'.format(vch[0]))
    
        if len(vch) not in [33, 34]:
            raise BitcoinException('invalid vch len for WIF key: {}'.format(len(vch)))
        compressed = len(vch) == 34
        return txin_type, vch[1:33], compressed
   
    # ECIES encryption/decryption methods; AES-128-CBC with PKCS7 is used as the cipher; hmac-sha256 is used as the mac

    @classmethod
    def encrypt_message(self, message, pubkey, magic=b'BIE1'):
        EC_KEY.assert_bytes(message)

        pk = EC_KEY.ser_to_point(pubkey)
        if not ecdsa.ecdsa.point_is_valid(generator_secp256k1, pk.x(), pk.y()):
            raise Exception('invalid pubkey')

        ephemeral_exponent = number_to_string(ecdsa.util.randrange(pow(2,256)), generator_secp256k1.order())
        ephemeral = EC_KEY(ephemeral_exponent)
        ecdh_key = EC_KEY.point_to_ser(pk * ephemeral.privkey.secret_multiplier)
        key = hashlib.sha512(ecdh_key).digest()
        iv, key_e, key_m = key[0:16], key[16:32], key[32:]
        ciphertext = EC_KEY.aes_encrypt_with_iv(key_e, iv, message)
        ephemeral_pubkey = bytes.fromhex(ephemeral.get_public_key(compressed=True))
        encrypted = magic + ephemeral_pubkey + ciphertext
        mac = hmac.new(key_m, encrypted, hashlib.sha256).digest()

        return base64.b64encode(encrypted + mac)

    def decrypt_message(self, encrypted, magic=b'BIE1'):
        encrypted = base64.b64decode(encrypted)
        if len(encrypted) < 85:
            raise Exception('invalid ciphertext: length')
        magic_found = encrypted[:4]
        ephemeral_pubkey = encrypted[4:37]
        ciphertext = encrypted[37:-32]
        mac = encrypted[-32:]
        if magic_found != magic:
            raise Exception('invalid ciphertext: invalid magic bytes')
        try:
            ephemeral_pubkey = EC_KEY.ser_to_point(ephemeral_pubkey)
        except AssertionError as e:
            raise Exception('invalid ciphertext: invalid ephemeral pubkey')
        if not ecdsa.ecdsa.point_is_valid(generator_secp256k1, ephemeral_pubkey.x(), ephemeral_pubkey.y()):
            raise Exception('invalid ciphertext: invalid ephemeral pubkey')
        ecdh_key = EC_KEY.point_to_ser(ephemeral_pubkey * self.privkey.secret_multiplier)
        key = hashlib.sha512(ecdh_key).digest()
        iv, key_e, key_m = key[0:16], key[16:32], key[32:]
        if mac != hmac.new(key_m, encrypted[:-32], hashlib.sha256).digest():
            raise Exception('invalid password')
        return EC_KEY.aes_decrypt_with_iv(key_e, iv, ciphertext)


def test():
    # pubkey and privkey are the strings returned by RPC call dumpprivkey of BitCoin daemon
    pubkey = "03360daec2591105e8c53f145c9f7682826ddaeb4a20e4dd34e0b760d7c71903d1"
    privkey = "UqYAnj1UJLD8pgw2biTspqUc1WJ4FNEqNRDWquvWiN2VgkTEmyuQ"
    message = "This is a test encrypted message"
    print("Original message: %s" %message)
    # Encrypt with public key and print message
    m_enc = EC_KEY.encrypt_message(message.encode('utf-8'), bytes.fromhex(pubkey))
    print("Encrypted msg: %s" %m_enc.decode('utf-8'))
    # Extract private key
    pk = EC_KEY.deserialize_privkey(privkey)[1]
    print("Private key: %s" %EC_KEY.bh2u(pk))
    # Create EC_KEY instance with private key
    ec = EC_KEY( pk )
    # Print public key
    print("Public Key: %s" %ec.get_public_key(compressed=True))
    # Decrypt and print message
    m_dec = ec.decrypt_message(m_enc)
    print("Decrypted msg: %s" %m_dec.decode('utf-8'))
    # Sign message and print (not working yet)
    #m_sig = EC_KEY.bh2u(ec.sign_message(message.encode('utf-8'),True))
    #print("Signature: %s" %m_sig)
    #print(ec.verify_message(bytes.fromhex(m_sig), message.encode('utf-8')))

if __name__ == "__main__": test()

