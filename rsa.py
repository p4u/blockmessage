import base64
import binascii
# pip3 install pycrypto (https://www.dlitz.net/software/pycrypto)
import Crypto.PublicKey.RSA as RSA
import Crypto.Cipher.PKCS1_v1_5 as PKCS

class RSA_SYS(object):
    def __init__(self, privkey=None, pubkey=None):
        if not pubkey and privkey:
            rsa = RSA.importKey(privkey)
            pubkey = rsa.publickey().exportKey()
        self.pub = pubkey
        self.priv = privkey

    @staticmethod
    def generate(bits=2048):
        key = RSA.generate(2048)
        return key.exportKey('PEM')

    def get_pubkey(self):
        return self.pub

    def encrypt_message(self, msg):
        if not self.pub: raise Exception("No RSA pubkey provided")
        rsaToEncrypt = RSA.importKey(self.pub)
        cipher = PKCS.new(rsaToEncrypt)
        ciphertext = cipher.encrypt(msg.encode('utf-8'))
        return base64.b64encode(ciphertext).decode('utf-8')

    def decrypt_message(self, msg):
        if not self.priv: raise Exception("No RSA privkey provided")
        rsaToEncrypt = RSA.importKey(self.priv)
        cipher = PKCS.new(rsaToEncrypt)
        ciphertext = base64.b64decode(msg.encode('utf-8'))
        plaintext = cipher.decrypt(ciphertext, b'DECRYPTION FAILED')
        return plaintext.decode('utf8')

def test():
    privkey = """-----BEGIN RSA PRIVATE KEY-----
    MIIBOwIBAAJBANBOMQo9wX55+w1ijEaPoYRP2T4BOjoFv3ma0QWqYYQ8FH0z14Zc
    B/jb0j2PWpyNcsUUBovj+yWxQnQohCck64kCAwEAAQJBAL4s9PbNpO9MfFkfBMSS
    8zoyEDtcsYUxpDtojbandDpdXfvn5D279QaOVLb1C3DgQTTEmroYB8dbeZBc5YJC
    2AECIQDqyUn68ehRcx/EyLMUB1IuckZBWCIApgfn7phgVwSwiQIhAOMgY4bN+xrx
    UV15Ian4ZbkME1IbAvDPcWuNGHxdsaMBAiBoz0K/S44yDfp4lj+bCUmeglTqhrVn
    JLcSymgrWa02QQIhAMJFvPvcilGkYl1atCHHt3LN0mTjd+N0/OXq3SvblIsBAiAc
    8RzaV1GmjMEJxw9vM/tQwQg0kyAPlITMRXnwGA6E0A==
    -----END RSA PRIVATE KEY-----"""

    rsa = RSA_SYS(privkey=privkey)
    pubkey = rsa.get_pubkey()
    print("")
    print(pubkey.decode('utf-8'))
    print("")

    message = "This is an encrypted message from python"
    ciphertext = rsa.encrypt_message(message)
    print('Encrypted: ' + ciphertext)
    plaintext = rsa.decrypt_message(ciphertext)
    print(plaintext)

    # the next encrypted string is encrypted from the javascript version
    plaintext = rsa.decrypt_message("PrJupfeUykP98ltrvZOBXKbOFYYBL+iJinNb/DaLzN7nW34VjUtyD5SkyRoUV3quiS3Z+Dh1TSChoOji5e8iZg==")
    print(plaintext)

    new_key = RSA_SYS.generate()
    rsa = RSA_SYS(privkey=new_key)
    pubkey = rsa.get_pubkey()
    print(new_key.decode('utf-8'))
    print(pubkey.decode('utf-8'))

if __name__ == "__main__": test()
