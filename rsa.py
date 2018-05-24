from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64
import binascii

class RSA_SYS(object):
    def pubKFromPrivK(privK):
        rsa = RSA.importKey(privK)
        pubK = rsa.publickey().exportKey()
        return (pubK)

    def encrypt_message(pubK, msg):
        # pubK is in string format
        rsaToEncrypt = RSA.importKey(pubK)
        cipher = PKCS1_v1_5.new(rsaToEncrypt)
        ciphertext = cipher.encrypt(msg.encode('utf8'))
        return base64.b64encode(ciphertext).decode('ascii')

    def decrypt_message(privK, msg):
        # privK is in string format
        rsaToEncrypt = RSA.importKey(privK)
        cipher = PKCS1_v1_5.new(rsaToEncrypt)
        ciphertext = base64.b64decode(msg.encode('ascii'))
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


    pubkey = RSA_SYS.pubKFromPrivK(privkey)
    print("")
    print(pubkey)
    print("")

    message = "This is an encrypted message from python"
    ciphertext = RSA_SYS.encrypt_message(pubkey, message)
    print(ciphertext)
    plaintext = RSA_SYS.decrypt_message(privkey, ciphertext)
    print(plaintext)

    # the next encrypted string is encrypted from the javascript version
    plaintext = RSA_SYS.decrypt_message(privkey, "PrJupfeUykP98ltrvZOBXKbOFYYBL+iJinNb/DaLzN7nW34VjUtyD5SkyRoUV3quiS3Z+Dh1TSChoOji5e8iZg==")
    print(plaintext)

if __name__ == "__main__": test()
