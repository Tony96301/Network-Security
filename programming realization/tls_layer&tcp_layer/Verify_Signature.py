from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePublicKey
from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


class VERIFY_SIGNATURE(object):
    def __init__(self, key):  # the key is from upper layer
        if isinstance(key, _EllipticCurvePrivateKey):
            self.signer = key.sign
            self.verifier = key.public_key().verify
        elif isinstance(key, _EllipticCurvePublicKey):
            self.signer = None
            self.verifier = key.verify

    def verify(self, signature, data):  # input tbs_bytes and signature from current layer
        return self.verifyMac(signature, data)

    def verifyMac(self, checkMac, data):  # input tbs_bytes and signature from current layer
        try:
            self.verifier(  # input variables to function 'key.verify'
                checkMac,  # signature, signed by upper layer's private key
                data,  # tbs_bytes, which means "to be hashed"
                ec.ECDSA(hashes.SHA256())  # chosen Hash algorithm to hash the tbs_bytes
            )
            return True
        except InvalidSignature:
            print("InvalidSignature")
            return False