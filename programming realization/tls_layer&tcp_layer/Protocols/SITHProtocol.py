from playground.network.common import StackingProtocol
from playground.common import CipherUtil
from ..Packets.SITHPackets import  SITHPacket
from ..CertFactory import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from ..Verify_Signature import VERIFY_SIGNATURE


class SITHProtocol(StackingProtocol):

    DEBUG_MODE = True   #turn on print debug information on console
    # State Definitions

    STATE_SERVER_HELLO = 100
    STATE_SERVER_KEY_EXCHANGE = 101
    STATE_SERVER_SITH_HANDSHAKE_DONE = 102
    STATE_SERVER_TRANSFER = 103
    STATE_SERVER_CLOSED = 104

    STATE_CLIENT_HELLO = 200
    STATE_CLIENT_KEY_EXCHANGE = 201
    STATE_CLIENT_SITH_HANDSHAKE_DONE = 202
    STATE_CLIENT_TRANSFER = 203
    STATE_CLIENT_CLOSED = 204

    STATE_DESC = {
        0: "STATE_DEFAULT",
        100: "STATE_SERVER_HELLO",
        101: "STATE_SERVER_KEY_EXCHANGE",
        102: "STATE_SERVER_SITH_HANDSHAKE_DONE",
        103: "STATE_SERVER_TRANSFER",
        104: "STATE_SERVER_CLOSED",
        200: "STATE_CLIENT_HELLO",
        201: "STATE_CLIENT_KEY_EXCHANGE",
        202: "STATE_CLIENT_SITH_HANDSHAKE_DONE",
        203: "STATE_CLIENT_TRANSFER",
        204: "STATE_CLIENT_CLOSED"
    }

    def __init__(self, higherProtocol=None):
        if higherProtocol:   #check if the connection has been made to higher layer
            self.log("Initializing SITH layer on " + type(higherProtocol).__name__)
        super().__init__(higherProtocol)
        self.deserializer = SITHPacket.Deserializer()
        self.messages = {}
        self.privateKey = None
        self.rootCert = None
        self.certs = []
        self.publicKey = None
        self.peerPublicKey = None
        self.peerAddress = None
        self.encEngine = None
        self.decEngine = None
        self.iv_enc = None
        self.iv_dec = None

    def decrypt(self, nonce, data, aad):
        self.log("Decrypting data at SITH layer on " + type(self.higherProtocol()).__name__)
        return self.decEngine.decrypt(nonce, data, aad)

    def encrypt(self, nonce, data, aad):
        self.log("Encrypting data at SITH layer on " + type(self.higherProtocol()).__name__)
        return self.encEngine.encrypt(nonce, data, aad)

    def importClientCerts(self):
        rawCerts = getClientCerts()
        self.certs = [CipherUtil.getCertFromBytes(c.encode("utf-8")) for c in rawCerts]
        self.publicKey = self.certs[0].public_key()
        self.rootCert = CipherUtil.getCertFromBytes(getRootCert().encode("utf-8"))

    def importServerCerts(self):
        rawCerts = getServerCerts()
        self.certs = [CipherUtil.getCertFromBytes(c.encode("utf-8")) for c in rawCerts]
        self.publicKey = self.certs[0].public_key()
        self.rootCert = CipherUtil.getCertFromBytes(getRootCert().encode("utf-8"))

    def verifyCerts(self, certs):
        return self.ValidateCertChainSigs(certs)

    def ValidateCertChainSigs(self, certs):
        for i in range(len(certs) - 1):
            this = certs[i]
            issuer = VERIFY_SIGNATURE(certs[i + 1].public_key())  # input the upper layer's public key
            if not issuer.verify(this.signature,
                        this.tbs_certificate_bytes):  # input this layer's certificate's tbs_bytes and signature
                print("not authenticated certificate")
                return False
        print("verified certificate")
        return True

    def log(self, msg, forced=False):
        if (self.DEBUG_MODE or forced):
            print(type(self).__name__ + ": " + msg)

    def sendSithClose(self, error=None):
        if error:
            self.log("Sending SithClose with error: ")
        else:
            self.log("Sending SithClose...")
        sithClose = SITHPacket.makeClosePacket(error)
        self.transport.write(sithClose.__serialize__())

    def verify_signature(self, public_key, signature, hash_msg):
        try:
            public_key.verify(
                signature,
                hash_msg,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:

            return False
