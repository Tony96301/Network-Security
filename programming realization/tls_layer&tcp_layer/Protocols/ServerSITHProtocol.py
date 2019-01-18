from ..Packets.SITHPackets import SITHPacket
from ..Transports.SITHTransport import SITHTransport
from .SITHProtocol import SITHProtocol
from playground.common import CipherUtil
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from ..CertFactory import *
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class ServerSITHProtocol(SITHProtocol):
    def __init__(self, higherProtocol=None):
        super().__init__(higherProtocol)
        self.state = self.STATE_SERVER_HELLO
        self.private_key = X25519PrivateKey.generate()   #generate private key
        self.public_key = self.private_key.public_key()   #generate public key
        self.random_length = 32
        self.random = os.urandom(self.random_length)
        self.client_public_key = None

        self.server_write = None
        self.server_read = None

        self.cert_private_key = None
        self.hash_msg = None

        self.peerCerts = None
        self.certBytes = None

    def connection_made(self, transport):
        self.log("Connection made at SITH layer on " + type(self.higherProtocol()).__name__)
        self.transport = transport
        self.peerAddress = transport.get_extra_info('peername')
        super().connection_made(transport)
        self.importServerCerts()

    def data_received(self, data):
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            if isinstance(pkt, SITHPacket):  # judge if this packet is an instance of RIPPPacket
                if (pkt.Type == "HELLO") and (self.state == self.STATE_SERVER_HELLO):  #receive client hello pkt
                    # Deserialize certs in packet, attach root cert
                    self.peerCerts = [CipherUtil.getCertFromBytes(c) for c in pkt.Certificate]

                    if self.verifyCerts(self.peerCerts):
                        self.log("Server: SithHello received!")
                        self.messages["M1"] = pkt.__serialize__()  #turn the client's hello pkt into bytes
                        self.peerPublicKey = self.peerCerts[0].public_key()

                        # Serialize certs to pack into SithHello
                        self.certBytes = [CipherUtil.serializeCert(c) for c in self.certs]
                        self.log("Server: sending SithHello back to client... Current state: {!r}, random: {!r}"
                                      .format(self.STATE_DESC[self.state], self.random))
                        helloPkt = SITHPacket.makeHelloPacket(self.random, self.certBytes, self.public_key)
                        self.messages["M2"] = helloPkt.__serialize__()   #turn the server's hello pkt into bytes

                        self.transport.write(helloPkt.__serialize__())  #send the server hello pkt and enter 'server_key_exchange' stage
                        self.state = self.STATE_SERVER_KEY_EXCHANGE

                        #key derivation
                        self.client_public_key = x25519.X25519PublicKey.from_public_bytes(pkt.PublicValue)#load client's public key from bytes
                        shared_secret = self.private_key.exchange(self.client_public_key)
                        hasher = hashes.Hash(hashes.SHA256(), backend = default_backend())
                        hasher.update(self.messages["M1"] + self.messages["M2"])
                        self.hash_msg = hasher.finalize()  #get the hash result
                        derived_key = HKDF(
                            algorithm = hashes.SHA256(),
                            length = 32,
                            salt = None,
                            info = self.hash_msg,
                            backend = default_backend()
                        ).derive(shared_secret)  #get the derived key

                        self.iv_dec = derived_key[:12]
                        self.iv_enc = derived_key[12:24]

                        self.server_write = derived_key[:16]
                        self.server_read = derived_key[16:]

                        self.setEngines()

                        self.state = self.STATE_SERVER_SITH_HANDSHAKE_DONE

                    else:
                        self.log("Error: certificate verification failure.")
                        self.sendSithClose(1)

                elif (pkt.Type == "FINISH") and (self.state == self.STATE_SERVER_SITH_HANDSHAKE_DONE):

                    self.log("Server: received handshake_finish packet from client")
                    #verify client's signature
                    client_public_key = self.peerCerts[0].public_key()
                    client_signature = pkt.Signature

                    verify_result = self.verify_signature(client_public_key, client_signature, self.hash_msg)

                    if not verify_result:
                        self.log("Server: wrong signature of client!")
                        self.log("Server is closing...")
                        self.sendSithClose(1)
                    else:

                        # generate handshake finish pkt
                        self.cert_private_key = getServerPrivateKey()  # read private of server's certificate
                        finishPkt = SITHPacket.makeFinishPacket(self.messages["M1"], self.messages["M2"], self.cert_private_key)
                        self.transport.write(finishPkt.__serialize__())  # send the server hello pkt and enter 'server_key_exchange' stage

                        #enter the data transmission state
                        self.state = self.STATE_SERVER_TRANSFER
                        higherTransport = SITHTransport(self.transport, self)
                        self.higherProtocol().connection_made(higherTransport)

                        # Enter transmission
                        higherTransport = SITHTransport(self.transport, self)
                        self.higherProtocol().connection_made(higherTransport)

                elif (pkt.Type == "DATA") and self.state == self.STATE_SERVER_TRANSFER:
                    self.log("Server: received application data from client, decrypt and notify upper layer")
                    self.log("Verification succeeded, sending data to upper layer...")
                    self.higherProtocol().data_received(self.decrypt(self.iv_dec, pkt.Ciphertext, None))
                elif (pkt.Type == "CLOSE"):
                    self.transport.close()

                else:
                    self.log("Error: wrong packet type " + pkt.DEFINITION_IDENTIFIER + ", current state "
                                     + self.STATE_DESC[self.state])
                    self.sendSithClose(1)

            else:
                self.log("Wrong packet class type: {!r}".format(str(type(pkt))))
                self.sendSithClose(1)

    def connection_lost(self, exc):
        self.log("Connection lost at SITH layer on " + type(self.higherProtocol()).__name__)
        self.higherProtocol().connection_lost(exc)
        self.transport = None

    def setEngines(self):
        self.encEngine = AESGCM(self.server_write)
        self.decEngine = AESGCM(self.server_read)

