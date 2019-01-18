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


class ClientSITHProtocol(SITHProtocol):
    def __init__(self, higherProtocol=None):
        super().__init__(higherProtocol)
        self.private_key = X25519PrivateKey.generate()  #generate private key
        self.public_key = self.private_key.public_key()  #generate public key
        # print("type of public key is:" + str(type(self.public_key)))
        self.random_length = 32
        self.random = os.urandom(self.random_length)  #generate 32-bytes random
        self.server_public_key = None

        self.client_write = None
        self.client_read = None

        self.cert_private_key = None
        self.hash_msg = None

        self.peerCerts = None
        self.certBytes = None

    def connection_made(self, transport):
        self.log("Connection made at SITH layer on " + type(self.higherProtocol()).__name__)
        self.transport = transport
        self.peerAddress = transport.get_extra_info('peername')

        super().connection_made(transport)
        self.importClientCerts()
        self.state = self.STATE_CLIENT_HELLO
        self.log("Client: Sending Hello message, current state: {!r}, random: {!r}".format(self.STATE_DESC[self.state],
                                                                                      self.random))
        self.certBytes = [CipherUtil.serializeCert(c) for c in self.certs]

        helloPkt = SITHPacket.makeHelloPacket(self.random, self.certBytes, self.public_key)
        self.messages["M1"] = helloPkt.__serialize__()
        self.transport.write(helloPkt.__serialize__())   #send client hello pkt

    def data_received(self, data):
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            if isinstance(pkt, SITHPacket):   #judge if this packet is an instance of RIPPPacket

                if (pkt.Type == "HELLO") and (self.state == self.STATE_CLIENT_HELLO):   #receive server's hello pkt
                    # Deserialize certs in packet, attach root cert
                    self.peerCerts = [CipherUtil.getCertFromBytes(c) for c in pkt.Certificate]   #deserialize certificate from byte format
                    if self.verifyCerts(self.peerCerts):
                        self.log("Client: received SithHello packet from server, current state: {!r}".format(
                            self.STATE_DESC[self.state]))
                        self.messages["M2"] = pkt.__serialize__()
                        self.state = self.STATE_CLIENT_KEY_EXCHANGE   #after receiving server's hello pkt, enter 'client_key_exchange' stage

                        #key derivation
                        self.server_public_key = x25519.X25519PublicKey.from_public_bytes(pkt.PublicValue)#load server's public key from bytes
                        shared_secret = self.private_key.exchange(self.server_public_key)
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

                        self.iv_enc = derived_key[:12]
                        self.iv_dec = derived_key[12:24]

                        self.client_read = derived_key[:16]
                        self.client_write = derived_key[16:]

                        self.setEngines()

                        self.state = self.STATE_CLIENT_SITH_HANDSHAKE_DONE

                        #generate handshake finish pkt
                        self.cert_private_key = getClientPrivateKey()
                        finishPkt = SITHPacket.makeFinishPacket(self.messages["M1"], self.messages["M2"], self.cert_private_key)
                        self.transport.write(finishPkt.__serialize__())  #send the server hello pkt and enter 'server_key_exchange' state
                        #send the client finish pkt to server and enter handshake done state

                    else:
                        self.log("Error: certificate verification failure.")
                        self.state = self.STATE_CLIENT_CLOSED
                        self.sendSithClose(1)

                elif (pkt.Type == "FINISH") and self.state == self.STATE_CLIENT_SITH_HANDSHAKE_DONE:
                    self.log("Client: received handshake_finish packet from server")

                    #verify server's signature
                    server_public_key = self.peerCerts[0].public_key()
                    server_signature = pkt.Signature

                    verify_result = self.verify_signature(server_public_key, server_signature, self.hash_msg)

                    if not verify_result:
                        self.log("Client: wrong signature of client!")
                        self.log("Client is closing...")
                        self.state = self.STATE_CLIENT_CLOSED
                        self.sendSithClose(1)
                    else:
                        #enter data transmission state
                        self.state = self.STATE_CLIENT_TRANSFER

                        higherTransport = SITHTransport(self.transport, self)
                        self.higherProtocol().connection_made(higherTransport)

                elif (pkt.Type == "DATA") and self.state == self.STATE_CLIENT_TRANSFER:
                    self.log("Client: received application data from server")

                    self.higherProtocol().data_received(self.decrypt(self.iv_dec, pkt.Ciphertext, None))
                elif (pkt.Type == "CLOSE"):
                    self.state = self.STATE_CLIENT_CLOSED
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
        self.decEngine = AESGCM(self.client_read)
        self.encEngine = AESGCM(self.client_write)


