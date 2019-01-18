from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import BUFFER, LIST, STRING
from playground.network.packet.fieldtypes.attributes import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec


class SITHPacket(PacketType):
    DEFINITION_IDENTIFIER = "SITH.kandarp.packet.Base"
    DEFINITION_VERSION = "1.0"

    TYPE_HELLO = "HELLO"
    TYPE_FINISH = "FINISH"
    TYPE_DATA = "DATA"
    TYPE_CLOSE = "CLOSE"

    FIELDS = [
      ("Random", BUFFER({Optional: True})),  #older version
      ("Type", STRING({Optional: True})), # HELLO, FINISH, DATA, CLOSE
      ("PublicValue", BUFFER({Optional: True})),   #to store public key
      ("Certificate", LIST(BUFFER)({Optional: True})),   #inherit older version 'Certs'
      ("Signature", BUFFER({Optional: True})),
      ("Ciphertext", BUFFER({Optional: True}))     #inherit older version 'Ciphertext'
    ]

    @classmethod
    def makeHelloPacket(cls, random, certs, public_key):
      pkt = cls()
      pkt.Random = random
      pkt.Certificate = certs
      pkt.Type = cls.TYPE_HELLO
      pkt.PublicValue = public_key.public_bytes()   #change the format of 'public_key' to bytes, in order to be stored in 'Buffer' field
      return pkt


    @classmethod
    def makeFinishPacket(cls, m1, m2, private_key):
      pkt = cls()
      hasher = hashes.Hash(hashes.SHA256(), backend = default_backend())
      hasher.update(m1 + m2)    #input message needed to hash
      hash_msg = hasher.finalize()  # get the hash result
      signed_msg = private_key.sign(   #generate the signature of messages by signing its hash
        hash_msg,
        ec.ECDSA(hashes.SHA256())
      )
      pkt.Type = cls.TYPE_FINISH
      pkt.Signature = signed_msg
      return pkt


    @classmethod
    def makeDataPacket(cls, ciphertext):
      pkt = cls()
      pkt.Ciphertext = ciphertext
      pkt.Type = cls.TYPE_DATA
      return pkt


    @classmethod
    def makeClosePacket(cls, error):
      pkt = cls()
      pkt.Ciphertext = bytes(error)
      pkt.Type = cls.TYPE_CLOSE
      return pkt