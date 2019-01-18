from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT16, STRING, UINT8, UINT32, BUFFER
from playground.network.packet.fieldtypes.attributes import Optional
import hashlib


#first try the "three-time" handshake establishment, without considering "four-time" handshake termination, checksum
class RIPPPacket(PacketType):

    TYPE_SYN = "SYN"
    TYPE_ACK = "ACK"
    TYPE_FIN = "FIN"
    TYPE_DATA = "DATA"

    DEFINITION_IDENTIFIER = "RIPP.Packet"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("Type", STRING),
        ("SequenceNumber", UINT32({Optional: True})),
        ("Checksum", BUFFER({Optional: True})),
        ("Acknowledgement", UINT32({Optional: True})),
        ("Data", BUFFER({Optional: True}))
    ]

    def calculateChecksum(self):
        # oldChecksum = self.Checksum
        self.Checksum = b"0"   #when calculating the hash value, we should make sure
        # the already existing self.Checksum not going to interfere our next calculation for hash.
        #because the format of Checksum is BUFFER, so we need to generate a '0' in byte, which could be put into the buffer.
        bytes = self.__serialize__()   #serialize the packet into bytes
        # self.Checksum = oldChecksum
        hash = hashlib.sha256()   #we use sha256 algorithm to calculate the hash value of the packet
        hash.update(bytes)
        return hash.digest()   #why we use digest() not hexdigest() is the return value format of the former is bytes and that of the latter is str
        #return the output of hash, whose format is int

    def updateChecksum(self):
        self.Checksum = self.calculateChecksum()   #calculate the hash value and attribute it to pkt.Checksum argument

    def verifyChecksum(self):
        oldChecksum = self.Checksum
        newChecksum = self.calculateChecksum()
        self.Checksum = newChecksum
        return newChecksum == oldChecksum  #verify whether the new hash value equals to the former one

    @classmethod
    def SynPacket(cls, seq):
        pkt = cls()
        pkt.Type = cls.TYPE_SYN
        pkt.SequenceNumber = seq    #seq = x
        pkt.updateChecksum()  #calculate the hash value of the packet
        return pkt

    @classmethod
    def SynAckPacket(cls, seq, ack):
        pkt = cls()
        pkt.Type = cls.TYPE_SYN + cls.TYPE_ACK
        pkt.SequenceNumber = seq    #seq = y
        pkt.Acknowledgement = ack    #ack = seq(received) + 1
        pkt.updateChecksum()
        return pkt

    @classmethod
    def AckPacket(cls, ack):
        pkt = cls()
        pkt.Type = cls.TYPE_ACK
        pkt.Acknowledgement = ack     #ack = y + 1
        pkt.updateChecksum()
        return pkt

    @classmethod
    def DataPacket(cls, seq, data):
        pkt = cls()
        pkt.Type = cls.TYPE_DATA
        pkt.SequenceNumber = seq
        pkt.Data = data
        pkt.updateChecksum()
        return pkt

    @classmethod
    def FinPacket(cls, seq):
        pkt = cls()
        pkt.Type = cls.TYPE_FIN
        pkt.SequenceNumber = seq
        # pkt.Acknowledgement = ack
        pkt.updateChecksum()
        return pkt

    @classmethod
    def FinAckPacket(cls, ack):
        pkt = cls()
        pkt.Type = cls.TYPE_FIN + cls.TYPE_ACK
        pkt.Acknowledgement = ack
        # pkt.SequenceNumber = seq
        pkt.updateChecksum()
        return pkt

