from playground.network.common import StackingTransport
from ..Packets.SITHPackets import *

class SITHTransport(StackingTransport):
    def __init__(self, transport, protocol=None):
        super().__init__(transport)
        self.protocol = protocol

    def write(self, data):
        self.protocol.log("Write got {} bytes of data to pass to lower layer".format(len(data)))
        ciphertext = self.protocol.encrypt(self.protocol.iv_enc, data, None)  #call the cipher to encrypt the plaintext into ciphertext
        sithData = SITHPacket.makeDataPacket(ciphertext)  #make data pkt to send to the other side
        super().write(sithData.__serialize__())

    def close(self):
        self.protocol.sendSithClose()  #send a close pkt to other side to initiate transmission shut down
