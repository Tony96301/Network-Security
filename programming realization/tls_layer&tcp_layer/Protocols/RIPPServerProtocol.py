import asyncio
from playground.network.common import StackingProtocol, StackingProtocolFactory, StackingTransport

from ..Packets.RIPPPacket import RIPPPacket
from ..Transports.RIPPTransport import RIPPTransport

from .RIPPProtocol import RIPPProtocol
import time
from ..timer import shutdown_anyway_timer



class ServerProtocol(RIPPProtocol):
    def __init__(self):
        super().__init__()
        self.state = self.STATE_SERVER_LISTEN
        print("Initialized server with state " +
                      self.STATE_DESC[self.state])
    def connection_made(self, transport):
        shutdown_anyway_timer(25, self.loop)
        self.transport = transport
        # super().connection_made(transport)



    def data_received(self, data):
        # print ("heiheihei")
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            if isinstance(pkt, RIPPPacket):
                if pkt.verifyChecksum():   #check whether there is error appeared in any one tcp packet
                    if (pkt.Type == "SYN") and (self.state == self.STATE_SERVER_LISTEN):
                        # the first way handshake, no need to check the sequence num
                        print("Received SYN packet with seq number " +
                                      str(pkt.SequenceNumber))
                        self.state = self.STATE_SERVER_SYN_RCVD
                        self.partnerSeqNum = pkt.SequenceNumber + 1  #x + 1 -> y
                        synAck_seq = self.seqNum   #y initialize
                        self.sendSynAck(self.transport, synAck_seq)
                        self.seqNum += 1

                    elif (pkt.Type == "ACK") and (self.state == self.STATE_SERVER_SYN_RCVD):
                        # client's ack for server's syn-ack
                        if pkt.Acknowledgement == self.seqNum:
                            print("Received ACK packet with ack number " + str(pkt.Acknowledgement))
                            # Do not change seqNum; follow the specifications
                            self.state = self.STATE_SERVER_TRANSMISSION
                            higherTransport = RIPPTransport(self.transport,self)
                            self.higherProtocol().connection_made(higherTransport)

                        else:
                            print(
                                "Server: Wrong ACK packet: ACK number: {!r}, expected: {!r}".format(
                                    pkt.Acknowledgement, self.seqNum))

                    elif (pkt.Type == "DATA") and (self.state == self.STATE_SERVER_TRANSMISSION):
                        self.processDataPkt(pkt)

                    elif (pkt.Type == "ACK") and (self.state == self.STATE_SERVER_TRANSMISSION):
                        self.processAckPkt(pkt)

                    elif ((pkt.Type == "FIN") and (self.state == self.STATE_SERVER_TRANSMISSION)) or \
                            ((pkt.Type == "FIN") and (self.state == self.STATE_SERVER_FIN_WAIT)):
                        print("Received FIN packet with sequence number " +
                              str(pkt.SequenceNumber))
                        self.state = self.STATE_SERVER_FIN_WAIT
                        for item in list(self.timer_list):  # close all the timer before shutdown
                            self.timer_list[item].cancel()
                            del self.timer_list[item]

                        self.partnerSeqNum = pkt.SequenceNumber + 1  # X + 1 -> ack_num
                        self.sendFinAck(self.transport)  #ack = x + 1
                        # time.sleep(2)   #mimic the close wait until the transport close.
                        self.state = self.STATE_SERVER_CLOSED
                        self.transport.close()  #close the connection with lower layer

                    elif ("FIN" in pkt.Type) and ("ACK" in pkt.Type) and (self.state == self.STATE_SERVER_FIN_WAIT):  #normal terminal procedure
                        # client's ack for server's fin
                        if pkt.Acknowledgement == (self.seqNum + 1):
                            print("Received FIN-ACK packet with ack number " + str(pkt.Acknowledgement))
                            self.state = self.STATE_SERVER_CLOSED
                            self.transport.close()  #close the connection with lower layer

                    else:
                        print("Server: Wrong packet: seq num {!r}, type {!r}, state {!r}".format(
                            pkt.SequenceNumber, pkt.Type, self.state))
                else:
                    print("Error in packet, with wrong checksum: " + str(pkt.Checksum))
            else:
                print("Wrong packet class type: {!r}".format(str(type(pkt))))

    def connection_lost(self,exc):
        self.higherProtocol().connection_lost(exc)   #calling the higher layer for conncetion_lost, which initiates terminal by calling tcp layer's transport.close()
        print("tcp server loses connection with lower layer...")
        self.transport = None #close the connection between the tcp layer and lower layer

    def prepareForFin(self):
        print("Server is preparing for FIN...")
        self.state = self.STATE_SERVER_FIN_WAIT

        for item in list(self.timer_list):   #close all the timer before shutdown
            self.timer_list[item].cancel()
            del self.timer_list[item]

        self.sendFin(self.transport)   #1
        # self.transport.close()     #2

        #for throughout test, turn off #1, turn on #2

    def isClosing(self):   #to judge whether the server is in closing status
        return self.state == self.STATE_SERVER_FIN_WAIT or self.state == self.STATE_SERVER_CLOSED