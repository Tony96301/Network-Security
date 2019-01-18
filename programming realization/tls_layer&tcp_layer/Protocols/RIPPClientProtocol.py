import asyncio

from ..Packets.RIPPPacket import RIPPPacket
# from .RIPPTransports.RIPPTransport import RIPPTransport
from playground.network.common import StackingProtocol, StackingProtocolFactory, StackingTransport
from ..Transports.RIPPTransport import RIPPTransport

from .RIPPProtocol import RIPPProtocol
import time
from ..timer import shutdown_anyway_timer



class ClientProtocol(RIPPProtocol):

    def __init__(self):
        super().__init__()    #instead of using self.transport=None?
        self.state = self.STATE_CLIENT_INITIAL_SYN
        print("Initialized client with state " +
                      self.STATE_DESC[self.state])

    def connection_made(self, transport):
        shutdown_anyway_timer(25, self.loop)
        self.transport = transport
        # super().connection_made(transport)
        if self.state == self.STATE_CLIENT_INITIAL_SYN:
            self.sendSyn(self.transport)      #send the first syn to the server once the connection is made
            self.seqNum += 1   #seqNum is defined in RIPPProtocol.py file
            self.state = self.STATE_CLIENT_SYN_SNT

    def data_received(self, data):
        # print("hahaha")
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            if isinstance(pkt, RIPPPacket):   #judge if this packet is an instance of RIPPPacket
                if pkt.verifyChecksum():
                    if ("SYN" in pkt.Type) and ("ACK" in pkt.Type) and (self.state == self.STATE_CLIENT_SYN_SNT):
                            # check ack num
                            if (pkt.Acknowledgement == self.seqNum):    #mimic the error detection???
                                print("Received SYN-ACK packet with sequence number " +
                                              str(pkt.SequenceNumber) + ", ack number " +
                                              str(pkt.Acknowledgement))
                                self.state = self.STATE_CLIENT_TRANSMISSION
                                self.partnerSeqNum = pkt.SequenceNumber + 1    #y + 1 -> ack_num
                                # self.initialSeq += 1
                                self.sendAck(self.transport)
                                #change seqNum; follow the specifications
                                # self.seqNum += 1
                                higherTransport = RIPPTransport(self.transport,self)   #make the new transport
                                self.higherProtocol().connection_made(higherTransport)

                            else:
                                print("Client: Wrong SYN_ACK packet: ACK number: {!r}, expected: {!r}".format(
                                    pkt.Acknowledgement, self.seqNum))

                    elif (pkt.Type == "DATA") and (self.state == self.STATE_CLIENT_TRANSMISSION):
                        self.processDataPkt(pkt)

                    elif (pkt.Type == "ACK") and (self.state == self.STATE_CLIENT_TRANSMISSION):
                        self.processAckPkt(pkt)

                    elif ((pkt.Type == "FIN") and (self.state == self.STATE_CLIENT_TRANSMISSION)) or \
                            ((pkt.Type == "FIN") and (self.state == self.STATE_CLIENT_FIN_WAIT)):
                        print("Received FIN packet with sequence number " +
                              str(pkt.SequenceNumber))
                        self.state = self.STATE_CLIENT_FIN_WAIT

                        for item in list(self.timer_list):  # close all the timer before shutdown
                            self.timer_list[item].cancel()
                            del self.timer_list[item]

                        self.partnerSeqNum = pkt.SequenceNumber + 1  # y + 1 -> ack_num
                        self.sendFinAck(self.transport)
                        # time.sleep(2)   #mimic the close wait until the transport close.
                        self.state = self.STATE_CLIENT_CLOSED
                        self.transport.close()   #close the connection with lower layer
                        # print("current client state is: " + str(self.state))

                    elif ("FIN" in pkt.Type) and ("ACK" in pkt.Type) and (self.state == self.STATE_CLIENT_FIN_WAIT):
                        # server's ack for client's fin
                        if pkt.Acknowledgement == (self.seqNum + 1):
                            print("Received FIN-ACK packet with ack number " + str(pkt.Acknowledgement))
                            self.state = self.STATE_CLIENT_CLOSED
                            self.transport.close()  #close the connection with lower layer

                    else:
                        print("Client: Wrong packet: seq num {!r}, type {!r}".format(
                            pkt.SequenceNumber, pkt.Type))
                else:
                    print("Error in packet, with wrong checksum: " + str(pkt.Checksum))
            else:
                print("Wrong packet class type: {!r}".format(str(type(pkt))))

    def connection_lost(self,exc):
        self.higherProtocol().connection_lost(exc)   #calling the higher layer for conncetion_lost, which initiates terminal by calling tcp layer's transport.close()
        print("tcp client loses connection with lower layer...")
        self.transport = None   #close the connection between the tcp layer and lower layer

    #four-time handshake for termination
    def prepareForFin(self):
        print("Client is preparing for FIN...")
        self.state = self.STATE_CLIENT_FIN_WAIT

        for item in list(self.timer_list):   #close all the timer before shutdown
            self.timer_list[item].cancel()
            del self.timer_list[item]

        self.sendFin(self.transport)   #1
        # self.transport.close()   #2

        #for throughout test, turn off #1, turn on #2

    def isClosing(self): #to judge whether the client is in closing status
        return self.state == self.STATE_CLIENT_FIN_WAIT or self.state == self.STATE_CLIENT_CLOSED




