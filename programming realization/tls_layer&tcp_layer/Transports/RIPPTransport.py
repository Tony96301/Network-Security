from playground.network.common import StackingTransport
from ..Packets.RIPPPacket import RIPPPacket
import time
import asyncio
import random
from ..timer import window_forward
from ..timer import data_resend_timer



class RIPPTransport(StackingTransport):   #inherit the stackingtransport class
    CHUNK_SIZE = 1500    #each packet is

    def __init__(self, transport, protocol=None):
        super().__init__(transport)
        self.protocol = protocol   #the protocol instance are put in from client or server protocol

    def write(self, data):    #mimic the stackingtransport class
        if self.protocol:
            if not self.protocol.isClosing():

                i = 0
                index = 0
                sentData = None
                while (i < len(data)):   #the serialized http packet is split into several chunks
                    if (i + self.CHUNK_SIZE < len(data)):
                        sentData = data[i: i + self.CHUNK_SIZE]
                    else:
                        sentData = data[i:]
                    i += len(sentData)   #the length of sentData is always 38, why is it???
                    #whether to change the seqNum, depends on the RIPP's definition
                    pkt = RIPPPacket.DataPacket(self.protocol.seqNum, sentData)   #make a data packet with one chunk bytes
                    index += 1
                    ackNumber = self.protocol.seqNum + len(sentData)  #the next ack_num we should get for our last sent data packet

                    #we create a sentdata_cache to contain those data packets sent without receiving corresponding ack packets
                    if len(self.protocol.sentDataCache) <= self.protocol.WINDOW_SIZE:   #there is window space for packet to send immediately
                        print("RIIPTransport: Sending packet {!r}, sequence number: {!r}".format(index, pkt.SequenceNumber))
                        self.protocol.transport.write(pkt.__serialize__())
                        self.protocol.sentDataCache[ackNumber] = (pkt, time.time())   #use dict to document ack_num with its packet and timestamp

                        #sentdatacache timeout timer begin
                        t = data_resend_timer(self.protocol.timeout, self.protocol.data_resend, ackNumber, self.protocol.loop)  #attribute each data packet a timer to resend
                        self.protocol.timer_list[ackNumber] = t   #put each timer into the timer_list

                        # set up a timer for window moving forward
                        t1 = window_forward(self.protocol.window_forward_timeout, self.protocol.sendNextDataPacket, self.protocol.loop)

                        #sentdatacache timeout timer end

                    else:
                        print("RIIPTransport: Buffering packet {!r}, sequence number: {!r}".format(index,
                                                                                                 pkt.SequenceNumber))
                        #if the window is fully used, then we need to put packets waiting to send into sending buffer
                        self.protocol.sendingDataBuffer.append((ackNumber, pkt))
                        # self.protocol.sendNextDataPacket()

                    self.protocol.seqNum += len(sentData)
                print("RIPPTransport: Batch transmission finished, number of packets sent: {!r}".format(index))
            else:
                print("RIPPTransport: protocol is closing, unable to write anymore.")

        else:
            print("RIPPTransport: Undefined protocol, writing anyway...")
            print("RIPPTransport: Write got {} bytes of data to pass to lower layer".format(len(data)))
            super().write(data)
        # self.protocol.sendNextDataPacket()

    def close(self):
        if not self.protocol.isClosing():
            print("Prepare to close...")
            self.protocol.prepareForFin()
        else:
            print("RIIPTransport: Protocol is already closing.")






