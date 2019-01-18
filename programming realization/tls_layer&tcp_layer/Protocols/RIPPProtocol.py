import asyncio
import os
import random
import time
import threading

from playground.network.common import StackingProtocol

from ..Packets.RIPPPacket import RIPPPacket
# from .timer import data_giveup_timer
from ..timer import ack_resend_timer
from ..timer import data_resend_timer
from ..timer import window_forward


class RIPPProtocol(StackingProtocol):
    # Constants
    WINDOW_SIZE = 100  #50   #350    #78   #75   #50  #60     #10   #the window side determines the throughout capacity of my tcp protocol
    timeout =1    #0.5  #0.5  #0.14   #0.1    #1.5 #2 #0.05
    timeout_max = 10   #4 #5  #4   #this should be very large
    window_forward_timeout = 0.8    #0.4 #0.3  #the timeout for force the window to move forward
    # ack_timeout = 0.5     #0.6 #this timeout should a little longer than data_timeout
    # change the value to change the transmission unreliability


    # # Constants
    # WINDOW_SIZE = 50  #50   #350    #78   #75   #50  #60     #10   #the window side determines the throughout capacity of my tcp protocol
    # timeout =0.02    #0.5  #0.5  #0.14   #0.1    #1.5 #2 #0.05
    # timeout_max = 5   #4 #5  #4   #this should be very large
    # window_forward_timeout = 0.01    #0.4 #0.3  #the timeout for force the window to move forward
    # ack_timeout = 0.5     #0.6 #this timeout should a little longer than data_timeout
    # # change the value to change the transmission unreliability

    # State definitions
    STATE_DESC = {
        0: "DEFAULT",

        100: "SERVER_LISTEN",
        101: "SERVER_SYN_RCVD",
        102: "SERVER_TRANSMISSION",

        103: "SERVER_FIN_WAIT",
        104: "SERVER_CLOSED",

        200: "CLIENT_INITIAL_SYN",
        201: "CLIENT_SYN_ACK",
        202: "CLIENT_TRANSMISSION",

        203: "CLIENT_FIN_WAIT",
        204: "CLIENT_CLOSED"
    }

    STATE_DEFAULT = 0

    STATE_SERVER_LISTEN = 100
    STATE_SERVER_SYN_RCVD = 101
    STATE_SERVER_TRANSMISSION = 102

    STATE_SERVER_FIN_WAIT = 103
    STATE_SERVER_CLOSED = 104

    STATE_CLIENT_INITIAL_SYN = 200
    STATE_CLIENT_SYN_SNT = 201
    STATE_CLIENT_TRANSMISSION = 202

    STATE_CLIENT_FIN_WAIT = 203
    STATE_CLIENT_CLOSED = 204

    def __init__(self):

        super().__init__()
        self.state = self.STATE_DEFAULT
        # self.transport = None
        self.deserializer = RIPPPacket.Deserializer()
        #generate the sequence number of packet sent from this side
        self.seqNum = int.from_bytes(os.urandom(4), byteorder='big')   #randomly spawn 4 Bytes string, then translate Byte to bit
        # self.initialSeq = self.seqNum
        self.partnerSeqNum = None    #the sequence number of the packet sent from other side

        self.loop = asyncio.get_event_loop()   #initialize the loop for timer

        self.sentDataCache = {}
        self.sendingDataBuffer = []
        self.receivedDataBuffer = {}   #receive the packet which is out of order
        self.timer_list = {}
        self.ack_timer_list = {}

        self.tasks = []


    def sendSyn(self,transport):
        # self.transport = transport
        synPacket = RIPPPacket.SynPacket(self.seqNum)
        print ("Sending SYN packet with seq number " + str(self.seqNum)
                      # + ", current state " + self.STATE_DESC[self.state]
                      )
        transport.write(synPacket.__serialize__())

    def sendSynAck(self, transport, synAck_seqNum):
        synAckPacket = RIPPPacket.SynAckPacket(synAck_seqNum, self.partnerSeqNum)
        print("Sending SYN_ACK packet with seq number " + str(synAck_seqNum) +
                      ", ack number " + str(self.partnerSeqNum))

        transport.write(synAckPacket.__serialize__())

    def sendAck(self, transport):
        ackPacket = RIPPPacket.AckPacket(self.partnerSeqNum)
        print("Sending ACK packet with ack number " + str(self.partnerSeqNum) +
              ", current state " + self.STATE_DESC[self.state])
        transport.write(ackPacket.__serialize__())

    def resendAck(self, transport, last_ackNum):
        ackPacket = RIPPPacket.AckPacket(last_ackNum)
        print("Resending ACK packet with ack number " + str(last_ackNum) +
              ", current state " + self.STATE_DESC[self.state])
        transport.write(ackPacket.__serialize__())

    def sendAckanyway(self, transport, ackNum):
        ackPacket = RIPPPacket.AckPacket(ackNum)
        print("Sending ACK packet with ack number " + str(ackNum) +
              ", current state " + self.STATE_DESC[self.state])
        transport.write(ackPacket.__serialize__())

    def sendFin(self, transport):
        finPacket = RIPPPacket.FinPacket(self.seqNum)
        print("Sending FIN packet with sequence number " + str(self.seqNum) +
                      ", current state " + self.STATE_DESC[self.state])
        transport.write(finPacket.__serialize__())

    def sendFinAck(self, transport):
        finAckPacket = RIPPPacket.FinAckPacket(self.partnerSeqNum)
        print("Sending FIN_ACK packet with ack number " + str(self.partnerSeqNum) + ", current state " + self.STATE_DESC[self.state])
        transport.write(finAckPacket.__serialize__())

    #the mechanism we deal with the data packet we received is simply that if one data packet we expected get lost on the way,
    #and the follow-up packets we get successfully, we put all of those follow-ups into a received_buffer, wait for the lost packet
    #by saying 'wait' we means that we do not increase the ack_num until we get the data packet we expect.
    #once we get the expected data packet, we not only update the ack_num and send the ack packet immediately,
    # but also try to figure out whether its follow-ups are already stackd in the received_buffer,
    # if that, we continue updating the ack_num and send follow-up ack packets.

    # send an ack corresponding to received pkt, the mechanism is called "selective" ack packet, means each data packet has one
    # corresponding ack packet with accumulated ack_num

    def processDataPkt(self, pkt):
        if self.isClosing():
            print("Closing, ignored data packet with seq " + str(pkt.SequenceNumber))

        else:
            # while self.partnerSeqNum in list(self.receivedDataBuffer):
            #     (nextPkt, receive_time) = self.receivedDataBuffer.pop(self.partnerSeqNum)
            #     self.partnerSeqNum = nextPkt.SequenceNumber + len(nextPkt.Data)  # update the ack_num for next packet, y + len(data) -> ack_num
            #     self.sendAck(self.transport)  #send the corresponding ack packet

            if pkt.SequenceNumber == self.partnerSeqNum:  # the data with the seq_num is exactly what we want
                print("Received DATA packet with sequence number " +
                      str(pkt.SequenceNumber))

                while pkt.SequenceNumber in list(self.ack_timer_list):
                    self.ack_timer_list[pkt.SequenceNumber].cancel()  # cancel the corresponding data packet resend timer, to avoid the key error
                    del self.ack_timer_list[pkt.SequenceNumber]  # delete the timer from the timer_list
                    break

                self.partnerSeqNum = pkt.SequenceNumber + len(pkt.Data)  # update the ack_num for next packet, y + len(data) -> ack_num
                self.sendAck(self.transport)  #send the corresponding ack packet

                #set a timer to resend the ack packet if can't receive next consecutive data packet in a certain time
                #we need the current partnerSeqNum, the last ackNum wrapped in the last ack packet, last ack packet

                # last_ack = self.partnerSeqNum
                # t = ack_resend_timer(self.ack_timeout, self.ack_resend, last_ack, self.loop)
                # self.ack_timer_list[last_ack] = t  # put each timer into the timer_list





                self.higherProtocol().data_received(pkt.Data)  # upload the data to higher level
                # we further pop those packets which are the follow-ups to that data packet we just got as our expectation.
                while self.partnerSeqNum in self.receivedDataBuffer:# transmit the packet with higher seq_num than expectation we get before to higher layer
                    (nextPkt, receive_time) = self.receivedDataBuffer.pop(self.partnerSeqNum)
                    self.partnerSeqNum = nextPkt.SequenceNumber + len(nextPkt.Data) # update the ack_num for next packet, y + len(data) -> ack_num
                    self.sendAck(self.transport)  # send the corresponding ack packet
                    self.higherProtocol().data_received(nextPkt.Data)  # upload the data to higher level--http
            # the data we get has a larger seq_num than we expect, means there is packet lost on the way
            #to make sure it's in order, we put those with higher ack_num into received_buffer
            elif pkt.SequenceNumber > self.partnerSeqNum:
                print("Received DATA packet with higher sequence number " +
                      str(pkt.SequenceNumber) + ", put it into buffer.")
                self.receivedDataBuffer[pkt.SequenceNumber] = (pkt, time.time())   #document the timestamp of the data packet, in case of timeout

                #receiveddatacache timeout timer begin

                # data_giveup_timer(self.timeout1, self.data_giveup, pkt.SequenceNumber, self.loop)  # attribute each data packet a timer to resend

                #receiveddatacache timeout timer end

            else:  # the data we get has a lower seq_num than we expect, means there is exception in transmission
                print("ERROR: Received DATA packet with lower sequence number " +
                      str(pkt.SequenceNumber) + ",current ack_num is : {!r}, discard it.".format(
                            self.partnerSeqNum))
                ackNum = pkt.SequenceNumber + len(pkt.Data)
                self.sendAckanyway(self.transport, ackNum)  #send ack as same as the sender want to send, to avoid the problem that sender lost the ack packet


        #previously, we used the accumulation method to attribute acks to data packets,
        #now, we need to change to select method, that means each data packet has a unique ack packet.
        #and also, we need to attribute each data packet stacked in sent_packet a timer to do the timeout job.

    # the basic scenario is that we get a new ack for a packet sent before, so the window left side is shortened,
    #which means we should delete one ack packet stacked in sent_buffer.

    #and then the right side of window should be extended.
    #which means we should directly send one data packet stacked in the sending_buffer

    def ack_resend(self, last_ackNum):
        if not self.isClosing():
            current_ackNum = self.partnerSeqNum
            if current_ackNum == last_ackNum:  # after resend_timeout, still haven't gotten next consecutive data packet
                # resend ack packet after timeout
                self.resendAck(self.transport, last_ackNum)  # resend the ack packet
                t = ack_resend_timer(self.ack_timeout, self.ack_resend, last_ackNum, self.loop)
                self.ack_timer_list[last_ackNum] = t  # put each timer into the timer_list

    def sendNextDataPacket(self):
        if len(self.sendingDataBuffer) > 0:
            (nextAck, dataPkt) = self.sendingDataBuffer.pop(0)
            print ("Sending next data packet " + str(nextAck) + " in sendingDataBuffer...")
            self.transport.write(dataPkt.__serialize__())
            self.sentDataCache[nextAck] = (dataPkt, time.time())
            t = data_resend_timer(self.timeout, self.data_resend, nextAck, self.loop)  # attribute each data packet a timer to resend
            self.timer_list[nextAck] = t  # put each timer into the timer_list

            t1 = window_forward(self.window_forward_timeout, self.sendNextDataPacket, self.loop)
    def processAckPkt(self, pkt):
        print("Received ACK packet with acknowledgement number " +
                      str(pkt.Acknowledgement))
        latestAckNumber = pkt.Acknowledgement  #the ack_num of the last ack packet we get

        while latestAckNumber in list(self.sentDataCache):  #when there is an ack_num stacked in the sent_buffer

            # self.sendNextDataPacket()

            # if len(self.sendingDataBuffer) >0:
            #     (nextAck, dataPkt) = self.sendingDataBuffer.pop(0)
            #     print ("Sending next packet " + str(nextAck) + " in sendingDataBuffer...")
            #     self.transport.write(dataPkt.__serialize__())
            #     self.sentDataCache[nextAck] = (dataPkt, time.time(), time.time())


                # t = data_resend_timer(self.timeout, self.data_resend, nextAck, self.loop)  # attribute each data packet a timer to resend
                # self.timer_list[nextAck] = t  # put each timer into the timer_list
                # self.seqNum += len(dataPkt.Data)    #update the seqNum after sending the data packet

            print ("Received ACK for dataSeq: {!r}, removing".format(self.sentDataCache[latestAckNumber][0].SequenceNumber))
            del self.sentDataCache[latestAckNumber]    #delete the data packet from the sent buffer
            break

        while latestAckNumber in list(self.timer_list):
            self.timer_list[latestAckNumber].cancel()  #cancel the corresponding data packet resend timer, to avoid the key error
            del self.timer_list[latestAckNumber]  # delete the timer from the timer_list
            break

        # self.sendNextDataPacket()

    def data_giveup(self, seqNum):
        if not self.isClosing():
            (dataPkt, timestamp) = self.receivedDataBuffer[seqNum]
            # give up waiting for the current data packet after timeout
            print("Giving up waiting for packet " + str(dataPkt.SequenceNumber))
            # make sure the data packets are received in order
            sorted_buffer = sorted(self.receivedDataBuffer.items(), key=lambda item: item[0])  # sort the cache by seq_num, from small to large
            new_ack_num = sorted_buffer[0][0]  # get the next packet's seq_num
            self.partnerSeqNum = new_ack_num  # update the ack_num to the next data packet's seq_num in cache

    def data_resend(self, ackNum):

        if not self.isClosing():
            if ackNum in list(self.sentDataCache):
                (dataPkt, timestamp) = self.sentDataCache[ackNum]
                currentTime = time.time()
                if currentTime - timestamp < self.timeout_max:  #over the timeout and below the max_timeout, resend the data packet
                    # resend data packet after timeout
                    print("Resending packet " + str(dataPkt.SequenceNumber) + " in sentDataCache...")
                    self.transport.write(dataPkt.__serialize__())
                    self.sentDataCache[ackNum] = (dataPkt, timestamp)
                    t = data_resend_timer(self.timeout, self.data_resend, ackNum, self.loop)
                    self.timer_list[ackNum] = t  # put each timer into the timer_list
                else:
                    return
            else:
                return


