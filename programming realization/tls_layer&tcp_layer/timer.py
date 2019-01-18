# from .RIPPPacket import RIPPPacket
import asyncio



class data_resend_timer():
    # global loop
    def __init__(self, delay, callback, data, loop):
        self.delay = delay
        self.callback = callback
        self.loop = loop
        self.data = data
        # self.loop = asyncio.get_event_loop()
        # self.loop = asyncio.get_event_loop()
        # self.loop.call_later(self.delay, self.callback)
        # self.loop.run_forever()   #when call
        # self.loop.close()
        self.callback = self.loop.call_later(self.delay, self.callback, self.data)


    # async def test(self, delay, callback):
    #     await asyncio.sleep(delay)
    #     callback()
    def loop_close(self):
        self.loop.close()

    def cancel(self):
        self.callback.cancel()


class data_giveup_timer():
    # global loop
    def __init__(self, delay, callback, data, loop):
        self.delay = delay
        self.callback = callback
        self.loop = loop
        self.data = data
        # self.loop = asyncio.get_event_loop()
        # self.loop = asyncio.get_event_loop()
        # self.loop.call_later(self.delay, self.callback)
        # self.loop.run_forever()   #when call
        # self.loop.close()
        self.callback = self.loop.call_later(self.delay, self.callback, self.data)


    # async def test(self, delay, callback):
    #     await asyncio.sleep(delay)
    #     callback()
    def loop_close(self):
        self.loop.close()

    def cancel(self):
        self.callback.cancel()


class shutdown_anyway_timer():
    # global loop
    def __init__(self, delay, loop):
        self.delay = delay
        self.loop = loop
        # self.loop = asyncio.get_event_loop()
        # self.loop = asyncio.get_event_loop()
        # self.loop.call_later(self.delay, self.callback)
        # self.loop.run_forever()   #when call
        # self.loop.close()
        self.callback = self.loop.call_later(self.delay, self.loop_close)

    # async def test(self, delay, callback):
    #     await asyncio.sleep(delay)
    #     callback()
    def loop_close(self):
        self.loop.stop()

    def cancel(self):
        self.callback.cancel()


class window_forward():
    # global loop
    def __init__(self, delay, callback, loop):
        self.delay = delay
        self.callback = callback
        self.loop = loop
        # self.loop = asyncio.get_event_loop()
        # self.loop = asyncio.get_event_loop()
        # self.loop.call_later(self.delay, self.callback)
        # self.loop.run_forever()   #when call
        # self.loop.close()
        self.callback = self.loop.call_later(self.delay, self.callback)

    # async def test(self, delay, callback):
    #     await asyncio.sleep(delay)
    #     callback()
    def loop_close(self):
        self.loop.close()

    def cancel(self):
        self.callback.cancel()

class ack_resend_timer():
    # global loop
    def __init__(self, delay, callback, ack_Num, loop):
        self.delay = delay
        self.callback = callback
        self.loop = loop
        self.ack = ack_Num
        # self.loop = asyncio.get_event_loop()
        # self.loop = asyncio.get_event_loop()
        # self.loop.call_later(self.delay, self.callback)
        # self.loop.run_forever()   #when call
        # self.loop.close()
        self.callback = self.loop.call_later(self.delay, self.callback, self.ack)


    # async def test(self, delay, callback):
    #     await asyncio.sleep(delay)
    #     callback()
    def loop_close(self):
        self.loop.close()

    def cancel(self):
        self.callback.cancel()

# def show():
#     print('hello')
#
# loop = asyncio.get_event_loop()
#
# t = timer(loop, 2, show)
# t1 = timer(loop, 3, show)
# t1 = timer(loop, 6, show)
# t1 = timer(loop, 8, show)
#
# loop.run_forever()



