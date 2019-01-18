from .RIPPClientProtocol import ClientProtocol
from .RIPPServerProtocol import ServerProtocol
from playground.network.common import StackingProtocol, StackingProtocolFactory, StackingTransport

import playground

f_client = StackingProtocolFactory(lambda: ClientProtocol())

f_server = StackingProtocolFactory(lambda: ServerProtocol())

ptConnector = playground.Connector(protocolStack=(f_client, f_server))

playground.setConnector("lab1protocol", ptConnector)