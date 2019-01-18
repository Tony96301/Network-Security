import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def getClientCerts():
    chain = []
    pwd = os.path.dirname(__file__)
    with open(pwd  + '/client_certificate/client.cert','r') as f0:
    # Enter the location of the client's certificate as per the client's system
        chain.append(f0.read())
    # Enter the location of the CA's certificate as per the client's system
    with open(pwd + '/client_certificate/ca1.cert', 'r') as f1:
        chain.append(f1.read())

    return chain

def getServerCerts():
    chain = []
    pwd = os.path.dirname(__file__)
    with open(pwd  + '/server_certificate/server.cert','r') as f0:
    # Enter the location of the server's certificate as per the server's system
        chain.append(f0.read())
    # Enter the location of the CA's certificate as per the server's system
    with open(pwd + '/server_certificate/ca1.cert', 'r') as f1:
        chain.append(f1.read())

    return chain

def getClientPrivateKey():
    # Enter the location of the client's Private key as per the client's system
    pwd = os.path.dirname(__file__)
    path = pwd + '/client_certificate/c_private.pem'
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend= default_backend()
        )
    return private_key

def getServerPrivateKey():
    # Enter the location of the server's Private key as per the server's system
    pwd = os.path.dirname(__file__)
    path = pwd + '/server_certificate/s_private.pem'
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend= default_backend()
        )
    return private_key

def getRootCert():
    # Enter the location of the Root's certificate
    pwd = os.path.dirname(__file__)
    with open(pwd + '/client_certificate/20184_root_signed.cert', 'r') as f:
        rootcertbytes = f.read()

    return rootcertbytes