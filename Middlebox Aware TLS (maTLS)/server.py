import hashlib
import hmac
import socket
import ssl
from sys import argv, stdout

import OpenSSL
import sslkeylog
from OpenSSL.crypto import FILETYPE_PEM, load_privatekey, sign

BUFFSIZE = 2048
serverport = 8010


def Server():

    # Socket Creation
    servsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servsock.bind(('', serverport))
    servsock.listen(1)
    print('Waiting For Client')

    # Accepting the client
    clientsock, clientAddr = servsock.accept()
    print('Got connection from ', clientAddr)
    flag = 1


    while(True):
        if flag == 0:
            break

        # loading server cert
        cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM,
        open('/root/prj/new_certs/server_cert.crt').read())

        # converting cert to string to send to client for explicit authentication
        output=OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        string=str(output)
        encoded_str=string.encode('ascii')
        clientsock.sendall(encoded_str)

        # creating server ID by hashing server cert
        hash_obj = hashlib.sha256()
        hash_obj.update(output)
        id_server = hash_obj.hexdigest()
        print("\n\n Server ID : ",id_server,"\n\n")


        # creating TLS context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # making TLSv1.2 default
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_3
        context.options &=  ~ssl.OP_NO_TLSv1_2

        # opening log file for storing master key
        sslkeylogfile = open('sslkeylogfile.txt', 'wb')
        sslkeylog.set_keylog('server_secrets.log')

        # disabling hostname check to use server cert properly
        context.check_hostname=False

        # loading root cert, server cert and secret key
        context.load_verify_locations(
            '/root/prj/new_certs/root.crt')
        context.load_cert_chain('/root/prj/new_certs/server_cert.crt', '/root/prj/new_certs/server_key.pem')

        # no client MB verify needed
        context.verify_mode = ssl.CERT_NONE

        # doing handshake with MB
        clientsock = context.wrap_socket(
        clientsock, server_side=True, do_handshake_on_connect=True)


        print('Secure TLS 1.2 pipe Established\n')

        # getting security parameters of server MB TLS conn
        sec_param_server = ""
        t = clientsock.cipher()
        print("TLS version:",t, "\n")
        sec_param_server = sec_param_server + t[0] + "$" + t[1] + "$"

        # getting master key and its hash
        t = sslkeylog.get_master_key(clientsock)
        hash_obj = hashlib.sha256()
        hash_obj.update(t)
        master_hash = hash_obj.hexdigest()
        print("master hash ",master_hash, "\n")

        # got security parameters
        sec_param_server += master_hash
        print("Security Param Server: ",sec_param_server, "\n")

        # hashing of security parameters with accountability key assumed to be sent by client
        sec_param_server_bytes = sec_param_server.encode('utf-8')
        hash_obj = hmac.new(key=b'server key', digestmod=hashlib.sha256)
        hash_obj.update(sec_param_server_bytes)
        sec_param_hash = hash_obj.hexdigest()

        print("\nsec params hash : ",sec_param_hash, "\n")

    # signing the security parameters hash

        # Load private key from a PEM file
        with open('/root/prj/new_certs/server_key.pem', 'rb') as f:
            private_key = load_privatekey(FILETYPE_PEM, f.read())

        # Sign the security parameters hash using the private key
        sec_param_hash_bytes = sec_param_hash.encode('utf-8')
        sec_param_hash_sign_bytes = sign(private_key, sec_param_hash_bytes, 'sha256')
        sec_param_hash_sign = sec_param_hash_sign_bytes.hex()

        print("\nsec parameter signed hash : ",sec_param_hash_sign, "\n")

    # creating sec_param_block contining server ID and signed hash of secutiry params

        sec_param_block = id_server + "\n" + sec_param_hash_sign
        print("\n\nsec param block of server : ", sec_param_block,"\n")


        #send and receive messages over TLS now
        print("Sending the sec para block form server->MB")
        clientsock.sendall(sec_param_block.encode())
        flag = 0
        #if(send_data == 'chat_close'):
            #break

    #do chat
    while(True):
        recv_data = clientsock.recv(BUFFSIZE)

    # closing the connections
    clientsock.close()
    servsock.close()



if __name__ == "__main__":
    Server()

