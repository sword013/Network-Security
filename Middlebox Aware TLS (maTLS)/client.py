import hashlib
import hmac
import os
import socket
import ssl
from sys import argv, stdout

import OpenSSL
import sslkeylog
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

BUFFSIZE = 8142
serverport = 8010


def validate():

    # Explicit Authentication of clients

    os.system("openssl verify -verbose -CAfile new_certs/root.crt server_test.crt")
    os.system("openssl verify -verbose -CAfile new_certs/root.crt MB_test.crt")

    print("MB and server validation successful")
    print("Explicit Authentication done!!")

def printCerts(output,string):
     # for making .crt files
     lines = []
     str1 = ""
     flag = False
     for i in output[2:-1]:
      if flag:
        flag = False
        continue
      if i != '\\':
        str1 += i
      else:
        lines.append(str1 + "\n")
        str1 = ""
        flag = True
     file_name = string + "_test.crt"
     file = open(file_name,"w")
     for line in lines:
        file.write(line)


def Client(serverhostname):

    # Socket Creation
    clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Resolving IP from hostname
    try:
        host_ip = socket.gethostbyname(serverhostname)
    except socket.gaierror:
        print("there was an error resolving the host")
        exit()

    # Connecting to Server
    clientsock.connect((host_ip, serverport))
    print('Connected to ', host_ip)



    recv_data = clientsock.recv(BUFFSIZE)

    #recv data has the certificates
    recv_data_d=recv_data.decode('ascii')

    print("recieved ", recv_data_d)
    print("type",type(recv_data_d))

    cert1,cert2 = recv_data_d.split("$")
    printCerts(cert1,"server")
    printCerts(cert2,"MB")

    #validate  certs here
    validate()

    # cresting SSL context and various configuration
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_3
    context.options &=  ~ssl.OP_NO_TLSv1_2


    # log file for storing master key from Handshake
    sslkeylogfile = open('sslkeylogfile.txt', 'wb')
    sslkeylog.set_keylog('secrets.log')
    context.check_hostname=False

    # load root CA
    context.load_verify_locations(
        '/root/prj/new_certs/root.crt')

    # cert required to be sent
    context.verify_mode = ssl.CERT_REQUIRED

    # do Handshake
    clientsock = context.wrap_socket(
    clientsock, server_hostname=serverhostname, do_handshake_on_connect=True)

    # getting sec params
    sec_param_client_mb = ""
    t = clientsock.cipher()
    print("TLS protocol:",t)
    sec_param_client_mb += t[0] + "$" + t[1] + "$"

    # getting master key hash
    t = sslkeylog.get_master_key(clientsock)
    hash_obj = hashlib.sha256()
    hash_obj.update(t)
    master_hash = hash_obj.hexdigest()


    print("master hash ",master_hash)
    sec_param_client_mb += master_hash

    print("sec param of client MB conn:", sec_param_client_mb)

    print('SSL Certificates Verified Succesfully')


    #*************************SEC PARA VERIFICATION************************************************
    #1) Get the SEC PARAM BLOCKS of MB & Server
    #recv the security parameters of MB
    sec_para_block_mb = clientsock.recv(BUFFSIZE)
    sec_para_block_mb = sec_para_block_mb.decode()
    print("Received the SPB of MB : ",sec_para_block_mb)
    #send an ack to the MB if it doesnt work

    #recv the security parameters of Server
    sec_para_block_server = clientsock.recv(BUFFSIZE)
    sec_para_block_server = sec_para_block_server.decode()
    print("Received the SPB of Server : ",sec_para_block_server)

    #2) Now we gotta authenticate somehow(hopefully !)
    #get the public keys of MB and server from the certs you got !
    # Load the certificate file
    with open("server_test.crt", "rb") as cert_file:
        cert_data = cert_file.read()

    # Parse the certificate data
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    # Get the public key from the certificate
    public_key = cert.public_key()


    # Print the public key in PEM format
    print("pub key:\n",public_key)
    print(public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    #now, get the signature component of the server from server's SPB
    _,signed_hash_server_param = [i for i in sec_para_block_server.split("\n")]
    print("Siged hash ofserver : ",signed_hash_server_param)
    _,server_param,_ = [i for i in sec_para_block_mb.split("\n")]

    # hashing of security parameters with accountability key assumed to be sent by client
    sec_param_server_bytes = server_param.encode('utf-8')
    hash_obj = hmac.new(key=b'server key', digestmod=hashlib.sha256)
    hash_obj.update(sec_param_server_bytes)
    sec_param_hash = hash_obj.hexdigest()

    print("\nsec params hash : ",sec_param_hash, "\n")


    #verify the signature now !
    signed_hash_server_param_by = signed_hash_server_param.encode('utf-8')
    sec_param_hash_by = sec_param_hash.encode('utf-8')
    try:
        public_key.verify(
            signed_hash_server_param_by,
            sec_param_hash_by,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Signature is valid")
    except InvalidSignature:
        print("Signature is invalid")


    # Chat session continues
    while(True):
        #send_data = input('Enter message to send: ')
        #clientsock.sendall(send_data.encode())
        #if(send_data == 'chat_close'):
         #   break
        #print('Waiting for message . . .')

        recv_data = clientsock.recv(BUFFSIZE)
        print("recieved ", recv_data.decode())
        if(recv_data.decode() == 'chat_close'):
            break



    # closing the connections
    clientsock.close()


if __name__ == "__main__":
    Client(argv[1])

