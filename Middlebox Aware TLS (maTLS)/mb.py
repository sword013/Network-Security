import hashlib
import hmac
import socket
import ssl
from sys import argv, stdout

import OpenSSL
import sslkeylog
from OpenSSL.crypto import FILETYPE_PEM, load_privatekey, sign


BUFFSIZE = 16384
serverport = 8010


def fake_connection(clienthostname, serverhostname):
    # Socket Creation for server(Fake Bob)
    fake_servsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    fake_servsock.bind(('', serverport))
    fake_servsock.listen(1)
    print('Waiting For Client')

    # Accepting the client (Fake Bob accepting Alice)
    client_sock, client_Addr = fake_servsock.accept()
    print('Got connection from ', client_Addr)

    # Socket Creation for client(Fake Alice)
    fake_clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Resolving IP from hostname(Fake Bob)
    try:
        server_ip = socket.gethostbyname(serverhostname)
    except socket.gaierror:
        print("there was an error resolving the host")
        exit()

    # Connecting to Server(Fake Alice --> Bob)
    fake_clientsock.connect((server_ip, serverport))
    print('Connected to ', server_ip)

    return fake_servsock, client_sock, fake_clientsock




def MB(clienthostname, serverhostname):


    # connecting to server and client
    fake_servsock, client_sock, fake_clientsock = fake_connection(
        clienthostname, serverhostname)

    flag =1
    while(True):
        if(flag==0) :
            break
        # reciving cert from server
        recv_data = fake_clientsock.recv(BUFFSIZE)

        # loading MB cert
        cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM,
        open('/root/prj/new_certs/mb_cert.crt').read())

        # converting cert to string to send to client for explicit authentication
        output=OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        string=str(output)

        # concatinating server cert and MB cert string swith "$" delimiter
        final = recv_data.decode('ascii') + "$" + string
        final = final.encode('ascii')
        print("recieved ", recv_data.decode(), " from ", serverhostname, "\n")
        print("sending ", final.decode(), " to ", clienthostname, "\n")
        client_sock.sendall(final)

        # creating MB ID by hashing server cert
        hash_obj = hashlib.sha256()
        hash_obj.update(output)
        id_MB = hash_obj.hexdigest()
        print("\n\n Middle Box ID : ",id_MB,"\n\n")


############ MB acting as client for server ######################

        # creating TLS context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # making TLSv1.2 default
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_3
        context.options &=  ~ssl.OP_NO_TLSv1_2

        # opening log file for storing master key
        sslkeylogfile = open('sslkeylogfile1.txt', 'wb')
        sslkeylog.set_keylog('mb_client_secrets.log')

        # disabling hostname check to use MB cert properly
        context.check_hostname=False

        # loading root cert
        context.load_verify_locations(
            '/root/prj/new_certs/root.crt')

        # for checking server cert
        context.verify_mode = ssl.CERT_REQUIRED

        # doing handshake
        fake_clientsock = context.wrap_socket(
            fake_clientsock, server_hostname=serverhostname, do_handshake_on_connect=True)

        print('SSL Certificates Verified Succesfully\nSecure TLS 1.2 pipe is Established between MB & server\n')


        # getting security parameters of MB server TLS conn
        sec_param_mb_server = ""
        t = fake_clientsock.cipher()
        print("TLS protocol:",t, "\n")
        sec_param_mb_server += t[0] + "$" + t[1] + "$"



        print("MB<----->Server\n")

        # getting master key
        t = sslkeylog.get_master_key(fake_clientsock)
        hash_obj = hashlib.sha256()
        hash_obj.update(t)
        master_hash = hash_obj.hexdigest()
        print("master hash ",master_hash, "\n")

        # got securing parameters of MB server (p23 as in NS rough notes)
        sec_param_mb_server += master_hash
        print("sec param of MB server conn:", sec_param_mb_server, "\n")

############# MB acting a server for client ##########################3

        # creating TLS context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # defaulting TLSv1.2
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_3
        context.options &=  ~ssl.OP_NO_TLSv1_2

        # disabling hostname cjeck for proper cert usage
        context.check_hostname=False

        #opening log file for storing master key
        sslkeylogfile = open('sslkeylogfile2.txt', 'wb')
        sslkeylog.set_keylog('mb_server_secrets.log')

        # loading root cert
        context.load_verify_locations(
            '/root/prj/new_certs/root.crt')

        # loading MB cert and secret key
        context.load_cert_chain(
            '/root/prj/new_certs/mb_cert.crt', '/root/prj/new_certs/mb_key.pem')

        # no client cert verification
        context.verify_mode = ssl.CERT_NONE

        # do handshake
        client_sock = context.wrap_socket(
            client_sock, server_side=True, do_handshake_on_connect=True)

        print('Secure TLS 1.2 pipe Established between client & MB\n')


        print("Client<------->MB\n")

        # getting sec params
        sec_param_client_mb = ""
        t = client_sock.cipher()
        print("TLS protocol:",t, "\n")
        sec_param_client_mb += t[0] + "$" + t[1] + "$"

        # getting master key
        t = sslkeylog.get_master_key(client_sock)
        hash_obj = hashlib.sha256()
        hash_obj.update(t)
        master_hash = hash_obj.hexdigest()
        print("master hash ",master_hash, "\n")

        # got security parameters of client MB (p12 as in NS rough notes)
        sec_param_client_mb += master_hash
        print("sec param of client MB conn:", sec_param_client_mb, "\n")


        # concatenate sec params of (MB-server) & (client-MB)
        sec_params_final = sec_param_mb_server + sec_param_client_mb

        print("cancat sec paramsof MB server <-> client MB conn:", sec_params_final, "\n")

        # hasning concatenated sec params with accountability key assumed to be sent by client
        sec_params_final_bytes = sec_params_final.encode('utf-8')
        hash_obj = hmac.new(key=b'MB key', digestmod=hashlib.sha256)
        hash_obj.update(sec_params_final_bytes)
        sec_param_final_hash = hash_obj.hexdigest()

        print("\nconcat sec params hash : ",sec_param_final_hash, "\n")

    # signing the final security parameters hash

        # Load private key from a PEM file
        with open('/root/prj/new_certs/mb_key.pem', 'rb') as f:
            private_key = load_privatekey(FILETYPE_PEM, f.read())

        # Sign the final security parameters hash using the private key
        sec_param_final_hash_bytes = sec_param_final_hash.encode('utf-8')
        sec_param__final_hash_sign_bytes = sign(private_key, sec_param_final_hash_bytes, 'sha256')
        sec_param_final_hash_sign = sec_param__final_hash_sign_bytes.hex()

        print("\nconcat sec parameter signed hash : ",sec_param_final_hash_sign)

    # creating sec_param_block contining MB ID, sec param of MB-server, signed hash of secutiry params

        sec_param_block_mb = id_MB + "\n" + sec_param_mb_server + "\n" + sec_param_final_hash_sign
        print("\n\nsec param block of MB : ", sec_param_block_mb,"\n")

        print("waiting for sec para block of server")
        sec_para_block_server = fake_clientsock.recv(BUFFSIZE)
        sec_para_block_server = sec_para_block_server.decode()
        #sec_para_block_server = recv_data.decode()
        print("recevied SPB of server : ",sec_para_block_server)

        print("Sending SPB of MB to Client ")
        client_sock.sendall(sec_param_block_mb.encode())
        print("Sent !")

        #recv ack from client if it doesnt work

        print("Sending SPB of Server to Client ")
        client_sock.sendall(sec_para_block_server.encode())
        print("Sent !")
        flag =0
        #if(recv_data.decode() == 'chat_close'):
         #   print("recived ", recv_data.decode(),
          #        "from Bob sending to Alice and exiting . . . ")
           # break

    #do the chat here !
    while(True):
        recv_data = client_sock.recv(BUFFSIZE)

    # closing the connections
    client_sock.close()
    fake_clientsock.close()
    fake_servsock.close()


if __name__ == "__main__":

    MB(argv[1], argv[2])

