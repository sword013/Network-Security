#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <netdb.h>

using namespace std;

int ssl_verify_callback(int ok, X509_STORE_CTX* store_ctx)
{
    if (!ok) {
        char err_buf[256];
        X509* cert = X509_STORE_CTX_get_current_cert(store_ctx);
        int err = X509_STORE_CTX_get_error(store_ctx);
        int depth = X509_STORE_CTX_get_error_depth(store_ctx);

        X509_NAME_oneline(X509_get_subject_name(cert), err_buf, 256);
        printf("Error verifying certificate: depth=%d err=%d subject=%s\n", depth, err, err_buf);
    }

    return ok;
}

int main(){


    //Client Trudy
    const char* HOST = "172.31.0.3";
    const int PORT = 8084;

     SSL_CTX *ctx2;
                SSL *ssl2;
                 SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx2 = SSL_CTX_new(TLSv1_2_client_method());

    SSL_CTX_set_mode(ctx2,SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_verify(ctx2, SSL_VERIFY_PEER| SSL_VERIFY_FAIL_IF_NO_PEER_CERT,ssl_verify_callback);
    SSL_CTX_load_verify_locations(ctx2, "CAfile.pem", NULL);
    SSL_CTX_set_verify_depth(ctx2,2);
    // SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file("intermediate_ca.crt"));

     if (SSL_CTX_use_certificate_file(ctx2, "fake_alice.crt", SSL_FILETYPE_PEM) <= 0) {
        perror("SSL_CTX_use_certificate_file() error");
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx2, "fake_alice.key", SSL_FILETYPE_PEM) <= 0) {
        perror("SSL_CTX_use_PrivateKey_file() error");
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ctx2)) {
        perror("Private key does not match the certificate public key");
        exit(EXIT_FAILURE);
    }

    // Server Trudy
    //const char* listen_addr = "172.31.0.4";
    const int listen_port = 8084;
    const char * t_hostname = "trudy1";
    struct hostent* trudy = gethostbyname(t_hostname);    
    SSL_CTX *ctx1;
                SSL *ssl1;
                SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx1 = SSL_CTX_new(TLSv1_2_server_method());
    SSL_CTX_set_verify(ctx1, SSL_VERIFY_PEER,ssl_verify_callback);
    SSL_CTX_load_verify_locations(ctx1, "CAfile.pem", NULL);
    // SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file("intermediate_ca.crt"));

    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx1, "fake_bob.crt", SSL_FILETYPE_PEM) <= 0) {
        perror("SSL_CTX_use_certificate_file() error");
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx1, "fake_bob.key", SSL_FILETYPE_PEM) <= 0) {
        perror("SSL_CTX_use_PrivateKey_file() error");
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ctx1)) {
        ERR_print_errors_fp(stderr);
        perror("Private key does not match the certificate public key");
        exit(EXIT_FAILURE);
    }



    // create a server socket
    int ssocket = socket(AF_INET, SOCK_STREAM, 0);
    if (ssocket == -1) {
        cerr << "Error: Failed to create server socket.\n";
        return 1;
    }

    // bind the server socket
    sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    //serv_addr.sin_addr.s_addr = inet_addr(listen_addr);
     serv_addr.sin_addr.s_addr = *((in_addr_t*)trudy->h_addr_list[0]);
    serv_addr.sin_port = htons(listen_port);
    if (bind(ssocket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
        cerr << "Error: Failed to bind server socket.\n";
        close(ssocket);
        return 1;
    }

    // listen for incoming connections
    if (listen(ssocket, 5) == -1) {
        cerr << "Error: Failed to listen for incoming connections.\n";
        close(ssocket);
        return 1;
    }

    cout << "Waiting for client...\n";
    sockaddr_in cli_addr;
    socklen_t cli_addr_len = sizeof(cli_addr);
    int client_sock = accept(ssocket, (struct sockaddr *)&cli_addr, &cli_addr_len);
    if (client_sock == -1) {
        cerr << "Error: Failed to accept incoming connection.\n";
        close(ssocket);
        return 1;
    }
    cout << "Client connected: " << inet_ntoa(cli_addr.sin_addr) << ":" << ntohs(cli_addr.sin_port) << endl;




    // Client 
    // create a client socket
    int client = socket(AF_INET, SOCK_STREAM, 0);
    if (client == -1) {
        cerr << "Error: Failed to create client socket.\n";
        close(client_sock);
        close(ssocket);
        return 1;
    }

    // connect to the target server
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(HOST);
    serv_addr.sin_port = htons(PORT);
    if (connect(client, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
        cerr << "Error: Failed to connect to target server.\n";
        close(client_sock);
        close(ssocket);
        close(client);
        return 1;
    }

    cout << " Trudy Connected to TargetServer Bob" << endl;

    char check[1024];
    char data_tcp[1024];
    char data_tls[1024];
    bool SECURE=false;


    while(true){
        memset(data_tcp, 0, sizeof(data_tcp));
        int bytes_received = recv(client_sock, data_tcp, 1024, 0);

        if (bytes_received == -1) {
            cerr << "Error: Failed to receive data from server socket.\n";
            break;
        }
        if (bytes_received == 0) {
            cout << "Server socket closed.\n";
            break;
        }
        data_tcp[bytes_received] = '\0';

        cout << "Data received from Alice: " << data_tcp<< endl;

        if (strcmp(data_tcp, "chat_STARTTLS") == 0) {

            
            // Send chat_STARTTLS TO BOB BY TRUDY
            
            send(client,"chat_STARTTLS",strlen("chat_STARTTLS"),0);

            //TRUDY receives chat_STARTTLS_ACK FROM SERVER AND FORWARDS IT TO CLIENT
             memset(data_tcp, 0, sizeof(data_tcp));

            read(client,data_tcp,1024);

            if(std::strcmp(data_tcp, "chat_STARTTLS_ACK") == 0){
                std::cout << "chat_STARTTLS_ACK received from Server ---->"<<endl;
                send(client_sock,"chat_STARTTLS_ACK",strlen("chat_STARTTLS_ACK"),0);
                SECURE=true;
            }


            if(SECURE){

                    // parameters for Trudy Server
                     ssl1 = SSL_new(ctx1);

                    SSL_set_fd(ssl1,client_sock);
                    if (SSL_accept(ssl1) <= 0) {
                    ERR_print_errors_fp(stderr);
                    SSL_shutdown(ssl1);
                    SSL_free(ssl1);
                    close(client_sock);
                    // continue;
                    }
                

                cout << "TLS connection between trudy and alice is established"<<endl;
                X509* cert = SSL_get_peer_certificate(ssl1);
                if (!cert) {
                    printf("Server certificate not provided\n");
                     return 0;
                    }

    


                if(SSL_get_verify_result(ssl1) == X509_V_OK){
                    cout << "Alice certificate verified by Trudy" <<endl;
                    }





                //Parameters for Trudy client
                ssl2 = SSL_new(ctx2);
                SSL_set_fd(ssl2, client);
            if (SSL_connect(ssl2) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_shutdown(ssl2);
        SSL_free(ssl2);
        close(client);
        exit(EXIT_FAILURE);
                }

        X509* cert2 = SSL_get_peer_certificate(ssl2);
            if (!cert2) {
                printf("Server certificate not provided\n");
                return 0;
            }

    


            if(SSL_get_verify_result(ssl2) == X509_V_OK){
                cout << "Bob Verified by Trudy" <<endl;
            }
            
               



            while(true){

                // Receive data from the Alice
            memset(data_tls, 0, sizeof(data_tls));
            if (SSL_read(ssl1, data_tls, sizeof(data_tls)) <= 0) {
                std::cout << "Connection closed by the client." << std::endl;
                break;
            }
            std::cout << "Msg Received from Client: " << data_tls<<endl;;
        // If the client sends "chat_close", close the connection
                if (std::strcmp(data_tls, "chat_close") == 0) {
            std::cout << "Closing connection." << std::endl;
            break;
        }
            // Forward  a message to the Bob
            SSL_write(ssl2, data_tls, strlen(data_tls));

            memset(data_tls, 0, sizeof(data_tls));
            SSL_read(ssl2, data_tls, sizeof(data_tls));

            cout << "Data Received from Bob to Trudy" << data_tls<<endl;
             if (std::strcmp(data_tls, "chat_close") == 0) {
            std::cout << "Closing connection." << std::endl;
            break;
        }
            //Forward the data from Trudy to Alice
            SSL_write(ssl1, data_tls, strlen(data_tls));
     

            }

                SSL_shutdown(ssl1);
                SSL_free(ssl1);
                SSL_CTX_free(ctx1);
    // Close the socket
                close(client_sock);

                SSL_shutdown(ssl2);
                SSL_free(ssl2);
                SSL_CTX_free(ctx2);
    // Close the socket
                close(client);


            return 0;

            }
           
            









        }else{

             cout << "Forward TCP data to Bob"<<endl;
        send(client, data_tcp, strlen(data_tcp), 0);

        }



    memset(data_tcp, 0, sizeof(data_tcp));
    // receive data from the target server
    bytes_received = read(client,data_tcp,1024);
    if (bytes_received == -1) {
        cerr << "Error: Failed to receive data from target server.\n";
        break;
    }
    if (bytes_received == 0) {
        cout << "Target server closed.\n";
        break;
    }
    data_tcp[bytes_received] = '\0';

    cout << "Data received from Bob: " << data_tcp << endl;

    // forward the data to the server socket

    send(client_sock, data_tcp, strlen(data_tcp), 0);

    cout << "Data is forwarded from Trudy to Alice ---->" << data_tcp << endl;




    }

    return 0;
}
