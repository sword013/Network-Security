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
void runserver();
void runclient();


int verify_cert_chain(X509* cert, X509_STORE* store) {
    X509_STORE_CTX* ctx;
    int rc;

    // Initialize the context for verification
    ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, NULL);

    // Set the verification flags
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);

    // Verify the certificate chain
    rc = X509_verify_cert(ctx);
    if (rc != 1) {
        int err = X509_STORE_CTX_get_error(ctx);
        printf("Certificate verification error: %s\n", X509_verify_cert_error_string(err));
        return 0;
    }

    // Cleanup the context
    X509_STORE_CTX_free(ctx);
    return 1;
}

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

void runserver(){

    int sockfd, newsockfd;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addrSize;
    SSL_CTX *ctx;
    SSL *ssl;
    char buffer[1024];
    char data[1024];
    bool SECURE=false;
    // Create a TCP socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket() error");
        exit(EXIT_FAILURE);
    }

    // Set server address and port
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    //serverAddr.sin_addr.s_addr =inet_addr("172.31.0.3");
    // serverAddr.sin_addr.s_addr =inet_addr(gethostbyname(bob1)); 
    //bob will act like a server when alice tries to connect to him  
    
    const char* sv_hostname = "bob1";
    struct hostent* server = gethostbyname(sv_hostname);
    serverAddr.sin_addr.s_addr = *((in_addr_t*)server->h_addr_list[0]); 
    serverAddr.sin_port = htons(8084);

    // Bind the socket to the server address and port
    if (bind(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("bind() error");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(sockfd, 1) < 0) {
        perror("listen() error");
        exit(EXIT_FAILURE);
    }

    
    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLSv1_2_server_method());
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_SERVER);
        if (SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384") != 1) {
   // Handle error
}
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER,ssl_verify_callback);
    SSL_CTX_load_verify_locations(ctx, "CAfile.pem", NULL);
    // SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file("intermediate_ca.crt"));
    if (SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256") != 1) {
   // Handle error
}

     // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "bob_2.crt", SSL_FILETYPE_PEM) <= 0) {
        perror("SSL_CTX_use_certificate_file() error");
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "Bob.key", SSL_FILETYPE_PEM) <= 0) {
        perror("SSL_CTX_use_PrivateKey_file() error");
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stderr);
        perror("Private key does not match the certificate public key");
        exit(EXIT_FAILURE);
    }

    while (true) {
        std::cout << "Waiting for incoming connections..." << std::endl;
        addrSize = sizeof(clientAddr);
        // Accept incoming connection
        newsockfd = accept(sockfd, (struct sockaddr*)&clientAddr, &addrSize);
        if (newsockfd < 0) {
            perror("accept() error");
            continue;
        }
        std::cout << "Accepted a new connection from " << inet_ntoa(clientAddr.sin_addr)
            << ":" << ntohs(clientAddr.sin_port) << std::endl;

        memset(buffer, 0, sizeof(buffer));
        read( newsockfd , buffer, 1024);
        while (strcmp(buffer, "chat_hello") != 0) {
        memset(buffer, 0, sizeof(buffer));
        read(newsockfd, buffer, sizeof(buffer));
    }
        
        std::cout << "chat_hello_received"<< std::endl;

         send(newsockfd , "chat_reply" , strlen("chat_reply") , 0 );

         std::cout << "chat_reply_sent"<<std::endl;

        while(!SECURE){
            std::cout << "Security_check"<<std::endl;
            memset(data, 0, sizeof(data));
            read(newsockfd,data,1024);
            if(std::strcmp(data, "chat_STARTTLS") == 0){
                std::cout << "chat_STARTTLS received from Client ---->";
                
                memset(data, 0, sizeof(data));

                std::cin >>data;

                if(std::strcmp(data, "chat_STARTTLS_NOT_SUPPORT") == 0){
                    cout << "chat_STARTTLS_NOT_SUPPORT NOT SUPPORTED BY SERVER"<<endl;
                    send(newsockfd,data,strlen(data),0);
                    SECURE=false;
                    break;
                    
                }else{
                send(newsockfd,data,strlen(data),0);

                std::cout << "chat_STARTTLS_ACK Sent from Server ---->"<< std::endl;
                SECURE=true;
                break;}
            }
             if(std::strcmp(data, "chat_STARTTLS_NOT_SUPPORT") == 0){
                std::cout << "chat_STARTTLS_NOT_SUPPORT received from Client ---->";
                send(newsockfd,data,strlen(data),0);
                    SECURE=false;
                    break;
                    
                
                
            }
            if(std::strcmp(data, "chat_close") == 0){
                std::cout << "chat_close received from Client ---->";
                std::cout << "closing --->"<< std::endl;
                
            }

            std::cout << "Message received from client-->"<< data;
            std::cin >> data;
            send(newsockfd,data,strlen(data),0);

        }

    if(SECURE){

        std::cout<<"communication through secured (TCP+TLS) connection"<<std::endl;

        // Create an SSL object and set it up for the connection
        ssl = SSL_new(ctx);

        SSL_set_fd(ssl, newsockfd);

    //         X509* cert = SSL_get_peer_certificate(ssl);
    // if (!cert) {
    //     printf("Client certificate not provided\n");
    //     return;
    // }

    // // Verify client certificate chain
    // STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl);
    // int chain_len = sk_X509_num(chain);
    // for (int i = 0; i < chain_len; i++) {
    //     X509* chain_cert = sk_X509_value(chain, i);
    //     // Verify chain certificate against trusted root CA and intermediate CA
    //     int verify = SSL_CTX_get_verify_mode(ctx);
    //     if (!(verify & SSL_VERIFY_PEER) || !SSL_CTX_get_cert_store(ctx)) {
    //         printf("Certificate verification not set up\n");
    //         return ;
    //     }
    //     X509_STORE_CTX* store_ctx = X509_STORE_CTX_new();
    //     X509_STORE_CTX_init(store_ctx, SSL_CTX_get_cert_store(ctx), cert, chain);
    //     int ret = X509_verify_cert(store_ctx);
    //     if (ret <= 0) {
    //         char err_buf[256];
    //         X509_NAME_oneline(X509_get_subject_name(chain_cert), err_buf, 256);
    //         printf("Error verifying chain certificate: subject=%s\n", err_buf);
    //         X509_STORE_CTX_free(store_ctx);
    //         return ;
    //     }
    //     X509_STORE_CTX_free(store_ctx);
    // }
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(newsockfd);
            continue;
        }

        cout<<"FIne"<<endl;
   




        std::cout << "SSL connection established. Client Certificate:\n"
            << SSL_get_peer_certificate(ssl) << std::endl;

        while (true) {
            // Receive data from the client
            memset(buffer, 0, sizeof(buffer));
            if (SSL_read(ssl, buffer, sizeof(buffer)) <= 0) {
                std::cout << "Connection closed by the client." << std::endl;
                break;
            }
            std::cout << "Msg Received from Client: " << buffer<<endl;;
        // If the client sends "chat_close", close the connection
        if (std::strcmp(buffer, "chat_close") == 0) {
            std::cout << "Closing connection." << std::endl;
            break;
        }

        // Send a message to the client
        memset(buffer, 0, sizeof(buffer));
        std::cout << "Send message to client-> ";
        std::cin >> buffer;
        if (SSL_write(ssl, buffer, strlen(buffer)) <= 0) {
            std::cout << "Connection closed by the server." << std::endl;
            break;
        }
    }

    // Close the SSL connection and free the SSL object
    SSL_shutdown(ssl);
    SSL_free(ssl);
SSL_CTX_free(ctx);
    // Close the socket
    close(newsockfd);


    
    }

     while (true) {
            // Receive data from the client
            memset(buffer, 0, sizeof(buffer));
            if ( read(newsockfd,buffer,1024)<= 0) {
                std::cout << "Connection closed by the client." << std::endl;
                break;
            }
            std::cout << "Msg Received from Client: " << buffer<<endl;
        // If the client sends "chat_close", close the connection
        if (std::strcmp(buffer, "chat_close") == 0) {
            std::cout << "Closing connection." << std::endl;
            break;
        }

        // Send a message to the client
        memset(buffer, 0, sizeof(buffer));
        std::cout << "Send Message to client-> ";
        std::cin >> buffer;
        if (send(newsockfd,buffer,strlen(buffer),0)<= 0) {
            std::cout << "Connection closed by the server." << std::endl;
            break;
        }
    }

    close(newsockfd);
    return;

}

// Free the SSL context

}


void runclient(){

 int sockfd;
    struct sockaddr_in serverAddr;
    SSL_CTX *ctx=NULL;
    
    SSL *ssl=NULL;
    char buffer[1024];
    char data[1024];
    
   
    
     


    // Create a TCP socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket() error");
        exit(EXIT_FAILURE);
    }

    // Set server address and port
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
   // serverAddr.sin_addr.s_addr = inet_addr("172.31.0.2"); // Change to server's IP address
    //when bob tries to connect as a client to alice, alice1 is the server for it
    const char* sv_hostname = "alice1";
    struct hostent* server = gethostbyname(sv_hostname);
    serverAddr.sin_addr.s_addr = *((in_addr_t*)server->h_addr_list[0]); 

    serverAddr.sin_port = htons(8084);

    // Connect to the server
    if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("connect() error");
        exit(EXIT_FAILURE);
    }
    
    send(sockfd,"chat_hello",strlen("chat_hello"),0);

    memset(buffer, 0, sizeof(buffer));
    read( sockfd , buffer, 1024);
    while (strcmp(buffer, "chat_reply") != 0) {
        memset(buffer, 0, sizeof(buffer));
        read(sockfd,buffer, sizeof(buffer));
    }

        std::cout << "chat reply received..." <<std::endl;

    bool SECURE = false;
    

    std::cout << "Let's Start TLS Connection ->" << std::endl;
    memset(buffer, 0, sizeof(buffer));
    strcpy(buffer, "chat_STARTTLS");
    send(sockfd, buffer, strlen(buffer),0);
    std::cout << "chat_STARTTLS Sent ---->" <<std::endl;
    while(!SECURE){
            std::cout << "Security_check"<<std::endl;
            memset(data, 0, sizeof(data));
            read(sockfd,data,1024);
            if(std::strcmp(data, "chat_STARTTLS_ACK") == 0){
                std::cout << "chat_STARTTLS_ACK received from Server ---->"<<endl;;
                SECURE=true;
                break;
            }

            if(std::strcmp(data, "chat_STARTTLS_NOT_SUPPORT") == 0){
                std::cout << "chat_STARTTLS_NOT_SUPPORT received from Server ---->"<<endl;;
                SECURE=false;
                break;
            }

           
    }
 

    if(SECURE){
    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLSv1_2_client_method());
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_mode(ctx,SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER| SSL_VERIFY_FAIL_IF_NO_PEER_CERT,ssl_verify_callback);
    SSL_CTX_load_verify_locations(ctx, "CAfile.pem", NULL);
    SSL_CTX_set_verify_depth(ctx,2);
    // SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file("intermediate_ca.crt"));

     if (SSL_CTX_use_certificate_file(ctx, "alice_2.crt", SSL_FILETYPE_PEM) <= 0) {
        perror("SSL_CTX_use_certificate_file() error");
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "alice.key", SSL_FILETYPE_PEM) <= 0) {
        perror("SSL_CTX_use_PrivateKey_file() error");
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        perror("Private key does not match the certificate public key");
        exit(EXIT_FAILURE);
    }
   
    
    

    // Load client certificate and private key
     

   

    
    
    

    // Create an SSL object and set it up for the connection
    ssl = SSL_new(ctx);
 
    
    

    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

 X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        printf("Server certificate not provided\n");
        return;
    }

    cout << "Passed"<<endl;


if(SSL_get_verify_result(ssl) == X509_V_OK){
    cout << "It is fine " <<endl;
}
   
    // // Verify client certificate chain
    // STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl);
    // int chain_len = sk_X509_num(chain);
    // for (int i = 0; i < chain_len; i++) {
    //     X509* chain_cert = sk_X509_value(chain, i);
    //     // Verify chain certificate against trusted root CA and intermediate CA
    //     int verify = SSL_CTX_get_verify_mode(ctx);
    //     if (!(verify & SSL_VERIFY_PEER) || !SSL_CTX_get_cert_store(ctx)) {
    //         printf("Certificate verification not set up\n");
    //         return ;
    //     }
    //     X509_STORE_CTX* store_ctx = X509_STORE_CTX_new();
    //     X509_STORE_CTX_init(store_ctx, SSL_CTX_get_cert_store(ctx), cert, chain);
    //     int ret = X509_verify_cert(store_ctx);
    //     if (ret <= 0) {
    //         char err_buf[256];
    //         X509_NAME_oneline(X509_get_subject_name(chain_cert), err_buf, 256);
    //         printf("Error verifying chain certificate: subject=%s\n", err_buf);
    //         X509_STORE_CTX_free(store_ctx);
    //         return ;
    //     }
    //     X509_STORE_CTX_free(store_ctx);
    // }
 

    
   

    std::cout << "SSL connection established. Server Certificate:\n"
        << SSL_get_peer_certificate(ssl) << std::endl;

    while(true) {
        // Send a message to the server
        std::string msg;
        memset(buffer, 0, sizeof(buffer));
        std::cout << "-> ";
        cin >> buffer;
        if (SSL_write(ssl, buffer, strlen(buffer)) <= 0) {
            std::cout << "Connection closed by the server." << std::endl;
            break;
        }

        // Receive data from the server
        memset(buffer, 0, sizeof(buffer));
        if (SSL_read(ssl, buffer, sizeof(buffer)) <= 0) {
            std::cout << "Connection closed by the server." << std::endl;
            break;
        }
        std::cout << "Msg Received from Server: " << buffer;

        // If the server sends "chat_close", close the connection
        if (std::strcmp(buffer, "chat_close") == 0) {
            std::cout << "Closing connection." << std::endl;
            break;
        }
    }

    // Close the SSL connection and free the SSL object
    SSL_shutdown(ssl);
    SSL_free(ssl);

    // Close the socket
    close(sockfd);
    
    }

    while(true) {
        // Send a message to the server
        std::string msg;
        memset(buffer, 0, sizeof(buffer));
        std::cout << "Send Message to server-> ";
        cin >> buffer;
        if (send(sockfd,buffer,1024,0)<= 0) {
            std::cout << "Connection closed by the server." << std::endl;
            break;
        }

        // Receive data from the server
        memset(buffer, 0, sizeof(buffer));
        if ( read(sockfd,buffer,1024)<= 0) {
            std::cout << "Connection closed by the server." << std::endl;
            break;
        }
        std::cout << "Msg Received from Server: " << buffer;

        // If the server sends "chat_close", close the connection
        if (std::strcmp(buffer, "chat_close") == 0) {
            std::cout << "Closing connection." << std::endl;
            break;
        }
    }


    

    close(sockfd);




    
    // Free the SSL context
    SSL_CTX_free(ctx);
     return;


}


int main(int argc, char *argv[]){

    cout << argv[1];

    if(string(argv[1])=="-s"){
        runserver();
    }

    if(string(argv[1])=="-c"){
        runclient();
    }

    return 0;

}
