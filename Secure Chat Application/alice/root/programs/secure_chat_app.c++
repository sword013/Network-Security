#include <iostream>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void runServer()
{
    int bindsocket, newsocket, opt = 1;
    struct sockaddr_in server_addr, client_addr;
    socklen_t sin_size = sizeof(client_addr);

    SSL_CTX *ctx;
    const SSL_METHOD *method;
    SSL *ssl;
    char *listen_addr = "0.0.0.0";
    int listen_port = 8082;
    char *server_cert = "Certs/bob/bob.crt";
    char *server_key = "Certs/bob/bob.key";
    char *client_certs = "Certs/ca/ec-cacert.pem";
    bool SECURE = false;

    SSL_library_init();
    SSL_load_error_strings();
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    SSL_CTX_set_ecdh_auto(ctx, 1);
    SSL_CTX_set_default_verify_paths(ctx);
    SSL_CTX_use_certificate_file(ctx, server_cert, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, server_key, SSL_FILETYPE_PEM);
    SSL_CTX_load_verify_locations(ctx, client_certs, NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_keylog_callback(ctx, [](const SSL *ssl, const char *line) {
        printf("%s", line);
    });

    bindsocket = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(bindsocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(listen_port);
    inet_pton(AF_INET, listen_addr, &server_addr.sin_addr);
    bind(bindsocket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(bindsocket, 5);

    while (true)
    {
        std::cout << "Waiting for client" << std::endl;
        newsocket = accept(bindsocket, (struct sockaddr *)&client_addr, &sin_size);
        char buf[1024];
        memset(buf, 0, 1024);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, newsocket);

        if (SSL_accept(ssl) <= 0)
        {
            SSL_free(ssl);
            continue;
        }

        int rc = SSL_read(ssl, buf, sizeof(buf));
        std::string data(buf);
        std::cout << "Client connected: " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << std::endl;
        std::cout << "from connected user: " << data << std::endl;

        while (data != "chat_hello")
        {
            rc = SSL_read(ssl, buf, sizeof(buf));
            data = std::string(buf);
        }

        std::cout << "chat_hello Received  <-----" << std::endl;
        SSL_write(ssl, "chat_reply", strlen("chat_reply"));
        std::cout << "chat_reply Sent ---->" << std::endl;
        std::cout << "TCP Connection Established Successfully." << std::endl;
        std::cout << "------------------------------------------" << std::endl;

        
	
