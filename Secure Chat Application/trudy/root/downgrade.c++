#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <netdb.h>

using namespace std;

int main()
{
    // Client : bob
    const char* HOST = "172.31.0.3";
    const int PORT = 8084;
    //const char* sv_hostname = "bob1";
    //struct hostent* bob = gethostbyname(sv_hostname);

    // Server : trudy
    // const char* listen_addr = "172.31.0.4";
    const int listen_port = 8084;
    const char * t_hostname = "trudy1";
    struct hostent* trudy = gethostbyname(t_hostname);

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
    //serv_addr.sin_addr.s_addr = *((in_addr_t*)bob->h_addr_list[0]);
    serv_addr.sin_addr.s_addr = inet_addr(HOST);
    serv_addr.sin_port = htons(PORT);
    if (connect(client, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
        cerr << "Error: Failed to connect to target server.\n";
        close(client_sock);
        close(ssocket);
        close(client);
        return 1;
    }

    char buffer[1024];
    char storage[1024];
    while (true) {
        // receive data from the server socket
        memset(buffer, 0, sizeof(buffer));
        int bytes_received = recv(client_sock, buffer, 1024, 0);
        if (bytes_received == -1) {
            cerr << "Error: Failed to receive data from server socket.\n";
            break;
        }
        if (bytes_received == 0) {
            cout << "Server socket closed.\n";
            break;
        }
        buffer[bytes_received] = '\0';

        cout << "Data received from Alice: " << buffer << endl;

        if (strcmp(buffer, "chat_STARTTLS") == 0) {
            cout << "Received chat_STARTTLS from Alice<----" << endl;
            cout << "Sending chat_STARTTLS_NOT_SUPPORTED to ALice from Trudy ---->" << endl;
            send(client_sock, "chat_STARTTLS_NOT_SUPPORT", strlen("chat_STARTTLS_NOT_SUPPORT"), 0);
            cout << "Sending chat_STARTTLS_NOT_SUPPORT FROM TRUDY TO BOB"<<endl;  
            send(client,"chat_STARTTLS_NOT_SUPPORT",strlen("chat_STARTTLS_NOT_SUPPORT"),0);
            bytes_received = read(client, buffer, 1024);
            if (bytes_received == -1) {
                cerr << "Error: Failed to receive data from target server.\n";
                break;
             }
            if (bytes_received == 0) {
                cout << "Target server closed.\n";
                break;
            }
            buffer[bytes_received] = '\0';

            cout << "Data received from Bob: " << buffer << endl;
            
        int bytes_received = recv(client_sock, buffer, 1024, 0);
         if (bytes_received == -1) {
            cerr << "Error: Failed to receive data from server socket.\n";
            break;
        }
        if (bytes_received == 0) {
            cout << "Server socket closed.\n";
            break;
        }
                buffer[bytes_received] = '\0';

        cout << "Data received from Alice in IF starttls: " << buffer << endl;
         cout << "Forward data to Bob"<<endl;
        send(client, buffer, strlen(buffer), 0);
            

    } else {
        // forward the data to the target server
        cout << "Forward data to Bob"<<endl;
        send(client, buffer, strlen(buffer), 0);
    }
    
    memset(storage, 0, sizeof(storage));
    // receive data from the target server
    bytes_received = read(client,storage,1024);
    if (bytes_received == -1) {
        cerr << "Error: Failed to receive data from target server.\n";
        break;
    }
    if (bytes_received == 0) {
        cout << "Target server closed.\n";
        break;
    }
    buffer[bytes_received] = '\0';

    cout << "Data received from Bob: " << storage << endl;

    // forward the data to the server socket

    send(client_sock, storage, strlen(storage), 0);

    cout << "Data is forwarded from Trudy to Alice ---->" << buffer << endl;
}

// close the sockets
close(client_sock);
close(ssocket);
close(client);

return 0;}
