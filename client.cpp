#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include "security.h"

#define PORT 8080

using namespace std;

int main()
{
    int sock;
    struct sockaddr_in server_address;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("Socket creation failed");
        return 1;
    }

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) <= 0)
    {
        perror("Invalid address");
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
    {
        perror("Connection failed");
        close(sock);
        return 1;
    }

    cout << "Connected to server" << endl;

    string username, password;

    cout << "Enter username: ";
    cin >> username;

    cout << "Enter password: ";
    cin >> password;

    if (!sendMessage(sock, username) || !sendMessage(sock, password))
    {
        cerr << "Failed to send credentials" << endl;
        close(sock);
        return 1;
    }

    string authResponse;

    if (!recvMessage(sock, authResponse))
    {
        cerr << "Failed to receive authentication response" << endl;
        close(sock);
        return 1;
    }

    if (authResponse != "AUTH_OK")
    {
        cout << "Sign in failed. Access denied." << endl;
        close(sock);
        return 1;
    }

    cout << "Sign in accepted by server." << endl;

    string command;
    cout << "Enter command (ls, read, copy, edit, delete): ";
    cin >> command;

    string encryptedCommand = aesEncrypt(command);

    if (!sendMessage(sock, encryptedCommand))
    {
        cerr << "Failed to send encrypted command" << endl;
        close(sock);
        return 1;
    }

    cout << "Encrypted command sent to server." << endl;

    string encryptedReply;

    if (!recvMessage(sock, encryptedReply))
    {
        cerr << "Failed to receive encrypted server response" << endl;
        close(sock);
        return 1;
    }

    string decryptedReply = aesDecrypt(encryptedReply);
    cout << "Server says: " << decryptedReply << endl;

    close(sock);
    return 0;
}
