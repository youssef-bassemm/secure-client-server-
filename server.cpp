#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "security.h"

#define PORT 8080

using namespace std;

void* handleClient(void* arg)
{
    int new_socket = *(int*)arg;
    delete (int*)arg;

    string username, password, role;

    if (!recvMessage(new_socket, username) || !recvMessage(new_socket, password))
    {
        cerr << "Failed to receive login credentials" << endl;
        close(new_socket);
        return NULL;
    }

    if (authenticateUser(username, password, role))
    {
        sendMessage(new_socket, "AUTH_OK");
        cout << "User signed in successfully: " << username << " | Role: " << role << endl;
        cout << "Access granted to client session." << endl;
    }
    else
    {
        sendMessage(new_socket, "AUTH_FAIL");
        cout << "Unauthorized login attempt for username: " << username << endl;
        close(new_socket);
        return NULL;
    }

    string encryptedCommand;

    if (!recvMessage(new_socket, encryptedCommand))
    {
        cerr << "Failed to receive encrypted command" << endl;
        close(new_socket);
        return NULL;
    }

    string command = aesDecrypt(encryptedCommand);
    cout << "Command received from " << username << ": " << command << endl;

    string reply;

    if (isCommandAllowed(role, command))
    {
        if (command == "ls")
            reply = "Command allowed: listing files";
        else if (command == "read")
            reply = "Command allowed: reading file";
        else if (command == "copy")
            reply = "Command allowed: copying file";
        else if (command == "edit")
            reply = "Command allowed: editing file";
        else if (command == "delete")
            reply = "Command allowed: deleting file";
        else
            reply = "Unknown command";
    }
    else
    {
        reply = "Permission denied for role: " + role;
    }

    string encryptedReply = aesEncrypt(reply);

    if (!sendMessage(new_socket, encryptedReply))
    {
        cerr << "Failed to send encrypted server response" << endl;
    }

    close(new_socket);
    return NULL;
}

int main()
{
    int server_fd;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("Socket failed");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("Bind failed");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 10) < 0)
    {
        perror("Listen failed");
        close(server_fd);
        return 1;
    }

    cout << "Server listening on port " << PORT << endl;

    while (true)
    {
        int* new_socket = new int;

        *new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen);
        if (*new_socket < 0)
        {
            perror("Accept failed");
            delete new_socket;
            continue;
        }

        cout << "Client connected" << endl;

        pthread_t thread_id;

        if (pthread_create(&thread_id, NULL, handleClient, new_socket) != 0)
        {
            perror("Thread creation failed");
            close(*new_socket);
            delete new_socket;
            continue;
        }

        pthread_detach(thread_id);
    }

    close(server_fd);
    return 0;
}
