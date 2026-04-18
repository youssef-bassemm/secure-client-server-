#ifndef SECURITY_H
#define SECURITY_H

#include <iostream>
#include <string>
#include <fstream>
#include <openssl/evp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUFFER_SIZE 4096

using namespace std;

const unsigned char *AES_KEY = (const unsigned char *)"12345678901234567890123456789012";
const unsigned char *AES_IV  = (const unsigned char *)"1234567890123456";

inline string aesEncrypt(const string &plainText)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char cipherText[BUFFER_SIZE];
    int len = 0, cipherLen = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY, AES_IV);
    EVP_EncryptUpdate(ctx, cipherText, &len,
                      (const unsigned char *)plainText.c_str(), plainText.length());
    cipherLen = len;

    EVP_EncryptFinal_ex(ctx, cipherText + len, &len);
    cipherLen += len;

    EVP_CIPHER_CTX_free(ctx);
    return string((char *)cipherText, cipherLen);
}

inline string aesDecrypt(const string &cipherText)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char plainText[BUFFER_SIZE];
    int len = 0, plainLen = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY, AES_IV);
    EVP_DecryptUpdate(ctx, plainText, &len,
                      (const unsigned char *)cipherText.c_str(), cipherText.length());
    plainLen = len;

    EVP_DecryptFinal_ex(ctx, plainText + len, &len);
    plainLen += len;

    EVP_CIPHER_CTX_free(ctx);
    return string((char *)plainText, plainLen);
}

inline bool authenticateUser(const string &username, const string &password, string &role)
{
    ifstream file("users.txt");
    string line;

    if (!file.is_open())
    {
        cerr << "Error: users.txt could not be opened." << endl;
        return false;
    }

    while (getline(file, line))
    {
        size_t firstPos = line.find(':');
        size_t secondPos = line.find(':', firstPos + 1);

        if (firstPos != string::npos && secondPos != string::npos)
        {
            string user = line.substr(0, firstPos);
            string pass = line.substr(firstPos + 1, secondPos - firstPos - 1);
            string userRole = line.substr(secondPos + 1);

            if (user == username && pass == password)
            {
                role = userRole;
                return true;
            }
        }
    }

    return false;
}

inline bool sendAll(int sock, const void *data, size_t length)
{
    size_t total = 0;
    const char *ptr = (const char *)data;

    while (total < length)
    {
        ssize_t sent = send(sock, ptr + total, length - total, 0);
        if (sent <= 0)
            return false;
        total += sent;
    }
    return true;
}

inline bool recvAll(int sock, void *data, size_t length)
{
    size_t total = 0;
    char *ptr = (char *)data;

    while (total < length)
    {
        ssize_t received = recv(sock, ptr + total, length - total, 0);
        if (received <= 0)
            return false;
        total += received;
    }
    return true;
}

inline bool sendMessage(int sock, const string &message)
{
    uint32_t len = htonl(message.size());

    if (!sendAll(sock, &len, sizeof(len)))
        return false;

    return sendAll(sock, message.c_str(), message.size());
}

inline bool recvMessage(int sock, string &message)
{
    uint32_t len = 0;

    if (!recvAll(sock, &len, sizeof(len)))
        return false;

    len = ntohl(len);

    if (len == 0 || len > BUFFER_SIZE)
        return false;

    char buffer[BUFFER_SIZE] = {0};

    if (!recvAll(sock, buffer, len))
        return false;

    message.assign(buffer, len);
    return true;
}

inline bool isCommandAllowed(const string &role, const string &command)
{
    if (role == "top")
        return true;

    if (role == "medium")
    {
        if (command == "ls" || command == "read" || command == "copy" || command == "edit")
            return true;
        return false;
    }

    if (role == "entry")
    {
        if (command == "ls" || command == "read")
            return true;
        return false;
    }

    return false;
}

#endif
