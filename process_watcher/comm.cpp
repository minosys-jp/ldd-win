#include "pch.h"
#include "tls.h"
#define PACKET_SIZE (16535)

using namespace std;

std::string BaseSocket::proxystr() {
    if (!this->proxy.empty()) {
        return "http://" + this->t_hostname + ":" + this->t_port;
    }
    return std::string();
}

int BaseSocket::connect(const std::wstring& hostname, const std::wstring& port) {
    // initialize windows sockets
    WSADATA wsadata;
    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
    {
        return -1;
    }

    // create TCP IPv4 socket
    this->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (this->sock == INVALID_SOCKET)
    {
        WSACleanup();
        return -1;
    }

    std::wstring pxname = this->proxy.empty() ? hostname : this->proxy;
    std::wstring pxport = this->proxy.empty() ? port : this->proxy_port;
    pxport = pxport.empty() ? L"3129" : pxport;
    if (!WSAConnectByName(this->sock, (LPWSTR)pxname.c_str(), (LPWSTR)pxport.c_str(), NULL, NULL, NULL, NULL, NULL, NULL))
    {
        this->disconnect();
        WSACleanup();
        return -1;
    }
    this->t_hostname = utf16_to_utf8(hostname);
    this->t_port = utf16_to_utf8(port);
    return 0;
}

int64_t BaseSocket::write(const void* b, size_t sz) {
    int64_t len = 0;
    int written;
    int npack = (sz > PACKET_SIZE) ? PACKET_SIZE : (int)sz;
    while (npack > 0 && (written = ::send(this->sock, (const char *)b + len, npack, 0)) > 0) {
        len += written;
        sz -= written;
        npack = (sz > PACKET_SIZE) ? PACKET_SIZE : (int)sz;
    }
    return len;
}

int64_t BaseSocket::read(void* b, size_t sz) {
    int64_t len = 0;
    int npack = (sz > PACKET_SIZE) ? PACKET_SIZE : (int)sz;
    int rbytes;
    while (npack > 0 && (rbytes = ::recv(this->sock, (char*)b + len, npack, 0)) > 0) {
        len += rbytes;
        sz -= rbytes;
        npack = (sz > PACKET_SIZE) ? PACKET_SIZE : (int)sz;
    }
    return len;
}
