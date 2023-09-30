#pragma once
#include "pch.h"
#define TLS_MAX_PACKET_SIZE (16384+512) // payload + extra over head for header/mac/padding (probably an overestimate)

std::string utf16_to_utf8(const std::wstring& s);

namespace std {
    struct BaseSocket {
        SOCKET sock;
        std::wstring proxy;
        std::wstring proxy_port;
        std::string t_hostname;
        std::string t_port;
        BaseSocket() : sock(0), proxy(), proxy_port() {}
        BaseSocket(const std::wstring& proxy, const wstring& port) : sock(0), proxy(proxy), proxy_port(port) {}
        ~BaseSocket() { this->disconnect(); WSACleanup(); }
        virtual int connect(const wstring& host, const wstring &port);
        virtual int64_t read(void* buffer, size_t size);
        virtual int64_t write(const void* buffer, size_t size);
        virtual std::string proxystr();
        virtual void disconnect() { if (this->sock) { closesocket(this->sock); this->sock = 0; } }
    };

    struct TlsSocket : BaseSocket {
        CredHandle handle;
        CtxtHandle context;
        SecPkgContext_StreamSizes sizes;
        int received;    // byte count in incoming buffer (ciphertext)
        int used;        // byte count used from incoming buffer to decrypt current packet
        int available;   // byte count available for decrypted bytes
        char* decrypted; // points to incoming buffer where data is decrypted inplace
        char* incoming;
        TlsSocket() : BaseSocket(), handle(), context(), sizes(),
            received(0), used(0), available(0), decrypted(nullptr), incoming(new char[TLS_MAX_PACKET_SIZE]) {
        }
        TlsSocket(const std::wstring proxy, const std::wstring proxy_port)
            : BaseSocket(proxy, proxy_port), handle(), context(), sizes(),
            received(0), used(0), available(0),
            decrypted(nullptr), incoming(new char[TLS_MAX_PACKET_SIZE]) {
        }
        ~TlsSocket() { delete[] this->incoming; }
        virtual int connect(const wstring& host, const wstring& port);
        virtual int64_t read(void* buffer, size_t size);
        virtual int64_t write(const void* buffer, size_t size);
        virtual std::string proxystr();
        virtual void disconnect();
    };
}