#include "pch.h"
#include "tls.h"

using namespace std;
using wsmatch = std::match_results<wstring>;
using json = nlohmann::json;


void append8(const char* format, ...);

std::string utf16_to_utf8(const std::wstring& s) {
    int cb = WideCharToMultiByte(CP_UTF8, 0, s.data(), s.length(), nullptr, 0, nullptr, nullptr);
    char* pTmp = (char*)HeapAlloc(GetProcessHeap(), 0, cb);
    if (pTmp) {
        WideCharToMultiByte(CP_UTF8, 0, s.data(), s.length(), pTmp, cb, nullptr, nullptr);
        std::string sret(pTmp, cb);
        HeapFree(GetProcessHeap(), 0, pTmp);
        return sret;
    }
    else {
        return std::string();
    }
}

std::wstring utf8_to_utf16(const std::string& s) {
    int cb = MultiByteToWideChar(CP_UTF8, 0, s.data(), s.length(), nullptr, 0);
    wchar_t* pTmp = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, cb);
    if (pTmp) {
        MultiByteToWideChar(CP_UTF8, 0, s.data(), s.length(), pTmp, cb);
        std::wstring w(pTmp, cb);
        HeapFree(GetProcessHeap(), 0, pTmp);
        return w;
    }
    else {
        return std::wstring();
    }
}

std::string TlsSocket::proxystr() {
    return std::string();
}

// returns 0 on success or negative value on error
int TlsSocket::connect(const wstring& hostname, const wstring& port)
{
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

    // connect to server
    std::wstring pxname = this->proxy.empty() ? hostname : this->proxy;
    std::wstring pxport = this->proxy.empty() ? port : this->proxy_port;
    pxport = pxport.empty() ? L"3129" : pxport;
    if (!WSAConnectByName(this->sock, (LPWSTR)pxname.c_str(), (LPWSTR)pxport.c_str(), NULL, NULL, NULL, NULL, NULL, NULL))
    {
        this->disconnect();
        WSACleanup();
        return -1;
    }
    _tprintf(L"Connected to %ws:%ws\n", pxname.c_str(), pxport.c_str());

    // proxy initialization
    if (!this->proxy.empty()) {
        std::string hname = utf16_to_utf8(hostname);
        std::string hport = utf16_to_utf8(port);

        std::string ps = "CONNECT " + hname + ":" + hport + " HTTP/1.1\r\n";
        ps += "Host:" + utf16_to_utf8(hostname) + ":" + utf16_to_utf8(port) + "\r\n";
        ps += "User-Agent: Skyster_Client(1.0.0)\r\n";
        ps += "Proxy-Connection: Keep-Alive\r\n";
        ps += "\r\n";

        // send proxy headers
        if (send(this->sock, ps.data(), ps.length(), 0) <= 0) {
            append8("proxy connect: %s", "failed to connect proxy");
            this->disconnect();
            return -1;
        }

        // receive proxy response
        std::string rs;
        char* rsbuff = new char[1024];
        int rslen = 0;
        while ((rslen = recv(this->sock, rsbuff, sizeof(rsbuff), 0)) > 0) {
            rs += rsbuff;
            if (rs.find("\r\n\r\n") != std::string::npos) {
                break;
            }
        }
        delete[] rsbuff;
        if (rs.find("200") == std::string::npos) {
            append8("proxy connect: %s(%s)", "fail response from proxy", rs.substr(0, 3));
            this->disconnect();
            return -1;
        }

        append8("proxy established to %ws:%ws", hostname.c_str(), port.c_str());
    }

    // initialize schannel
    {
        SCHANNEL_CRED cred;
        ZeroMemory(&cred, sizeof(cred));
        cred.dwVersion = SCHANNEL_CRED_VERSION;
        cred.dwFlags = SCH_USE_STRONG_CRYPTO          // use only strong crypto alogorithms
            | SCH_CRED_AUTO_CRED_VALIDATION  // automatically validate server certificate
            | SCH_CRED_NO_DEFAULT_CREDS;     // no client certificate authentication
        cred.grbitEnabledProtocols = SP_PROT_TLS1_2 | SP_PROT_TLS1_3;

        if (AcquireCredentialsHandle(NULL, (LPWSTR)UNISP_NAME, SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &this->handle, NULL) != SEC_E_OK)
        {
            _tprintf(L"%lx\n", GetLastError());
            this->disconnect();
            return -1;
        }
    }

    this->received = this->used = this->available = 0;
    this->decrypted = NULL;

    // perform tls handshake
    // 1) call InitializeSecurityContext to create/update schannel context
    // 2) when it returns SEC_E_OK - tls handshake completed
    // 3) when it returns SEC_I_INCOMPLETE_CREDENTIALS - server requests client certificate (not supported here)
    // 4) when it returns SEC_I_CONTINUE_NEEDED - send token to server and read data
    // 5) when it returns SEC_E_INCOMPLETE_MESSAGE - need to read more data from server
    // 6) otherwise read data from server and go to step 1

    CtxtHandle* context = NULL;
    int result = 0;
    for (;;)
    {
        SecBuffer inbuffers[2] = { 0 };
        inbuffers[0].BufferType = SECBUFFER_TOKEN;
        inbuffers[0].pvBuffer = this->incoming;
        inbuffers[0].cbBuffer = this->received;
        inbuffers[1].BufferType = SECBUFFER_EMPTY;

        SecBuffer outbuffers[1] = { 0 };
        outbuffers[0].BufferType = SECBUFFER_TOKEN;

        SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
        SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };

        DWORD flags = ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
        SECURITY_STATUS sec = InitializeSecurityContext(
            &this->handle,
            context,
            context ? NULL : (SEC_WCHAR*)hostname.c_str(),
            flags,
            0,
            0,
            context ? &indesc : NULL,
            0,
            context ? NULL : &this->context,
            &outdesc,
            &flags,
            NULL);

        // after first call to InitializeSecurityContext context is available and should be reused for next calls
        context = &this->context;

        if (inbuffers[1].BufferType == SECBUFFER_EXTRA)
        {
            MoveMemory(this->incoming, this->incoming + (this->received - inbuffers[1].cbBuffer), inbuffers[1].cbBuffer);
            this->received = inbuffers[1].cbBuffer;
        }
        else
        {
            this->received = 0;
        }

        if (sec == SEC_E_OK)
        {
            // tls handshake completed
            break;
        }
        else if (sec == SEC_I_INCOMPLETE_CREDENTIALS)
        {
            // server asked for client certificate, not supported here
            _tprintf(L"SEC_I_INCOMPLETE_CREDENTIALS\n");
            result = -1;
            break;
        }
        else if (sec == SEC_I_CONTINUE_NEEDED)
        {
            // need to send data to server
            char* buffer = (char *)outbuffers[0].pvBuffer;
            int size = outbuffers[0].cbBuffer;

            while (size != 0)
            {
                int d = send(this->sock, buffer, size, 0);
                _tprintf(L"sent TLS handshake:%d\n", d);
                if (d <= 0)
                {
                    break;
                }
                size -= d;
                buffer += d;
            }
            FreeContextBuffer(outbuffers[0].pvBuffer);
            if (size != 0)
            {
                // failed to fully send data to server
                _tprintf(L"failed to fully send data to server\n");
                result = -1;
                break;
            }
        }
        else if (sec != SEC_E_INCOMPLETE_MESSAGE)
        {
            // SEC_E_CERT_EXPIRED - certificate expired or revoked
            // SEC_E_WRONG_PRINCIPAL - bad hostname
            // SEC_E_UNTRUSTED_ROOT - cannot vertify CA chain
            // SEC_E_ILLEGAL_MESSAGE / SEC_E_ALGORITHM_MISMATCH - cannot negotiate crypto algorithms
            wstring s = L"Unknown reason";
            switch (sec) {
            case SEC_E_CERT_EXPIRED: s = L"SEC_E_CERT_EXPIRED"; break;
            case SEC_E_WRONG_PRINCIPAL: s = L"SEC_E_WRONG_PRINCIPAL"; break;
            case SEC_E_UNTRUSTED_ROOT: s = L"SEC_E_UNTRUSTED_ROOT"; break;
            case SEC_E_ILLEGAL_MESSAGE: s = L"SEC_E_ILLEGAL_MESSAGE"; break;
            case SEC_E_ALGORITHM_MISMATCH: s = L"SEC_E_ALGORITHM_MISMATCH"; break;
            case SEC_E_BUFFER_TOO_SMALL: s = L"SEC_E_BUFFER_TOO_SMALL"; break;
            case SEC_E_APPLICATION_PROTOCOL_MISMATCH: s = L"SEC_E_APPLICATION_PROTOCOL_MISMATCH"; break;
            case SEC_E_BAD_BINDINGS: s = L"SEC_E_BAD_BINDINGS"; break;
            case SEC_E_BAD_PKGID: s = L"SEC_E_BAD_PKGID"; break;
            case SEC_E_CERT_UNKNOWN: s = L"SEC_E_CERT_UNKNOWN"; break;
            case SEC_E_INVALID_TOKEN: s = L"SEC_E_INVALID_TOKEN"; break;
            default:
                _tprintf(L"%lllx", sec);
            }
            _tprintf(L"%.*ws\n", (unsigned int)s.length(), s.data());
            result = -1;
            break;
        }

        // read more data from server when possible
        if (this->received == TLS_MAX_PACKET_SIZE)
        {
            // server is sending too much data instead of proper handshake?
            _tprintf(L"more data needed\n");
            result = -1;
            break;
        }

        int r = recv(this->sock, this->incoming + this->received, TLS_MAX_PACKET_SIZE - this->received, 0);
        _tprintf(L"received data:%d\n", r);
        if (r == 0)
        {
            // server disconnected socket
            return 0;
        }
        else if (r < 0)
        {
            // socket error
            _tprintf(L"recv socket error\n");
            result = -1;
            break;
        }
        this->received += r;
    }

    _tprintf(L"Handshake result:%d\n", result);

    if (result != 0)
    {
        DeleteSecurityContext(context);
        FreeCredentialsHandle(&this->handle);
        this->disconnect();
        return result;
    }

    QueryContextAttributes(context, SECPKG_ATTR_STREAM_SIZES, &this->sizes);
    return 0;
}

// disconnects socket & releases resources (call this even if tls_write/tls_read function return error)
void TlsSocket::disconnect()
{
    DWORD type = SCHANNEL_SHUTDOWN;

    SecBuffer inbuffers[1];
    inbuffers[0].BufferType = SECBUFFER_TOKEN;
    inbuffers[0].pvBuffer = &type;
    inbuffers[0].cbBuffer = sizeof(type);

    SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
    ApplyControlToken(&this->context, &indesc);

    SecBuffer outbuffers[1];
    outbuffers[0].BufferType = SECBUFFER_TOKEN;

    SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };
    DWORD flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
    if (InitializeSecurityContext(&this->handle, &this->context, NULL, flags, 0, 0, &outdesc, 0, NULL, &outdesc, &flags, NULL) == SEC_E_OK)
    {
        char* buffer = (char *)outbuffers[0].pvBuffer;
        int size = outbuffers[0].cbBuffer;
        while (size != 0)
        {
            int d = send(this->sock, buffer, size, 0);
            if (d <= 0)
            {
                // ignore any failures socket will be closed anyway
                break;
            }
            buffer += d;
            size -= d;
        }
        FreeContextBuffer(outbuffers[0].pvBuffer);
    }
    shutdown(this->sock, SD_BOTH);

    DeleteSecurityContext(&this->context);
    FreeCredentialsHandle(&this->handle);
    BaseSocket::disconnect();
}

// returns 0 on success or negative value on error
int64_t TlsSocket::write(const void* buffer, size_t size)
{
    char* wbuffer = new char[TLS_MAX_PACKET_SIZE];
    while (size != 0)
    {
        size_t use = min(size, this->sizes.cbMaximumMessage);

        assert(this->sizes.cbHeader + this->sizes.cbMaximumMessage + this->sizes.cbTrailer <= TLS_MAX_PACKET_SIZE);

        SecBuffer buffers[3];
        ZeroMemory(&buffers[0], sizeof(buffers));
        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
        buffers[0].pvBuffer = wbuffer;
        buffers[0].cbBuffer = this->sizes.cbHeader;
        buffers[1].BufferType = SECBUFFER_DATA;
        buffers[1].pvBuffer = wbuffer + this->sizes.cbHeader;
        buffers[1].cbBuffer = (unsigned long)use;
        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        buffers[2].pvBuffer = wbuffer + this->sizes.cbHeader + use;
        buffers[2].cbBuffer = this->sizes.cbTrailer;

        CopyMemory(buffers[1].pvBuffer, buffer, use);

        SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };
        SECURITY_STATUS sec = EncryptMessage(&this->context, 0, &desc, 0);
        if (sec != SEC_E_OK)
        {
            // this should not happen, but just in case check it
            delete[] wbuffer;
            return -1;
        }

        int total = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
        int sent = 0;
        while (sent != total)
        {
            int d = send(this->sock, wbuffer + sent, total - sent, 0);
            if (d <= 0)
            {
                // error sending data to socket, or server disconnected
                delete[] wbuffer;
                return -1;
            }
            sent += d;
        }

        buffer = (char*)buffer + use;
        size -= use;
    }
    delete[] wbuffer;
    return 0;
}

// blocking read, waits & reads up to size bytes, returns amount of bytes received on success (<= size)
// returns 0 on disconnect or negative value on error
int64_t TlsSocket::read(void* buffer, size_t size)
{
    int64_t result = 0;

    while (size != 0)
    {
        if (this->decrypted)
        {
            // if there is decrypted data available, then use it as much as possible
            size_t use = min(size, this->available);
            CopyMemory(buffer, this->decrypted, use);
            buffer = (char*)buffer + use;
            size -= use;
            result += use;

            if (use == this->available)
            {
                // all decrypted data is used, remove ciphertext from incoming buffer so next time it starts from beginning
                MoveMemory(this->incoming, this->incoming + this->used, this->received - this->used);
                this->received -= this->used;
                this->used = 0;
                this->available = 0;
                this->decrypted = NULL;
            }
            else
            {
                this->available -= (int)use;
                this->decrypted += (int)use;
            }
        }
        else
        {
            // if any ciphertext data available then try to decrypt it
            if (this->received != 0)
            {
                SecBuffer buffers[4];
                assert(this->sizes.cBuffers == ARRAYSIZE(buffers));

                buffers[0].BufferType = SECBUFFER_DATA;
                buffers[0].pvBuffer = this->incoming;
                buffers[0].cbBuffer = this->received;
                buffers[1].BufferType = SECBUFFER_EMPTY;
                buffers[2].BufferType = SECBUFFER_EMPTY;
                buffers[3].BufferType = SECBUFFER_EMPTY;

                SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };

                SECURITY_STATUS sec = DecryptMessage(&this->context, &desc, 0, NULL);
                if (sec == SEC_E_OK)
                {
                    assert(buffers[0].BufferType == SECBUFFER_STREAM_HEADER);
                    assert(buffers[1].BufferType == SECBUFFER_DATA);
                    assert(buffers[2].BufferType == SECBUFFER_STREAM_TRAILER);

                    this->decrypted = (char *)buffers[1].pvBuffer;
                    this->available = buffers[1].cbBuffer;
                    this->used = this->received - (buffers[3].BufferType == SECBUFFER_EXTRA ? buffers[3].cbBuffer : 0);

                    // data is now decrypted, go back to beginning of loop to copy memory to output buffer
                    continue;
                }
                else if (sec == SEC_I_CONTEXT_EXPIRED)
                {
                    // server closed TLS connection (but socket is still open)
                    this->received = 0;
                    return result;
                }
                else if (sec == SEC_I_RENEGOTIATE)
                {
                    // server wants to renegotiate TLS connection, not implemented here
                    return -1;
                }
                else if (sec != SEC_E_INCOMPLETE_MESSAGE)
                {
                    // some other schannel or TLS protocol error
                    return -1;
                }
                // otherwise sec == SEC_E_INCOMPLETE_MESSAGE which means need to read more data
            }
            // otherwise not enough data received to decrypt

            if (result != 0)
            {
                // some data is already copied to output buffer, so return that before blocking with recv
                break;
            }

            if (this->received == TLS_MAX_PACKET_SIZE)
            {
                // server is sending too much garbage data instead of proper TLS packet
                return -1;
            }

            // wait for more ciphertext data from server
            int r = recv(this->sock, this->incoming + this->received, TLS_MAX_PACKET_SIZE - this->received, 0);
            if (r == 0)
            {
                // server disconnected socket
                return 0;
            }
            else if (r < 0)
            {
                // error receiving data from socket
                result = -1;
                break;
            }
            this->received += r;
        }
    }

    return result;
}

void json_post(string& r, const wstring &url,const wstring &auth, const json &json, const wstring& proxy) {
    BaseSocket* ps = nullptr;
    std::wsmatch results;
    TCHAR pat[] = L"(http|https)://([A-Za-z0-9_.-]+)(:\\d+)?(/[/%+A-Za-z0-9_.-]*)";
    std::basic_regex<TCHAR> patr(pat);
    wstring hostname, port;
    std::string host_s, fstr;

    if (std::regex_match(url, results, patr)) {
        wstring prot = results[1].str();
        _tprintf(L"prot:%ws\n", prot.c_str());
        assert(prot == L"http" || prot == L"https");
        if (prot == L"http") {
            ps = new BaseSocket();
        }
        else if (prot == L"https") {
            ps = new TlsSocket();
        }
        else {
            _tprintf(L"Illegal URL:%ws\n", url.c_str());
            return;
        }
        hostname = results[2].str();
        port = results[3].str();
        wstring wfstr = results[4].str();
        if (wfstr.empty()) {
            wfstr = L"/";
        }
        size_t cbFstrLen = wfstr.length() + 1;
        char* fstrBuff = new char[cbFstrLen];
        ZeroMemory(fstrBuff, cbFstrLen);
        WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)wfstr.data(), (int)wfstr.length(), fstrBuff, cbFstrLen, NULL, NULL);
        fstr = std::string(fstrBuff);
        delete[] fstrBuff;
        size_t cbHostname = hostname.length() + 1;
        char* hostBuff = new char[cbHostname];
        ZeroMemory(hostBuff, cbHostname);
        WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)hostname.data(), (int)hostname.length(), hostBuff, cbHostname, NULL, NULL);
        host_s = std::string(hostBuff);
        delete[] hostBuff;
        if (port.empty()) {
            port = (prot == L"http") ? L"80" : L"443";
        }
        else
        {
            // ignore : character
            port = port.substr(1);
        }
    }
    else {
        _tprintf(L"Illegal URL:%ws\n", url.c_str());
        return;
    }

    if (!proxy.empty()) {
        auto pos = proxy.find(L":");
        std::wstring proxy_host;
        std::wstring proxy_port;

        if (pos != std::wstring::npos) {
            ps->proxy = proxy.substr(0, pos);
            ps->proxy_port = proxy.substr(pos + 1);
        }
        else {
            ps->proxy = proxy;
            ps->proxy_port = L"3129";
        }
    }

    _tprintf(L"host:%ws, port:%ws\n", hostname.c_str(), port.c_str());
    printf("host_s:%s, ", host_s.c_str());
    printf("fstr:%s\n", fstr.c_str());

    if (ps->connect(hostname, port) < 0) {
        _tprintf(L"failed to connect server.\n");
        return;
    }
    _tprintf(L"ps connected\n");
    std::unordered_map<std::string, std::string> headers;
    std::string send_str, auth_str;
    const char first_template[] = "POST %s%s HTTP/1.1\r\n";
    size_t len = fstr.length() + 32;
    char* first_line = new char[len];
    snprintf(first_line, len, first_template, ps->proxystr().c_str(), fstr.c_str());
    send_str += first_line;
    printf("send_str:%s", send_str.c_str());
    headers["User-Agent"] = "Skyster_Client/1.0.0";
    headers["Host"] = host_s.c_str();
    headers["Connection"] = "close";
    headers["Content-Type"] = "application/json";
    headers["Accept"] = "application/json";
    if (!auth.empty()) {
        std::string auth8 = utf16_to_utf8(auth);
        TCHAR pTmp[128];
        DWORD cbpTmp = sizeof(pTmp) / sizeof(TCHAR);
        CryptBinaryToString((BYTE *)auth8.data(), auth8.length(),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            pTmp, &cbpTmp);
        std::wstring wauth(pTmp, cbpTmp);
        auth_str = std::string("Basic ") + utf16_to_utf8(wauth);
        headers["Authorization"] = auth_str.c_str();
    }

    std::string jd = json.dump();
    snprintf(first_line, len, "%zd", jd.length());
    headers["Content-Length"] = first_line;
    for (std::unordered_map<std::string, std::string>::const_iterator i = headers.cbegin();
        i != headers.cend();
        i++) {
        send_str += i->first + ":" + i->second + "\r\n";
    }
    send_str += "\r\n";
    send_str += jd;
    append8("\n\nsend: %.*s\n", (uint32_t)send_str.length(), send_str.data());
    ps->write(send_str.data(), send_str.length());
    int64_t rlen;
    int cBuffer = 64 * 1024;
    char* buffer = new char[cBuffer];

    while ((rlen = ps->read(buffer, cBuffer)) > 0) {
        r += std::string(buffer, rlen);
    }
    append8("received: %lu bytes\n", (uint32_t)r.length());
    ps->disconnect();
    delete ps;
    append8("CP#1\n");
    delete[] buffer;
    append8("CP#2\n");
    delete [] first_line;
    append8("CP#3\n");
}

/*
int main()
{
    const char* hostname = "www.google.com";
    //const char* hostname = "badssl.com";
    //const char* hostname = "expired.badssl.com";
    //const char* hostname = "wrong.host.badssl.com";
    //const char* hostname = "self-signed.badssl.com";
    //const char* hostname = "untrusted-root.badssl.com";
    const char* path = "/";

    tls_socket s;
    if (tls_connect(&s, hostname, 443) != 0)
    {
        printf("Error connecting to %s\n", hostname);
        return -1;
    }

    printf("Connected!\n");

    // send request
    char req[1024];
    int len = sprintf(req, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostname);
    if (tls_write(&s, req, len) != 0)
    {
        tls_disconnect(&s);
        return -1;
    }

    // write response to file
    FILE* f = fopen("response.txt", "wb");
    int received = 0;
    for (;;)
    {
        char buf[65536];
        int r = tls_read(&s, buf, sizeof(buf));
        if (r < 0)
        {
            printf("Error receiving data\n");
            break;
        }
        else if (r == 0)
        {
            printf("Socket disconnected\n");
            break;
        }
        else
        {
            fwrite(buf, 1, r, f);
            fflush(f);
            received += r;
        }
    }
    fclose(f);

    printf("Received %d bytes\n", received);

    tls_disconnect(&s);
}
*/