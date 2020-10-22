#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include "HttpClient.h"

extern "C" {
#include <MacTCP.h>
#include <Threads.h>
#include <mactcp/CvtAddr.h>
#include <mactcp/TCPHi.h>
}

void ThreadEntry(void *param);

HttpClient::HttpClient() {
  Init("");
}

HttpClient::HttpClient(string baseUri) {
  Init(baseUri);
}

/* Public functions */
void HttpClient::SetProxy(string host, int port) {
  _proxyHost = host;
  _proxyPort = port;
}

void HttpClient::Get(const string &requestUri, function<void(HttpResponse &)> onComplete) {
  try {
    Uri uri = GetUri(requestUri);

    Get(uri, onComplete);
  } catch (const invalid_argument &e) {
    HttpResponse response;
    response.ErrorMsg = e.what();
    onComplete(response);
  }
}

void HttpClient::Get(const Uri &requestUri, function<void(HttpResponse &)> onComplete) {
  string getRequest = "GET " + requestUri.Path + " HTTP/1.1\r\n" + "Host: " + requestUri.Host + "\r\n" +
                      GetAuthHeader() + "User-Agent: MacHTTP\r\n\r\n";

  Request(requestUri, getRequest, onComplete);
}

void HttpClient::Post(const string &requestUri, const string &content, function<void(HttpResponse &)> onComplete) {
  try {
    Uri uri = GetUri(requestUri);

    Post(uri, content, onComplete);
  } catch (const invalid_argument &e) {
    HttpResponse response;
    response.ErrorMsg = e.what();
    onComplete(response);
  }
}

void HttpClient::Post(const Uri &requestUri, const string &content, function<void(HttpResponse &)> onComplete) {
  string method = "POST";
  PutPost(requestUri, method, content, onComplete);
}

void HttpClient::Put(const Uri &requestUri, const string &content, function<void(HttpResponse &)> onComplete) {
  string method = "PUT";
  PutPost(requestUri, method, content, onComplete);
}

void HttpClient::PutPost(const Uri &requestUri, const string &method, const string &content,
                         function<void(HttpResponse &)> onComplete) {
  string request = method + " " + requestUri.Path + " HTTP/1.1\r\n" + "Host: " + requestUri.Host + "\r\n" +
                   GetAuthHeader() + "User-Agent: MacHTTP\r\n" + "Content-Length: " + to_string(content.length()) +
                   "\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n\r\n" + content;

  Request(requestUri, request, onComplete);
}

void HttpClient::SetDebugLevel(int debugLevel) {
  _debugLevel = debugLevel;
}

void HttpClient::SetStunnel(string host, int port) {
  _stunnelHost = host;
  _stunnelPort = port;
}

void HttpClient::SetAuthorization(string authorization) {
  _authorization = authorization;
}

/* Private functions */
void HttpClient::Init(string baseUri) {
  MaxApplZone();

  _baseUri = baseUri;
  InitParser();

#ifdef SSL_ENABLED
  _overrideCipherSuite[0] = 0;
#endif
}

void HttpClient::Yield() {
  YieldToAnyThread();
}

string HttpClient::GetAuthHeader() {
  if (_authorization != "") {
    return "Authorization: " + _authorization + "\r\n";
  }

  return "";
}

void HttpClient::Connect(const Uri &uri, unsigned long stream) {
  HttpResponse response;

  string request =
      "CONNECT " + uri.Host + ":443 HTTP/1.1\r\n" + "Host: " + uri.Host + ":443\r\n" + "User-Agent: MacHTTP\r\n\r\n";

  SendData(stream, (Ptr)request.c_str(), (unsigned short)strlen(request.c_str()), false, (GiveTimePtr)Yield, &_cancel);
}

Uri HttpClient::GetUri(const string &requestUri) {
  if (!Uri::IsAbsolute(requestUri)) {
    string absUri = _baseUri + requestUri;
    return Uri(absUri);
  }

  return Uri(requestUri);
}

void HttpClient::CancelRequest() {
  if (_status != Idle) {
    _cancel = true;
  }
}

void HttpClient::Request(const Uri &uri, const string &request, function<void(HttpResponse &)> onComplete) {
  _uri = uri;
  _request = request;
  _onComplete = onComplete;
  _cRequest = NULL;
  _cancel = false;
  _response.Reset();
  _status = Waiting;

  // Reset http parser
  memset(&_parser, 0, sizeof(_parser));
  _parser.data = (void *)&_response;
  http_parser_init(&_parser, HTTP_RESPONSE);

  ThreadID id;
  NewThread(kCooperativeThread, (ThreadEntryTPP)ThreadEntry, this,
            0,  // Default stack size
            kCreateIfNeeded, NULL, &id);
}

void ThreadEntry(void *param) {
  HttpClient *httpClient = (HttpClient *)param;

  httpClient->InitThread();
}

void HttpClient::InitThread() {
  _status = Running;

  if (_uri.Scheme == "http" || (_stunnelHost != "" && _uri.Scheme == "https")) {
    HttpRequest();
  }
#ifdef SSL_ENABLED
  else {
    HttpsRequest();
  }
#endif
}

HttpClient::RequestStatus HttpClient::GetStatus() {
  return _status;
}

void HttpClient::ProcessRequests() {
  YieldToAnyThread();
}

void HttpClient::HttpRequest() {
  if (Connect()) {
    if (Request()) {
      Response();
    }
  }
  NetClose();
}

#ifdef SSL_ENABLED
void HttpClient::HttpsRequest() {
  printf("before SSL connect\n");
  if (SslConnect()) {
    printf("before SSL handshake\n");
    if (SslHandshake()) {
      printf("before SSL request\n");
      if (SslRequest()) {
        printf("before SSL respone\n");
        SslResponse();
      }
    }
  }

  SslClose();
}
#endif  // SSL_ENABLED

void HttpClient::InitParser() {
  // Set parser data
  _parser.data = (void *)&_response;

  // Parser settings
  memset(&_settings, 0, sizeof(_settings));
  _settings.on_status = on_status_callback;
  _settings.on_header_field = on_header_field_callback;
  _settings.on_header_value = on_header_value_callback;
  _settings.on_message_complete = on_message_complete_callback;
  _settings.on_body = on_body_callback;
}

bool HttpClient::DoRedirect() {
  if (_response.Success && _response.StatusCode == 302 && _response.Headers.count("Location") > 0) {
    string location = _response.Headers["Location"];

    if (!Uri::IsAbsolute(location)) {
      location = _uri.Scheme + "://" + _uri.Host + location;
    }

    // Perform 302 redirect
    Get(location, _onComplete);
    return true;
  }

  return false;
}

string HttpClient::GetRemoteHost(const Uri &uri) {
  if (_proxyHost != "") {
    return _proxyHost;
  } else {
    return uri.Host;
  }
}

int HttpClient::GetRemotePort(const Uri &uri) {
  if (_proxyPort > 0) {
    return _proxyPort;
  } else if (uri.Scheme == "https") {
    return 443;
  }

  return 80;
}

bool HttpClient::Connect() {
  OSErr err;
  unsigned long ipAddress;

  // Open the network driver
  err = InitNetwork();
  if (err != noErr) {
    _response.ErrorCode = ConnectionError;
    _response.ErrorMsg = "InitNetwork returned " + to_string(err);
    return false;
  }

  // Get remote IP
  char *hostname = _stunnelHost != "" ? (char *)_stunnelHost.c_str() : (char *)GetRemoteHost(_uri).c_str();
  err = ConvertStringToAddr(hostname, &ipAddress, (GiveTimePtr)Yield);
  if (err != noErr) {
    _response.ErrorCode = ConnectionError;
    _response.ErrorMsg = "ConvertStringToAddr returned " + to_string(err) + " for hostname " + string(hostname);
    return false;
  }

  // Open a TCP stream
  err = CreateStream(&_stream, BUF_SIZE, (GiveTimePtr)Yield, &_cancel);
  if (err != noErr) {
    _response.ErrorCode = ConnectionError;
    _response.ErrorMsg = "CreateStream returned " + to_string(err);
    return false;
  }

  // Open a connection
  err = OpenConnection(_stream, ipAddress, _stunnelPort > 0 ? _stunnelPort : GetRemotePort(_uri), 0, (GiveTimePtr)Yield,
                       &_cancel);
  if (err == noErr) {
    if (_uri.Scheme == "https" && _proxyHost != "") {
      // First issue CONNECT request to open SSl tunnel via proxy
      Connect(_uri, _stream);
    }
  } else {
    _response.ErrorCode = ConnectionError;
    _response.ErrorMsg = "OpenConnection returned " + to_string(err);
    return false;
  }

  // Connect success, move to next status
  return true;
}

bool HttpClient::Request() {
  // Send the request
  OSErr err = SendData(_stream, (Ptr)_request.c_str(), (unsigned short)strlen(_request.c_str()), false,
                       (GiveTimePtr)Yield, &_cancel);

  if (err != noErr) {
    _response.ErrorCode = ConnectionError;
    _response.ErrorMsg = "SendData returned " + to_string(err);
    return false;
  }

  // Request complete, move to next status
  return true;
}

bool HttpClient::Response() {
  unsigned char buf[BUF_SIZE];
  unsigned short dataLength;
  int ret;

  while (true) {
    dataLength = sizeof(buf) - 1;
    memset(buf, 0, sizeof(buf));

    OSErr err = RecvData(_stream, (Ptr)&buf, &dataLength, false, (GiveTimePtr)Yield, &_cancel);

    ret = http_parser_execute(&_parser, &_settings, (const char *)&buf, dataLength);

    if (_response.MessageComplete || err == connectionClosing) {
      // Read response complete
      _response.Success = true;
      break;
    }

    if (ret < 0) {
      _response.ErrorCode = ConnectionError;
      _response.ErrorMsg = "http_parser_execute returned " + to_string(ret);
      return false;
    }
  }

  return true;
}

void HttpClient::NetClose() {
  CloseConnection(_stream, (GiveTimePtr)Yield, &_cancel);
  ReleaseStream(_stream, (GiveTimePtr)Yield, &_cancel);

  if (!DoRedirect()) {
    _status = Idle;
    if (!_cancel) {
      _onComplete(_response);
    } else {
      _cancel = false;
    }
  }
}

#ifdef SSL_ENABLED

static const unsigned char DigiCertHighAssuranceEVRootCA_crt[] = {
    0x30, 0x82, 0x03, 0xc5, 0x30, 0x82, 0x02, 0xad, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x02, 0xac, 0x5c, 0x26,
    0x6a, 0x0b, 0x40, 0x9b, 0x8f, 0x0b, 0x79, 0xf2, 0xae, 0x46, 0x25, 0x77, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x6c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
    0x13, 0x02, 0x55, 0x53, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0c, 0x44, 0x69, 0x67, 0x69,
    0x43, 0x65, 0x72, 0x74, 0x20, 0x49, 0x6e, 0x63, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x10,
    0x77, 0x77, 0x77, 0x2e, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x2b, 0x30,
    0x29, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x22, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x48, 0x69,
    0x67, 0x68, 0x20, 0x41, 0x73, 0x73, 0x75, 0x72, 0x61, 0x6e, 0x63, 0x65, 0x20, 0x45, 0x56, 0x20, 0x52, 0x6f, 0x6f,
    0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x30, 0x36, 0x31, 0x31, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x5a, 0x17, 0x0d, 0x33, 0x31, 0x31, 0x31, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x6c,
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03,
    0x55, 0x04, 0x0a, 0x13, 0x0c, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x49, 0x6e, 0x63, 0x31, 0x19,
    0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x10, 0x77, 0x77, 0x77, 0x2e, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65,
    0x72, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x2b, 0x30, 0x29, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x22, 0x44, 0x69,
    0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x48, 0x69, 0x67, 0x68, 0x20, 0x41, 0x73, 0x73, 0x75, 0x72, 0x61, 0x6e,
    0x63, 0x65, 0x20, 0x45, 0x56, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30,
    0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc6, 0xcc, 0xe5, 0x73, 0xe6, 0xfb, 0xd4, 0xbb, 0xe5, 0x2d, 0x2d,
    0x32, 0xa6, 0xdf, 0xe5, 0x81, 0x3f, 0xc9, 0xcd, 0x25, 0x49, 0xb6, 0x71, 0x2a, 0xc3, 0xd5, 0x94, 0x34, 0x67, 0xa2,
    0x0a, 0x1c, 0xb0, 0x5f, 0x69, 0xa6, 0x40, 0xb1, 0xc4, 0xb7, 0xb2, 0x8f, 0xd0, 0x98, 0xa4, 0xa9, 0x41, 0x59, 0x3a,
    0xd3, 0xdc, 0x94, 0xd6, 0x3c, 0xdb, 0x74, 0x38, 0xa4, 0x4a, 0xcc, 0x4d, 0x25, 0x82, 0xf7, 0x4a, 0xa5, 0x53, 0x12,
    0x38, 0xee, 0xf3, 0x49, 0x6d, 0x71, 0x91, 0x7e, 0x63, 0xb6, 0xab, 0xa6, 0x5f, 0xc3, 0xa4, 0x84, 0xf8, 0x4f, 0x62,
    0x51, 0xbe, 0xf8, 0xc5, 0xec, 0xdb, 0x38, 0x92, 0xe3, 0x06, 0xe5, 0x08, 0x91, 0x0c, 0xc4, 0x28, 0x41, 0x55, 0xfb,
    0xcb, 0x5a, 0x89, 0x15, 0x7e, 0x71, 0xe8, 0x35, 0xbf, 0x4d, 0x72, 0x09, 0x3d, 0xbe, 0x3a, 0x38, 0x50, 0x5b, 0x77,
    0x31, 0x1b, 0x8d, 0xb3, 0xc7, 0x24, 0x45, 0x9a, 0xa7, 0xac, 0x6d, 0x00, 0x14, 0x5a, 0x04, 0xb7, 0xba, 0x13, 0xeb,
    0x51, 0x0a, 0x98, 0x41, 0x41, 0x22, 0x4e, 0x65, 0x61, 0x87, 0x81, 0x41, 0x50, 0xa6, 0x79, 0x5c, 0x89, 0xde, 0x19,
    0x4a, 0x57, 0xd5, 0x2e, 0xe6, 0x5d, 0x1c, 0x53, 0x2c, 0x7e, 0x98, 0xcd, 0x1a, 0x06, 0x16, 0xa4, 0x68, 0x73, 0xd0,
    0x34, 0x04, 0x13, 0x5c, 0xa1, 0x71, 0xd3, 0x5a, 0x7c, 0x55, 0xdb, 0x5e, 0x64, 0xe1, 0x37, 0x87, 0x30, 0x56, 0x04,
    0xe5, 0x11, 0xb4, 0x29, 0x80, 0x12, 0xf1, 0x79, 0x39, 0x88, 0xa2, 0x02, 0x11, 0x7c, 0x27, 0x66, 0xb7, 0x88, 0xb7,
    0x78, 0xf2, 0xca, 0x0a, 0xa8, 0x38, 0xab, 0x0a, 0x64, 0xc2, 0xbf, 0x66, 0x5d, 0x95, 0x84, 0xc1, 0xa1, 0x25, 0x1e,
    0x87, 0x5d, 0x1a, 0x50, 0x0b, 0x20, 0x12, 0xcc, 0x41, 0xbb, 0x6e, 0x0b, 0x51, 0x38, 0xb8, 0x4b, 0xcb, 0x02, 0x03,
    0x01, 0x00, 0x01, 0xa3, 0x63, 0x30, 0x61, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04,
    0x03, 0x02, 0x01, 0x86, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01,
    0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xb1, 0x3e, 0xc3, 0x69, 0x03, 0xf8,
    0xbf, 0x47, 0x01, 0xd4, 0x98, 0x26, 0x1a, 0x08, 0x02, 0xef, 0x63, 0x64, 0x2b, 0xc3, 0x30, 0x1f, 0x06, 0x03, 0x55,
    0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xb1, 0x3e, 0xc3, 0x69, 0x03, 0xf8, 0xbf, 0x47, 0x01, 0xd4, 0x98,
    0x26, 0x1a, 0x08, 0x02, 0xef, 0x63, 0x64, 0x2b, 0xc3, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x1c, 0x1a, 0x06, 0x97, 0xdc, 0xd7, 0x9c, 0x9f, 0x3c,
    0x88, 0x66, 0x06, 0x08, 0x57, 0x21, 0xdb, 0x21, 0x47, 0xf8, 0x2a, 0x67, 0xaa, 0xbf, 0x18, 0x32, 0x76, 0x40, 0x10,
    0x57, 0xc1, 0x8a, 0xf3, 0x7a, 0xd9, 0x11, 0x65, 0x8e, 0x35, 0xfa, 0x9e, 0xfc, 0x45, 0xb5, 0x9e, 0xd9, 0x4c, 0x31,
    0x4b, 0xb8, 0x91, 0xe8, 0x43, 0x2c, 0x8e, 0xb3, 0x78, 0xce, 0xdb, 0xe3, 0x53, 0x79, 0x71, 0xd6, 0xe5, 0x21, 0x94,
    0x01, 0xda, 0x55, 0x87, 0x9a, 0x24, 0x64, 0xf6, 0x8a, 0x66, 0xcc, 0xde, 0x9c, 0x37, 0xcd, 0xa8, 0x34, 0xb1, 0x69,
    0x9b, 0x23, 0xc8, 0x9e, 0x78, 0x22, 0x2b, 0x70, 0x43, 0xe3, 0x55, 0x47, 0x31, 0x61, 0x19, 0xef, 0x58, 0xc5, 0x85,
    0x2f, 0x4e, 0x30, 0xf6, 0xa0, 0x31, 0x16, 0x23, 0xc8, 0xe7, 0xe2, 0x65, 0x16, 0x33, 0xcb, 0xbf, 0x1a, 0x1b, 0xa0,
    0x3d, 0xf8, 0xca, 0x5e, 0x8b, 0x31, 0x8b, 0x60, 0x08, 0x89, 0x2d, 0x0c, 0x06, 0x5c, 0x52, 0xb7, 0xc4, 0xf9, 0x0a,
    0x98, 0xd1, 0x15, 0x5f, 0x9f, 0x12, 0xbe, 0x7c, 0x36, 0x63, 0x38, 0xbd, 0x44, 0xa4, 0x7f, 0xe4, 0x26, 0x2b, 0x0a,
    0xc4, 0x97, 0x69, 0x0d, 0xe9, 0x8c, 0xe2, 0xc0, 0x10, 0x57, 0xb8, 0xc8, 0x76, 0x12, 0x91, 0x55, 0xf2, 0x48, 0x69,
    0xd8, 0xbc, 0x2a, 0x02, 0x5b, 0x0f, 0x44, 0xd4, 0x20, 0x31, 0xdb, 0xf4, 0xba, 0x70, 0x26, 0x5d, 0x90, 0x60, 0x9e,
    0xbc, 0x4b, 0x17, 0x09, 0x2f, 0xb4, 0xcb, 0x1e, 0x43, 0x68, 0xc9, 0x07, 0x27, 0xc1, 0xd2, 0x5c, 0xf7, 0xea, 0x21,
    0xb9, 0x68, 0x12, 0x9c, 0x3c, 0x9c, 0xbf, 0x9e, 0xfc, 0x80, 0x5c, 0x9b, 0x63, 0xcd, 0xec, 0x47, 0xaa, 0x25, 0x27,
    0x67, 0xa0, 0x37, 0xf3, 0x00, 0x82, 0x7d, 0x54, 0xd7, 0xa9, 0xf8, 0xe9, 0x2e, 0x13, 0xa3, 0x77, 0xe8, 0x1f, 0x4a};
static const unsigned int DigiCertHighAssuranceEVRootCA_crt_len = 969;

void HttpClient::SetCipherSuite(int cipherSuite) {
  _overrideCipherSuite[0] = cipherSuite;
}

static FILE *debugFd;

static void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
  ((void)level);
  ((void)ctx);
  ((void)file);
  ((void)line);
  ((void)str);

  unsigned long now = 0;
  ReadDateTime(&now);

  fprintf(debugFd, "%d: %s", (int)now, str);
  // fflush(debugFd);
}

bool HttpClient::SslConnect() {
  const char *pers = "HttpClient";
  int ret;

#ifdef MBEDTLS_DEBUG
  mbedtls_debug_set_threshold(_debugLevel);
#endif

  debugFd = fopen("log.txt", "w");

  /* Initialize the RNG and the session data */
  mbedtls_net_init(&_server_fd);
  mbedtls_ssl_init(&_ssl);
  mbedtls_ssl_config_init(&_conf);

  // mbedtls_debug_set_threshold(2);
  // mbedtls_ssl_conf_dbg(&_conf, my_debug, stdout);

  mbedtls_x509_crt_init(&_cacert);
  mbedtls_ctr_drbg_init(&_ctr_drbg);
  mbedtls_entropy_init(&_entropy);

  if ((ret = mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy, (const unsigned char *)pers,
                                   strlen(pers))) != 0) {
    _response.ErrorCode = SSLError;
    _response.ErrorMsg = "mbedtls_ctr_drbg_seed returned " + to_string(ret);
    return false;

  }
  /* Initialize certificates */
  ret = mbedtls_x509_crt_parse(&_cacert, DigiCertHighAssuranceEVRootCA_crt, DigiCertHighAssuranceEVRootCA_crt_len);
  if (ret < 0) {
    _response.ErrorCode = SSLError;
    _response.ErrorMsg = "mbedtls_x509_crt_parse returned " + to_string(ret);
    return false;
  }

  /* Start the connection */

  // mbedtls_net_connect modifies the remote host (strips subdomain), so we work off a copy
  string remoteHost = GetRemoteHost(_uri).c_str();

  if ((ret = mbedtls_net_connect(&_server_fd, remoteHost.c_str(), to_string(GetRemotePort(_uri)).c_str(),
                                 MBEDTLS_NET_PROTO_TCP)) != 0) {
    _response.ErrorCode = ConnectionError;
    _response.ErrorMsg = "mbedtls_net_connect returned " + to_string(ret);
    return false;
  }

  /* Setup stuff */
  if ((ret = mbedtls_ssl_config_defaults(&_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    _response.ErrorCode = SSLError;
    _response.ErrorMsg = "mbedtls_ssl_config_defaults returned " + to_string(ret);
    return false;
  }

  // mbedtls_ssl_conf_ca_chain(&_conf, &_cacert, NULL);
  // mbedtls_ssl_conf_authmode(&_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_authmode(&_conf, MBEDTLS_SSL_VERIFY_NONE);
  mbedtls_ssl_conf_rng(&_conf, mbedtls_ctr_drbg_random, &_ctr_drbg);

#ifdef MBEDTLS_DEBUG
  mbedtls_ssl_conf_dbg(&_conf, ssl_debug, stdout);
#endif

  if (_overrideCipherSuite[0] > 0) {
    mbedtls_ssl_conf_ciphersuites(&_conf, _overrideCipherSuite);
  } else {
    // Use default cipher suites
    mbedtls_ssl_conf_ciphersuites(&_conf, _cipherSuites);
  }

  if ((ret = mbedtls_ssl_setup(&_ssl, &_conf)) != 0) {
    _response.ErrorCode = SSLError;
    _response.ErrorMsg = "mbedtls_ssl_setup returned " + to_string(ret);
    return false;
  }

  // Work off a copy
  string hostname = _uri.Host.c_str();
  if ((ret = mbedtls_ssl_set_hostname(&_ssl, hostname.c_str())) != 0) {
    _response.ErrorCode = SSLError;
    _response.ErrorMsg = "mbedtls_ssl_set_hostname returned " + to_string(ret);
    return false;
  }

  mbedtls_ssl_set_bio(&_ssl, &_server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

  // Connect success
  return true;
}

bool HttpClient::SslHandshake() {
  printf("ssl_handshake start\n");
  int ret = mbedtls_ssl_handshake(&_ssl);
  printf("ssl_handshake end\n");
  fflush(debugFd);

  if (ret == 0) {
    // Handshake complete
    return true;
  } else if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
    if (ret == MBEDTLS_ERR_NET_RECV_FAILED) {
      // Most likely a timeout
      _response.ErrorCode = ConnectionTimeout;
    } else {
      // Something else went wrong
      _response.ErrorCode = SSLError;
    }

    _response.ErrorMsg = "mbedtls_ssl_handshake returned " + to_string(ret);
    return false;
  }

  return false;
}

bool HttpClient::SslVerifyCert() {
  /* Verify the server certificate */
  //	uint32_t flags;
  /* if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 )
  {
  char vrfy_buf[512];
  // mbedtls_printf( " failed\n" );

  mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
  // mbedtls_printf( "%s\n", vrfy_buf );
  return -1;
  } */
  return true;
}

bool HttpClient::SslRequest() {
  if (_cRequest == NULL) {
    _cRequest = _request.c_str();
  }

  while (true) {
    int ret = mbedtls_ssl_write(&_ssl, (const unsigned char *)_cRequest, strlen(_cRequest));

    if (ret > 0) {
      // Request complete
      break;
    }

    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      _response.ErrorCode = ConnectionError;
      _response.ErrorMsg = "mbedtls_ssl_write returned " + to_string(ret);
      return false;
    }
  }

  return true;
}

#ifdef MBEDTLS_SSL_MAX_CONTENT_LEN
#define SSL_RESPONSE_BUFFER_SIZE MBEDTLS_SSL_MAX_CONTENT_LEN
#else
#define SSL_RESPONSE_BUFFER_SIZE 16384
#endif

unsigned char buf[SSL_RESPONSE_BUFFER_SIZE];

bool HttpClient::SslResponse() {
  memset(buf, 0, SSL_RESPONSE_BUFFER_SIZE * sizeof(unsigned char));
  int len;

  while (true) {
    len = sizeof(buf) - 1;
    memset(buf, 0, sizeof(buf));

    int ret = mbedtls_ssl_read(&_ssl, buf, len);
    ret = http_parser_execute(&_parser, &_settings, (const char *)buf, ret);

    if (_response.MessageComplete || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
      // Read response complete, move to next status
      _response.Success = true;
      break;
    }

    if (ret < 0) {
      _response.ErrorCode = ConnectionError;
      _response.ErrorMsg = "http_parser_execute returned " + to_string(ret);
      return false;
    }
  }

  return true;
}

void HttpClient::SslClose() {
  mbedtls_ssl_close_notify(&_ssl);
  mbedtls_net_free(&_server_fd);
  mbedtls_x509_crt_free(&_cacert);
  mbedtls_ssl_free(&_ssl);
  mbedtls_ssl_config_free(&_conf);
  mbedtls_ctr_drbg_free(&_ctr_drbg);
  mbedtls_entropy_free(&_entropy);

  if (!DoRedirect()) {
    if (!_cancel) {
      _onComplete(_response);
    } else {
      _cancel = false;
    }
  }
}
#endif  // SSL_ENABLED

static int on_body_callback(http_parser *parser, const char *at, size_t length) {
  HttpResponse *response = (HttpResponse *)parser->data;
  response->Content.append(at, length);
  return 0;
}

static int on_header_field_callback(http_parser *parser, const char *at, size_t length) {
  HttpResponse *response = (HttpResponse *)parser->data;

  string header = string(at);
  int delim = header.find(":");
  string headerName = header.substr(0, delim);

  response->Headers.insert(pair<string, string>(headerName, ""));
  response->CurrentHeader = headerName;

  return 0;
}

static int on_header_value_callback(http_parser *parser, const char *at, size_t length) {
  HttpResponse *response = (HttpResponse *)parser->data;

  string header = string(at);
  int delim = header.find("\n");
  string headerVal = header.substr(0, delim - 1);

  response->Headers[response->CurrentHeader] = headerVal;

  if (response->CurrentHeader == "Content-Length") {
    response->Content.reserve(stoi(headerVal));
  }

  return 0;
}

static int on_message_complete_callback(http_parser *parser) {
  HttpResponse *response = (HttpResponse *)parser->data;
  response->MessageComplete = true;
  return 0;
}

static int on_status_callback(http_parser *parser, const char *at, size_t length) {
  HttpResponse *response = (HttpResponse *)parser->data;
  response->StatusCode = parser->status_code;
  return 0;
}

#ifdef MBEDTLS_DEBUG
static void ssl_debug(void *ctx, int level, const char *file, int line, const char *str) {
  ((void)level);

  FILE *fp;
  fp = fopen("Mac Volume:log.txt", "a");

  if (fp) {
    fprintf(fp, "%s:%04d: %s", file, line, str);
    fflush(fp);
  }

  fclose(fp);
}
#endif  // MBEDTLS_DEBUG