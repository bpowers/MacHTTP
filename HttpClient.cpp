#include <ctype.h>
#include <string.h>
#include "HttpClient.h"
#include <stdio.h>

extern "C"
{
	#include <MacTCP.h>
	#include <Threads.h>
	#include <mactcp/CvtAddr.h>
	#include <mactcp/TCPHi.h>
}

void ThreadEntry(void* param);

HttpClient::HttpClient()
{ 
	Init("");
}

HttpClient::HttpClient(std::string baseUri)
{
	Init(baseUri);
}

/* Public functions */
void HttpClient::SetProxy(std::string host, int port)
{
	_proxyHost = host;
	_proxyPort = port;
}

void HttpClient::Get(std::string requestUri, std::function<void(HttpResponse)> onComplete)
{
	try
	{
		Uri uri = GetUri(requestUri);

		std::string getRequest =
			"GET " + uri.Path + " HTTP/1.1\r\n" +
			"Host: " + uri.Host + "\r\n" +
			"User-Agent: MacHTTP\r\n\r\n";

		Request(uri, getRequest, onComplete);
	}
	catch (const std::invalid_argument& e)
	{
		HttpResponse response;
		response.ErrorMsg = e.what();
		onComplete(response);
	}
}

void HttpClient::Post(std::string requestUri, std::string content, std::function<void(HttpResponse)> onComplete)
{
	try
	{
		Uri uri = GetUri(requestUri);

		std::string postRequest =
			"POST " + uri.Path + " HTTP/1.1\r\n" +
			"Host: " + uri.Host + "\r\n" +
			"User-Agent: MacHTTP\r\n" +
			"Content-Length: " + std::to_string(content.length()) + "\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n\r\n" +
			content;

		Request(uri, postRequest, onComplete);
	}
	catch (const std::invalid_argument& e)
	{
		HttpResponse response;
		response.ErrorMsg = e.what();
		onComplete(response);
	}
}

void HttpClient::SetDebugLevel(int debugLevel)
{
	_debugLevel = debugLevel;
}

/* Private functions */
void HttpClient::Init(std::string baseUri)
{
	MaxApplZone();

	_baseUri = baseUri;
	_proxyHost = "";
	_proxyPort = 0;
	_debugLevel = 0;
	_status = Idle;
	InitParser();
	
	#ifdef HTTPS_ENABLED
	_overrideCipherSuite[0] = 0;
	#endif
}

void HttpClient::Yield()
{
	YieldToAnyThread();
}

void HttpClient::Connect(Uri uri, unsigned long stream)
{
	HttpResponse response;

	std::string request =
		"CONNECT " + uri.Host + ":443 HTTP/1.1\r\n" +
		"Host: " + uri.Host + ":443\r\n" +
		"User-Agent: MacHTTP\r\n\r\n";

	SendData(
		stream, 
		(Ptr)request.c_str(), 
		(unsigned short)strlen(request.c_str()), 
		false, 
		(GiveTimePtr)Yield,
		&_cancel);
}

Uri HttpClient::GetUri(std::string requestUri)
{
	if (!Uri::IsAbsolute(requestUri))
	{
		requestUri = _baseUri + requestUri;
	}

	return Uri(requestUri);
}

void HttpClient::CancelRequest()
{
	if (_status != Idle)
	{
		_cancel = true;
	}
}

void HttpClient::Request(Uri uri, std::string request, std::function<void(HttpResponse)> onComplete)
{
	_uri = uri;
	_request = request;
	_onComplete = onComplete;
	_cRequest = NULL;
	_cancel = false;
	_response.Reset();
	_status = Waiting;

	// Reset http parser
	memset(&_parser, 0, sizeof(_parser));
	_parser.data = (void*)&_response;
	http_parser_init(&_parser, HTTP_RESPONSE);

	ThreadID id;
	NewThread(
		kCooperativeThread,
		(ThreadEntryTPP)ThreadEntry,
		this,
		0, // Default stack size
		kCreateIfNeeded,
		NULL,
		&id);
}

void ThreadEntry(void* param)
{
	HttpClient* httpClient = (HttpClient*)param;

	httpClient->InitThread();
}

void HttpClient::InitThread()
{
	_status = Running;

	if (_uri.Scheme == "http")
	{
		HttpRequest();
	}
	#ifdef HTTPS_ENABLED
	else
	{
		HttpsRequest();
	}
	#endif
}

HttpClient::RequestStatus HttpClient::GetStatus()
{
	return _status;
}

void HttpClient::ProcessRequests()
{
	YieldToAnyThread();
}

void HttpClient::HttpRequest()
{
	if (Connect())
		if (Request())
			Response();

	NetClose();
}

#ifdef HTTPS_ENABLED
void HttpClient::HttpsRequest()
{
	if (SslConnect())
		if(SslHandshake())
			if (SslRequest())
				SslResponse();

	SslClose();
}
#endif // HTTPS_ENABLED

void HttpClient::InitParser()
{
	// Set parser data
	_parser.data = (void*)&_response;

	// Parser settings
	memset(&_settings, 0, sizeof(_settings));
	_settings.on_status = on_status_callback;
	_settings.on_header_field = on_header_field_callback;
	_settings.on_header_value = on_header_value_callback;
	_settings.on_message_complete = on_message_complete_callback;
	_settings.on_body = on_body_callback;
}

bool HttpClient::DoRedirect()
{
	if (_response.Success && _response.StatusCode == 302 && _response.Headers.count("Location") > 0)
	{
		std::string location = _response.Headers["Location"];

		if (!Uri::IsAbsolute(location))
		{
			location = _uri.Scheme + "://" + _uri.Host + location;
		}

		// Perform 302 redirect
		Get(location, _onComplete);
		return true;
	}

	return false;
}

std::string HttpClient::GetRemoteHost(Uri uri)
{
	if (_proxyHost != "")
	{
		return _proxyHost;
	}
	else
	{
		return uri.Host;
	}
}

int HttpClient::GetRemotePort(Uri uri)
{
	if (_proxyPort > 0)
	{
		return _proxyPort;
	}
	else if(uri.Scheme == "https")
	{
		return 443;
	}

	return 80;
}

bool HttpClient::Connect()
{
	OSErr err;
	unsigned long ipAddress;

	// Open the network driver
	err = InitNetwork();
	if (err != noErr)
	{
		_response.ErrorCode = ConnectionError;
		_response.ErrorMsg = "InitNetwork returned " + std::to_string(err);
		return false;
	}

	// Get remote IP
	err = ConvertStringToAddr((char*)GetRemoteHost(_uri).c_str(), &ipAddress, (GiveTimePtr)Yield);
	if (err != noErr)
	{
		_response.ErrorCode = ConnectionError;
		_response.ErrorMsg = "ConvertStringToAddr returned " + std::to_string(err);
		return false;
	}

	// Open a TCP stream
	err = CreateStream(&_stream, 4096, (GiveTimePtr)Yield, &_cancel);
	if (err != noErr)
	{
		_response.ErrorCode = ConnectionError;
		_response.ErrorMsg = "CreateStream returned " + std::to_string(err);
		return false;
	}

	// Open a connection
	err = OpenConnection(_stream, ipAddress, GetRemotePort(_uri), 0, (GiveTimePtr)Yield, &_cancel);
	if (err == noErr) {
		if (_uri.Scheme == "https" && _proxyHost != "")
		{
			// First issue CONNECT request to open SSl tunnel via proxy
			Connect(_uri, _stream);
		}
	}
	else
	{
		_response.ErrorCode = ConnectionError;
		_response.ErrorMsg = "OpenConnection returned " + std::to_string(err);
		return false;
	}

	// Connect success, move to next status
	return true;
}

bool HttpClient::Request()
{
	// Send the request
	OSErr err = SendData(
		_stream, 
		(Ptr)_request.c_str(), 
		(unsigned short)strlen(_request.c_str()), 
		false, 
		(GiveTimePtr)Yield, 
		&_cancel);

	if (err != noErr)
	{
		_response.ErrorCode = ConnectionError;
		_response.ErrorMsg = "SendData returned " + std::to_string(err);
		return false;
	}

	// Request complete, move to next status
	return true;
}

bool HttpClient::Response()
{
	unsigned char buf[4096];
	unsigned short dataLength;
	int ret;

	while (true)
	{
		dataLength = sizeof(buf);
		memset(buf, 0, sizeof(buf));

		OSErr err = RecvData(
			_stream,
			(Ptr)&buf, &dataLength,
			false,
			(GiveTimePtr)Yield,
			&_cancel);

		ret = http_parser_execute(&_parser, &_settings, (const char*)&buf, dataLength);

		if (_response.MessageComplete || err == connectionClosing)
		{
			// Read response complete
			_response.Success = true;
			break;
		}

		if (ret < 0)
		{
			_response.ErrorCode = ConnectionError;
			_response.ErrorMsg = "http_parser_execute returned " + std::to_string(ret);
			return false;
		}
	}

	return true;
}

void HttpClient::NetClose()
{
	CloseConnection(_stream, (GiveTimePtr)Yield, &_cancel);
	ReleaseStream(_stream, (GiveTimePtr)Yield, &_cancel);

	if (!DoRedirect())
	{
		_status = Idle;
		if (!_cancel)
		{
			_onComplete(_response);
		}
		else
		{
			_cancel = false;
		}
	}
}

#ifdef HTTPS_ENABLED
void HttpClient::SetCipherSuite(int cipherSuite)
{
	_overrideCipherSuite[0] = cipherSuite;
}

bool HttpClient::SslConnect()
{
	const char *pers = "HttpClient";
	int ret;

#ifdef MBEDTLS_DEBUG
	mbedtls_debug_set_threshold(_debugLevel);
#endif

	/* Initialize the RNG and the session data */
	mbedtls_net_init(&_server_fd, (GiveTimePtr)Yield);
	mbedtls_ssl_init(&_ssl);
	mbedtls_ssl_config_init(&_conf);
	mbedtls_x509_crt_init(&_cacert);
	mbedtls_ctr_drbg_init(&_ctr_drbg);
	mbedtls_entropy_init(&_entropy);

	if ((ret = mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy,
		(const unsigned char *)pers,
		strlen(pers))) != 0)
	{
		_response.ErrorCode = SSLError;
		_response.ErrorMsg = "mbedtls_ctr_drbg_seed returned " + std::to_string(ret);
		return false;
	}

	/* Initialize certificates */
	/* ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)mbedtls_test_cas_pem,
	mbedtls_test_cas_pem_len);
	if (ret < 0)
	{
	response.ErrorMsg = "mbedtls_x509_crt_parse returned " + std::to_string(ret);
	return response;
	} */

	/* Start the connection */

	// mbedtls_net_connect modifies the remote host (strips subdomain), so we work off a copy
	std::string remoteHost = GetRemoteHost(_uri).c_str();

	if ((ret = mbedtls_net_connect(&_server_fd, remoteHost.c_str(), std::to_string(GetRemotePort(_uri)).c_str(), MBEDTLS_NET_PROTO_TCP)) != 0)
	{
		_response.ErrorCode = ConnectionError;
		_response.ErrorMsg = "mbedtls_net_connect returned " + std::to_string(ret);
		return false;
	}

	/* Setup stuff */
	if ((ret = mbedtls_ssl_config_defaults(&_conf,
		MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
	{
		_response.ErrorCode = SSLError;
		_response.ErrorMsg = "mbedtls_ssl_config_defaults returned " + std::to_string(ret);
		return false;
	}

	mbedtls_ssl_conf_authmode(&_conf, MBEDTLS_SSL_VERIFY_NONE); // BAD BAD BAD! No remote certificate verification (requires root cert)
															   //mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
	mbedtls_ssl_conf_rng(&_conf, mbedtls_ctr_drbg_random, &_ctr_drbg);

#ifdef MBEDTLS_DEBUG
	mbedtls_ssl_conf_dbg(&_conf, ssl_debug, stdout);
#endif

	if (_overrideCipherSuite[0] > 0)
	{
		mbedtls_ssl_conf_ciphersuites(&_conf, _overrideCipherSuite);
	}
	else
	{
		// Use default cipher suites
		mbedtls_ssl_conf_ciphersuites(&_conf, _cipherSuites);
	}

	if ((ret = mbedtls_ssl_setup(&_ssl, &_conf)) != 0)
	{
		_response.ErrorCode = SSLError;
		_response.ErrorMsg = "mbedtls_ssl_setup returned " + std::to_string(ret);
		return false;
	}

	// Work off a copy
	std::string hostname = _uri.Host.c_str();
	if ((ret = mbedtls_ssl_set_hostname(&_ssl, hostname.c_str())) != 0)
	{
		_response.ErrorCode = SSLError;
		_response.ErrorMsg = "mbedtls_ssl_set_hostname returned " + std::to_string(ret);
		return false;
	}

	mbedtls_ssl_set_bio(&_ssl, &_server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

	// Connect success
	return true;
}

bool HttpClient::SslHandshake()
{
	int ret = mbedtls_ssl_handshake(&_ssl);

	if (ret == 0)
	{
		// Handshake complete
		return true;
	}
	else if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
	{
		if (ret == MBEDTLS_ERR_NET_RECV_FAILED)
		{
			// Most likely a timeout
			_response.ErrorCode = ConnectionTimeout;
		}
		else
		{
			// Something else went wrong
			_response.ErrorCode = SSLError;
		}

		_response.ErrorMsg = "mbedtls_ssl_handshake returned " + std::to_string(ret);
		return false;
	}

	return false;
}

bool HttpClient::SslVerifyCert()
{
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

bool HttpClient::SslRequest()
{
	if (_cRequest == NULL)
	{
		_cRequest = _request.c_str();
	}

	while (true)
	{
		int ret = mbedtls_ssl_write(&_ssl, (const unsigned char*)_cRequest, strlen(_cRequest));

		if (ret > 0)
		{
			// Request complete
			break;
		}

		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			_response.ErrorCode = ConnectionError;
			_response.ErrorMsg = "mbedtls_ssl_write returned " + std::to_string(ret);
			return false;
		}
	}

	return true;
}

bool HttpClient::SslResponse()
{
	unsigned char buf[4096];
	int len;

	while (true)
	{
		len = sizeof(buf);
		memset(buf, 0, sizeof(buf));

		int ret = mbedtls_ssl_read(&_ssl, buf, len);
		ret = http_parser_execute(&_parser, &_settings, (const char*)buf, ret);

		if (_response.MessageComplete ||
			ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
		{
			// Read response complete, move to next status
			_response.Success = true;
			break;
		}

		if (ret < 0)
		{
			_response.ErrorCode = ConnectionError;
			_response.ErrorMsg = "http_parser_execute returned " + std::to_string(ret);
			return false;
		}
	}

	return true;
}

void HttpClient::SslClose()
{
	mbedtls_ssl_close_notify(&_ssl);
	mbedtls_net_free(&_server_fd);
	mbedtls_x509_crt_free(&_cacert);
	mbedtls_ssl_free(&_ssl);
	mbedtls_ssl_config_free(&_conf);
	mbedtls_ctr_drbg_free(&_ctr_drbg);
	mbedtls_entropy_free(&_entropy);

	if (!DoRedirect())
	{
		if (!_cancel)
		{
			_onComplete(_response);
		}
		else
		{
			_cancel = false;
		}
	}
}
#endif // HTTPS_ENABLED

static int on_body_callback(http_parser* parser, const char *at, size_t length) 
{
	HttpResponse* response = (HttpResponse*)parser->data;
	response->Content += std::string(at);
	return 0;
}

static int on_header_field_callback(http_parser* parser, const char *at, size_t length)
{
	HttpResponse* response = (HttpResponse*)parser->data;

	std::string header = std::string(at);
	int delim = header.find(":");
	std::string headerName = header.substr(0, delim);

	response->Headers.insert(std::pair<std::string, std::string>(headerName, ""));
	response->CurrentHeader = headerName;

	return 0;
}

static int on_header_value_callback(http_parser* parser, const char *at, size_t length)
{
	HttpResponse* response = (HttpResponse*)parser->data;

	std::string header = std::string(at);
	int delim = header.find("\n");
	std::string headerVal = header.substr(0, delim - 1);

	response->Headers[response->CurrentHeader] = headerVal;

	return 0;
}

static int on_message_complete_callback(http_parser* parser) 
{
	HttpResponse* response = (HttpResponse*)parser->data;
	response->MessageComplete = true;
	return 0;
}

static int on_status_callback(http_parser* parser, const char *at, size_t length)
{
	HttpResponse* response = (HttpResponse*)parser->data;
	response->StatusCode = parser->status_code;
	return 0;
}

#ifdef MBEDTLS_DEBUG
static void ssl_debug(void *ctx, int level,
	const char *file, int line,
	const char *str)
{
	((void)level);

	FILE *fp;
	fp = fopen("Mac Volume:log.txt", "a");

	if (fp)
	{
		fprintf(fp, "%s:%04d: %s", file, line, str);
		fflush(fp);
	}

	fclose(fp);
}
#endif // MBEDTLS_DEBUG