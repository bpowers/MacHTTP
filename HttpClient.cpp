#include <ctype.h>
#include <string.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/debug.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/certs.h>
#include "HttpClient.h"

extern "C" 
{
	#include <MacTCP.h>
	#include <mactcp/TCPHi.h>
}

HttpClient::HttpClient(std::string baseUri)
{
	_host = GetHost(baseUri);
	_https = IsHttps(baseUri);
}

/* Public functions */
HttpResponse HttpClient::Get(std::string requestUri)
{
	std::string getRequest =
		"GET " + requestUri + " HTTP/1.1\r\n" +
		"Host: " + _host + "\r\n" +
		"Connection: close\r\n\r\n";

	return Request(getRequest);
}

/* Private functions */
HttpResponse HttpClient::Request(std::string request)
{
	_messageComplete = false;
	_response.Content = "";
	_response.ErrorMsg = "";

	if (_https)
	{
		return HttpsRequest(request);
	}
	else
	{
		return HttpRequest(request);
	}
}

HttpResponse HttpClient::HttpRequest(std::string request)
{
	OSErr err;
	unsigned char buf[8192];
	unsigned short dataLength;
	int ret;
		return _response;
		return _response;
		return _response;
			parser.data = (void*)this;

			// Parser settings
			memset(&settings, 0, sizeof(settings));
			settings.on_message_complete = on_message_complete_callback;
			settings.on_body = on_body_callback;

			http_parser_init(&parser, HTTP_RESPONSE);
			{
				dataLength = sizeof(buf) - 1;
				err = RecvData(stream, (Ptr)&buf, &dataLength, false);

				if (ret < 0)
				{
					_response.ErrorMsg = "http_parser_execute returned " + std::to_string(ret);
					return _response;
				}
			} while (!_messageComplete);
			return _response;
		return _response;
}

HttpResponse HttpClient::HttpsRequest(std::string request)
{
	int ret, len;
	mbedtls_net_context server_fd;
	uint32_t flags;
	unsigned char buf[8192];
	const char *pers = "HttpClient";
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cacert;
	struct http_parser parser;
	http_parser_settings settings;
	size_t parsed;

	_response.Content = "";

	/* Initialize the RNG and the session data */
	mbedtls_net_init(&server_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&cacert);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		(const unsigned char *)pers,
		strlen(pers))) != 0)
	{
		_response.ErrorMsg = "mbedtls_ctr_drbg_seed returned " + std::to_string(ret);
		return _response;
	}

	/* Initialize certificates */
	ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)mbedtls_test_cas_pem,
		mbedtls_test_cas_pem_len);
	if (ret < 0)
	{
		_response.ErrorMsg = "mbedtls_x509_crt_parse returned " + std::to_string(ret);
		return _response;
	}

	/* Start the connection */
	if ((ret = mbedtls_net_connect(&server_fd, _host.c_str(), "443", MBEDTLS_NET_PROTO_TCP)) != 0)
	{
		_response.ErrorMsg = "mbedtls_net_connect returned " + std::to_string(ret);
		return _response;
	}

	/* Setup stuff */
	if ((ret = mbedtls_ssl_config_defaults(&conf,
		MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
	{
		_response.ErrorMsg = "mbedtls_ssl_config_defaults returned " + std::to_string(ret);
		return _response;
	}

	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE); // BAD BAD BAD! No remote certificate verification (requires root cert)
	//mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
	{
		_response.ErrorMsg = "mbedtls_ssl_setup returned " + std::to_string(ret);
		return _response;
	}

	if ((ret = mbedtls_ssl_set_hostname(&ssl, _host.c_str())) != 0)
	{
		_response.ErrorMsg = "mbedtls_ssl_set_hostname returned " + std::to_string(ret);
		return _response;
	}

	mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

	/* Handshake */
	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
	{
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			_response.ErrorMsg = "mbedtls_ssl_handshake returned " + std::to_string(ret);
			return _response;
		}
	}

	/* Verify the server certificate */
	/* if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 )
	{
	    char vrfy_buf[512];
	    // mbedtls_printf( " failed\n" );

	    mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
	    // mbedtls_printf( "%s\n", vrfy_buf );
		return -1;
	} */

	/* Write the GET request */
	len = sprintf((char *)buf, request.c_str());

	while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0)
	{
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			_response.ErrorMsg = "mbedtls_ssl_write returned " + std::to_string(ret);
			return _response;
		}
	}

	len = ret;
	
	// Set parser data
	parser.data = (void*)this;

	// Parser settings
	memset(&settings, 0, sizeof(settings));
	settings.on_message_complete = on_message_complete_callback;
	settings.on_body = on_body_callback;

	http_parser_init(&parser, HTTP_RESPONSE);

	/* Read the HTTP response */
	do
	{
		len = sizeof(buf) - 1;
		memset(buf, 0, sizeof(buf));
		ret = mbedtls_ssl_read(&ssl, buf, len);
		ret = http_parser_execute(&parser, &settings, (const char*)buf, ret);

		if (ret < 0)
		{
			_response.ErrorMsg = "http_parser_execute returned " + std::to_string(ret);
			return _response;
		}
	}
	while(!_messageComplete);

	mbedtls_ssl_close_notify(&ssl);
	mbedtls_net_free(&server_fd);
	mbedtls_x509_crt_free(&cacert);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	_response.Success = true;

	return _response;
}

static int on_body_callback(http_parser* parser, const char *at, size_t length) 
{
	return ((HttpClient*)parser->data)->OnBody(parser, at, length);
}

static int on_message_complete_callback(http_parser* parser) 
{
	return ((HttpClient*)parser->data)->OnMessageComplete(parser);
}

int HttpClient::OnBody(http_parser* parser, const char *at, size_t length) 
{
	_response.Content += std::string(at);
    return 0;
}

int HttpClient::OnMessageComplete(http_parser* p)
{
	_messageComplete = true;
	return 0;
}

bool HttpClient::IsHttps(std::string requestUri)
{
	return requestUri.find("https") == 0;
}

std::string HttpClient::GetHost(std::string requestUri)
{
	char* serverName = strtok((char *)requestUri.c_str(), "/");
	serverName = strtok(NULL, "/");
	
	return std::string(serverName);
}