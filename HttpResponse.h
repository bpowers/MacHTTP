#ifndef __HTTP_RESPONSE__
#define __HTTP_RESPONSE__

#include <string>
#include <map>

enum HttpResponseErrorCode
{
	ConnectionError,
	ConnectionTimeout,
	SSLError
};

#pragma once
class HttpResponse
{
public:
	HttpResponse();
	void Reset();
	bool Success;
	bool MessageComplete;
	unsigned int StatusCode;
	HttpResponseErrorCode ErrorCode;
	std::string ErrorMsg;
	std::string Content;
	std::map<std::string, std::string> Headers;
	std::string CurrentHeader;
};

#endif