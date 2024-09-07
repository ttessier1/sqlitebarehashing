#include "pch.h"
#include <stdlib.h>
#include "util.h"
#include "digestsize.h"
#include "algorithms.h"

#include <cstdarg>
#include <sstream>

#ifdef __cplusplus
extern "C" {
#endif

const char* hexChars = "0123456789ABCDEF";

unsigned int strlength( const unsigned char* string)
{
    // Cap to 32 bits only
	unsigned int length = STRLENGTH_INVALID;
	if (string != NULL)
	{
        length = 0;// Initialize to non -1 value
		while ((*string)!='\0')
		{
			length++;
            string++;
		}
	}
	return length;
}

void* AllocCryptoResult(size_t size)
{
	return malloc(size);
}

void FreeCryptoResult(const void* object)
{
	if (object != NULL)
	{
		free((void*)object);
	}
}

const char* ToHex(const char* value, unsigned int length, unsigned int algorithms)
{
    char* hexValue = NULL;
    char theChar = 0;
    unsigned int maxLength = 0;
    unsigned int index = 0;
    unsigned int valueIndex = 0;
    if (value)
    {
        switch (algorithms)
        {
#if defined ( __MD2__ ) || defined(__ALL__)
        case algo_md2:
//        case algo_hmac_md2:
            if (length != DIGESTSIZE::DigestSizeMD2)
            {
                DebugFormat("MD2 Algorithm Length does not match actual length: [%i] [%i]\r\n,", length, DIGESTSIZE::DigestSizeMD2);
                return NULL;
            }
            maxLength = DIGESTSIZE::DigestSizeMD2 * 2;
            break;
#endif
#if defined ( __MD4__ ) || defined(__ALL__)
        case algo_md4:
//        case algo_hmac_md4:
            if (length != DIGESTSIZE::DigestSizeMD4)
            {
                DebugFormat("MD4 Algorithm Length does not match actual length: [%i] [%i]\r\n,", length, DIGESTSIZE::DigestSizeMD4);
                return NULL;
            }
            maxLength = DIGESTSIZE::DigestSizeMD4 * 2;
            break;
#endif
#if defined ( __MD5__ ) || defined(__ALL__)
        case algo_md5:
//        case algo_hmac_md5:
            if (length != DIGESTSIZE::DigestSizeMD5)
            {
                DebugFormat("MD5 Algorithm Length does not match actual length: [%i] [%i]\r\n,", length, DIGESTSIZE::DigestSizeMD5);
                return NULL;
            }
            maxLength = DIGESTSIZE::DigestSizeMD5 * 2;
            break;
#endif
#if defined ( __SHA1__ ) || defined(__ALL__)
        case algo_sha1:
//        case algo_hmac_sha1:
            if (length != DIGESTSIZE::DigestSizeSHA1)
            {
                DebugFormat("SHA1 Algorithm Length does not match actual length: [%i] [%i]\r\n,", length, DIGESTSIZE::DigestSizeSHA1);
                return NULL;
            }
            maxLength = DIGESTSIZE::DigestSizeSHA1 * 2;
            break;
#endif
#if defined ( __SHA224__ ) || defined(__ALL__)
        case algo_sha224:
//        case algo_hmac_sha224:
            if (length != DIGESTSIZE::DigestSizeSHA224)
            {
                DebugFormat("SHA224 Algorithm Length does not match actual length: [%i] [%i]\r\n,", length, DIGESTSIZE::DigestSizeSHA224);
                return NULL;
            }
            maxLength = DIGESTSIZE::DigestSizeSHA224 * 2;
            break;
#endif
#if defined ( __SHA256__ ) || defined(__ALL__)
        case algo_sha256:
//        case algo_hmac_sha256:
            if (length != DIGESTSIZE::DigestSizeSHA256)
            {
                DebugFormat("SHA256 Algorithm Length does not match actual length: [%i] [%i]\r\n,", length, DIGESTSIZE::DigestSizeSHA256);
                return NULL;
            }
            maxLength = DIGESTSIZE::DigestSizeSHA256 * 2;
            break;
#endif
#if defined ( __SHA384__ ) || defined(__ALL__)
        case algo_sha384:
//        case algo_hmac_sha384:
            if (length != DIGESTSIZE::DigestSizeSHA384)
            {
                DebugFormat("SHA384 Algorithm Length does not match actual length: [%i] [%i]\r\n,", length, DIGESTSIZE::DigestSizeSHA384);
                return NULL;
            }
            maxLength = DIGESTSIZE::DigestSizeSHA384 * 2;
            break;
#endif
#if defined ( __SHA512__ ) || defined(__ALL__)
        case algo_sha512:
//        case algo_hmac_sha512:
            if (length != DIGESTSIZE::DigestSizeSHA512)
            {
                DebugFormat("SHA512 Algorithm Length does not match actual length: [%i] [%i]\r\n,", length, DIGESTSIZE::DigestSizeSHA512);
                return NULL;
            }
            maxLength = DIGESTSIZE::DigestSizeSHA512 * 2;
            break;
    #endif
        default:
            return NULL;
        }
        hexValue = (char*)AllocCryptoResult((length * 2) + 1);
        if (hexValue)
        {
            for (index = 0; index < length; index++)
            {
                theChar = (((value[index] & 0xF0) >> 4) & 0x0F);
                hexValue[valueIndex] = hexChars[theChar];
                if (valueIndex > (maxLength))
                {

                    break;
                }
                DebugFormat("Index:%i ValueIndex:%i Initial: %x Char: %i Value: %i\r\n", index, valueIndex, value[index], theChar, hexValue[valueIndex]);
                valueIndex++;
                theChar = ((value[index]) & 0x0F);
                hexValue[valueIndex] = hexChars[theChar];
                if (valueIndex > (maxLength))
                {

                    break;
                }
                DebugFormat("Index:%i ValueIndex:%i Initial: %x Char: %i Value: %i\r\n", index, valueIndex, value[index], theChar, hexValue[valueIndex]);
                valueIndex++;
            }
            hexValue[maxLength] = '\0';
            if (SelfCheckToHex(hexValue, maxLength, algorithms) != 1)
            {
                DebugFormat("hexValue Failed to SelfCheck\r\n");
                return NULL;
            }
        }
        else
        {
            DebugFormat("hexValue Failed to allocated\r\n");
            return NULL;
        }
    }
    else
    {
        DebugFormat("Value is NULL\r\n");
        return NULL;
    }
    return hexValue;
}


unsigned int SelfCheckToHex(const char* value, unsigned int length, unsigned int algorithm)
{
    unsigned int index = 0;
    unsigned int maxLength = 0;
    if (value)
    {
        switch (algorithm)
        {
#if defined ( __MD2__ ) || defined(__ALL__)
        case algo_md2:
//        case algo_hmac_md2:
            if (length != DIGESTSIZE::DigestSizeMD2 * 2)
            {
                DebugFormat("SelfCheck MD2 Algorithm Length does not match actual length: [%i] [%i]\r\n", length, DIGESTSIZE::DigestSizeMD2 * 2);
                return 0;
            }
            maxLength = DIGESTSIZE::DigestSizeMD2 * 2;
            break;
#endif
#if defined ( __MD4__ ) || defined(__ALL__)
        case algo_md4:
//        case algo_hmac_md4:
            if (length != DIGESTSIZE::DigestSizeMD4 * 2)
            {
                DebugFormat("SelfCheck MD4 Algorithm Length does not match actual length: [%i] [%i]\r\n", length, DIGESTSIZE::DigestSizeMD4 * 2);
                return 0;
            }
            maxLength = DIGESTSIZE::DigestSizeMD4 * 2;
            break;
#endif
#if defined ( __MD5__ ) || defined(__ALL__)
        case algo_md5:
//        case algo_hmac_md5:
            if (length != DIGESTSIZE::DigestSizeMD5 * 2)
            {
                DebugFormat("SelfCheck MD5 Algorithm Length does not match actual length: [%i] [%i]\r\n", length, DIGESTSIZE::DigestSizeMD5 * 2);
                return 0;
            }
            maxLength = DIGESTSIZE::DigestSizeMD5 * 2;
            break;
#endif
#if defined ( __SHA1__ ) || defined(__ALL__)
        case algo_sha1:
//        case algo_hmac_sha1:
            if (length != DIGESTSIZE::DigestSizeSHA1 * 2)
            {
                DebugFormat("SelfCheck SHA1 Algorithm Length does not match actual length: [%i] [%i]\r\n", length, DIGESTSIZE::DigestSizeSHA1 * 2);
                return 0;
            }
            maxLength = DIGESTSIZE::DigestSizeSHA1 * 2;
            break;
#endif
#if defined ( __SHA224__ ) || defined(__ALL__)
        case algo_sha224:
//        case algo_hmac_sha224:
            if (length != DIGESTSIZE::DigestSizeSHA224 * 2)
            {
                DebugFormat("SelfCheck SHA224 Algorithm Length does not match actual length: [%i] [%i]\r\n", length, DIGESTSIZE::DigestSizeSHA224 * 2);
                return 0;
            }
            maxLength = DIGESTSIZE::DigestSizeSHA224 * 2;
            break;
#endif
#if defined ( __SHA256__ ) || defined(__ALL__)
        case algo_sha256:
//        case algo_hmac_sha256:
            if (length != DIGESTSIZE::DigestSizeSHA256 * 2)
            {
                DebugFormat("SelfCheck SHA256 Algorithm Length does not match actual length: [%i] [%i]\r\n", length, DIGESTSIZE::DigestSizeSHA256 * 2);
                return 0;
            }
            maxLength = DIGESTSIZE::DigestSizeSHA256 * 2;
            break;
#endif
#if defined ( __SHA384__ ) || defined(__ALL__)
        case algo_sha384:
//        case algo_hmac_sha384:
            if (length != DIGESTSIZE::DigestSizeSHA384 * 2)
            {
                DebugFormat("SelfCheck SHA384 Algorithm Length does not match actual length: [%i] [%i]\r\n", length, DIGESTSIZE::DigestSizeSHA384 * 2);
                return 0;
            }
            maxLength = DIGESTSIZE::DigestSizeSHA384 * 2;
            break;
#endif
#if defined ( __SHA512__ ) || defined(__ALL__)
        case algo_sha512:
//        case algo_hmac_sha512:
            if (length != DIGESTSIZE::DigestSizeSHA512 * 2)
            {
                DebugFormat("SelfCheck SHA512 Algorithm Length does not match actual length: [%i] [%i]\r\n", length, DIGESTSIZE::DigestSizeSHA512 * 2);
                return 0;
            }
            maxLength = DIGESTSIZE::DigestSizeSHA512 * 2;
            break;
#endif
        default:
            DebugFormat("Invalid Algorithm: [%i] [%i]\r\n", algorithm);
            return 0;
        }
        for (index = 0; index < maxLength; index++)
        {
            if (
                (value[index] >= '0' && value[index] <= '9') ||
                (value[index] >= 'a' && value[index] <= 'f') ||
                (value[index] >= 'A' && value[index] <= 'F')
                )
            {
                continue;
            }
            else
            {
                DebugFormat("Index: %i Value: %c\r\n", index, value);
                return 0;
            }
        }
        return 1;
    }
    else
    {
        DebugFormat("Value is NULL\r\n");
    }
    return 0;
}
#ifdef WIN32

void DebugFormat(const char* format, ...)
{
    std::va_list args;
    std::stringstream outputStream;
    va_start(args, format);

    for (const char* p = format; *p != '\0'; ++p)
    {
        switch (*p)
        {
        case '%':
            switch (*++p) // read format symbol
            {
            case 'i':
            case 'd':
                outputStream << va_arg(args, int);
                continue;
            case 'f':
                outputStream << va_arg(args, double);
                continue;
            case 's':
                outputStream << va_arg(args, const char*);
                continue;
            case 'c':
                outputStream << static_cast<char>(va_arg(args, int));
                continue;
            case '%':
                outputStream << '%';
                continue;
            case 'x':
                outputStream << std::hex << va_arg(args, int);
                continue;
            case 'o':
                outputStream << std::oct << va_arg(args, int);
                continue;
                /* ...more cases... */
            }
            break; // format error...
        case '\n':
            outputStream << '\n';
            continue;
        case '\t':
            outputStream << '\t';
            continue;
        case ' ':
            outputStream << ' ';
        default:
            outputStream << *p;
        }
    }
    va_end(args);
    OutputDebugStringA(outputStream.str().c_str());
}
#else

#endif

#ifdef __cplusplus
}
#endif