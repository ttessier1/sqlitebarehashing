#include "pch.h"
#include "crypto_hashing.h"

#if defined ( __MD2__ ) || defined(__ALL__)
#include "md2.h"
#endif

#if defined ( __MD4__ ) || defined(__ALL__)
#include "md4.h"
#endif

#if defined ( __MD5__ ) || defined(__ALL__)
#include "md5.h"
#endif


#if (defined(__MD2__) ||  defined (__ALL__))&& defined(__USE_BLOB__)
struct md2BlobContext
{
    BOOL initialized;
    MD2_CTX blobContext;
};
#endif


#if (defined(__MD4__) ||  defined (__ALL__))&& defined(__USE_BLOB__)
struct md4BlobContext
{
    BOOL initialized;
    MD4_CTX blobContext;
};
#endif

#if (defined(__MD5__) ||  defined (__ALL__))&& defined(__USE_BLOB__)
struct md5BlobContext
{
    BOOL initialized;
    MD5_CTX blobContext;
};
#endif

#if (defined(__SHA1__) ||  defined (__ALL__))&& defined(__USE_BLOB__)
struct shaBlobContext
{
    BOOL initialized;
    USHAContext blobContext;
};
#endif


#ifdef __cplusplus
extern "C" {
#endif

#if defined ( __MD2__ ) || defined(__ALL__)

    static void MD2String(unsigned char** digest, unsigned int * digest_length, const unsigned char* string)
    {
        MD2_CTX context;
        unsigned int len = strlength(string);
        if (len != STRLENGTH_INVALID && string != NULL && digest_length != NULL && digest != NULL && *digest == NULL )
        {

            MD2Init(&context);
            MD2Update(&context, (unsigned char*)string, len);
            *digest_length = DIGESTSIZE::DigestSizeMD2;
            *digest = (unsigned char *)AllocCryptoResult(DIGESTSIZE::DigestSizeMD2);
            if ((*digest) != NULL)
            {
                MD2Final(*digest, &context);
            }
        }

    }

    const char* DoMd2(const char* message)
    {
        char* lpBuffer = NULL;
        unsigned int length = 0;
        const char* result;
        if (message)
        {
            DebugFormat("Message passed in is:");
            DebugFormat(message);
            DebugFormat("\r\n");

            MD2String((unsigned char **) & lpBuffer, &length, ( const unsigned char *)message);
            DebugFormat("Processed Message to Buffer Length: %i\r\n", DIGESTSIZE::DigestSizeMD2);
            result = ToHex(lpBuffer, DIGESTSIZE::DigestSizeMD2, algo_md2);
            if (result != NULL)
            {
                DebugFormat("Processed ToHex\r\n");
                if (strlength((const unsigned char *)result) != (DIGESTSIZE::DigestSizeMD2 * 2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength((const unsigned char*)result), (DIGESTSIZE::DigestSizeMD2 * 2), result);
                    return NULL;
                }
            }
            else
            {
                DebugFormat("Failed to convert to hex\r\n");
            }
            FreeCryptoResult(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            DebugFormat("Message passed in is NULL\r\n");
        }
        return NULL;
    }

    Md2BlobContextPtr Md2Initialize()
    {
        Md2BlobContextPtr contextPtr = (Md2BlobContextPtr)AllocCryptoResult(sizeof(Md2BlobContext));
        if (contextPtr != NULL)
        {
            MD2Init(&contextPtr->blobContext);
            contextPtr->initialized = TRUE;
        }
        return contextPtr;
    }

    void Md2Update(Md2BlobContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->initialized && message != NULL && length > 0)
        {
            MD2Update(&context->blobContext, (unsigned char*)message, length);
        }
    }
    
    const char* Md2Finalize(Md2BlobContextPtr context)
    {
        char* digestBuffer = NULL;
        const char* result = NULL;
        if (context != NULL && context->initialized )
        {
            digestBuffer = (char*)AllocCryptoResult(DIGESTSIZE::DigestSizeMD2);
            if (digestBuffer != NULL)
            {
                MD2Final((unsigned char *)digestBuffer, &context->blobContext);
                result = ToHex(digestBuffer, DIGESTSIZE::DigestSizeMD2, algo_md2);
                if (result != NULL)
                {
                    if (strlength((const unsigned char*)result) != (DIGESTSIZE::DigestSizeMD2 * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength((const unsigned char*)result), (DIGESTSIZE::DigestSizeMD2 * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugFormat("Failed to convert to hex\r\n");
                }
                FreeCryptoResult(digestBuffer);
                digestBuffer = NULL;
            }
        }
        return result;
    }


#endif
#if defined ( __MD4__ ) || defined(__ALL__)
    static void MD4String(unsigned char** digest, unsigned int* digest_length, const unsigned char* string)
    {
        MD4_CTX context;
        unsigned int len = strlength(string);
        if (len != STRLENGTH_INVALID && string != NULL && digest_length != NULL && digest != NULL && *digest == NULL)
        {

            MD4Init(&context);
            MD4Update(&context, (unsigned char*)string, len);
            *digest_length = DIGESTSIZE::DigestSizeMD4;
            *digest = (unsigned char*)AllocCryptoResult(DIGESTSIZE::DigestSizeMD4);
            if ((*digest) != NULL)
            {
                MD4Final(*digest, &context);
            }
        }

    }
    const char* DoMd4(const char* message)
    {
        char* lpBuffer = NULL;
        unsigned int length = 0;
        const char* result;
        if (message)
        {
            DebugFormat("Message passed in is:");
            DebugFormat(message);
            DebugFormat("\r\n");

            MD4String((unsigned char**)&lpBuffer, &length, (const unsigned char*)message);
            DebugFormat("Processed Message to Buffer Length: %i\r\n", DIGESTSIZE::DigestSizeMD4);
            result = ToHex(lpBuffer, DIGESTSIZE::DigestSizeMD4, algo_md4);
            if (result != NULL)
            {
                DebugFormat("Processed ToHex\r\n");
                if (strlength((const unsigned char*)result) != (DIGESTSIZE::DigestSizeMD4 * 2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength((const unsigned char*)result), (DIGESTSIZE::DigestSizeMD2 * 2), result);
                    return NULL;
                }
            }
            else
            {
                DebugFormat("Failed to convert to hex\r\n");
            }
            FreeCryptoResult(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            DebugFormat("Message passed in is NULL\r\n");
        }
        return NULL;
    }

    Md4BlobContextPtr Md4Initialize()
    {
        Md4BlobContextPtr contextPtr = (Md4BlobContextPtr)AllocCryptoResult(sizeof(Md4BlobContext));
        if (contextPtr != NULL)
        {
            MD4Init(&contextPtr->blobContext);
            contextPtr->initialized = TRUE;
        }
        return contextPtr;
    }

    void Md4Update(Md4BlobContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->initialized && message != NULL && length > 0)
        {
            MD4Update(&context->blobContext, (unsigned char*)message, length);
        }
    }

    const char* Md4Finalize(Md4BlobContextPtr context)
    {
        char* digestBuffer = NULL;
        const char* result = NULL;
        if (context != NULL && context->initialized)
        {
            digestBuffer = (char*)AllocCryptoResult(DIGESTSIZE::DigestSizeMD4);
            if (digestBuffer != NULL)
            {
                MD4Final((unsigned char*)digestBuffer, &context->blobContext);
                result = ToHex(digestBuffer, DIGESTSIZE::DigestSizeMD4, algo_md4);
                if (result != NULL)
                {
                    if (strlength((const unsigned char*)result) != (DIGESTSIZE::DigestSizeMD4 * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength((const unsigned char*)result), (DIGESTSIZE::DigestSizeMD4 * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugFormat("Failed to convert to hex\r\n");
                }
                FreeCryptoResult(digestBuffer);
                digestBuffer = NULL;
            }
        }
        return result;
    }

#endif

#if defined ( __MD5__ ) || defined(__ALL__)
    static void MD5String(unsigned char** digest, unsigned int* digest_length, const unsigned char* string)
    {
        MD5_CTX context;
        unsigned int len = strlength(string);
        if (len != STRLENGTH_INVALID && string != NULL && digest_length != NULL && digest != NULL && *digest == NULL)
        {

            MD5Init(&context);
            MD5Update(&context, (unsigned char*)string, len);
            *digest_length = DIGESTSIZE::DigestSizeMD5;
            *digest = (unsigned char*)AllocCryptoResult(DIGESTSIZE::DigestSizeMD5);
            if ((*digest) != NULL)
            {
                MD5Final(*digest, &context);
            }
        }

    }
    const char* DoMd5(const char* message)
    {
        char* lpBuffer = NULL;
        unsigned int length = 0;
        const char* result;
        if (message)
        {
            DebugFormat("Message passed in is:");
            DebugFormat(message);
            DebugFormat("\r\n");

            MD5String((unsigned char**)&lpBuffer, &length, (const unsigned char*)message);
            DebugFormat("Processed Message to Buffer Length: %i\r\n", DIGESTSIZE::DigestSizeMD5);
            result = ToHex(lpBuffer, DIGESTSIZE::DigestSizeMD5, algo_md5);
            if (result != NULL)
            {
                DebugFormat("Processed ToHex\r\n");
                if (strlength((const unsigned char*)result) != (DIGESTSIZE::DigestSizeMD5 * 2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength((const unsigned char*)result), (DIGESTSIZE::DigestSizeMD5 * 2), result);
                    return NULL;
                }
            }
            else
            {
                DebugFormat("Failed to convert to hex\r\n");
            }
            FreeCryptoResult(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            DebugFormat("Message passed in is NULL\r\n");
        }
        return NULL;
    }
    Md5BlobContextPtr Md5Initialize()
    {
        Md5BlobContextPtr contextPtr = (Md5BlobContextPtr)AllocCryptoResult(sizeof(Md5BlobContext));
        if (contextPtr != NULL)
        {
            MD5Init(&contextPtr->blobContext);
            contextPtr->initialized = TRUE;
        }
        return contextPtr;
    }
    void Md5Update(Md5BlobContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->initialized && message != NULL && length > 0)
        {
            MD5Update(&context->blobContext, (unsigned char*)message, length);
        }
    }
    const char* Md5Finalize(Md5BlobContextPtr context)
    {
        char* digestBuffer = NULL;
        const char* result = NULL;
        if (context != NULL && context->initialized)
        {
            digestBuffer = (char*)AllocCryptoResult(DIGESTSIZE::DigestSizeMD5);
            if (digestBuffer != NULL)
            {
                MD5Final((unsigned char*)digestBuffer, &context->blobContext);
                result = ToHex(digestBuffer, DIGESTSIZE::DigestSizeMD5, algo_md5);
                if (result != NULL)
                {
                    if (strlength((const unsigned char*)result) != (DIGESTSIZE::DigestSizeMD5 * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength((const unsigned char*)result), (DIGESTSIZE::DigestSizeMD5 * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugFormat("Failed to convert to hex\r\n");
                }
                FreeCryptoResult(digestBuffer);
                digestBuffer = NULL;
            }
        }
        return result;
    }
#endif

#if defined ( __SHA1__ ) || defined(__ALL__)
    static void SHA1String(unsigned char** digest, unsigned int* digest_length, const unsigned char* string)
    {
        USHAContext context;
        unsigned int len = strlength(string);
        if (len != STRLENGTH_INVALID && string != NULL && digest_length != NULL && digest != NULL && *digest == NULL)
        {
            USHAReset(&context, SHAversion::VersionSHA1);
            USHAInput(&context, (unsigned char*)string, len);
            *digest_length = DIGESTSIZE::DigestSizeUSHA;
            *digest = (unsigned char*)AllocCryptoResult( DIGESTSIZE::DigestSizeUSHA); // DIGESTSIZE::DigestSizeSHA1);
            if ((*digest) != NULL)
            {
                USHAResult(&context,*digest );
            }
        }

    }
    
    const char* DoSha1(const char* message)
    {
        char* lpBuffer = NULL;
        unsigned int length = 0;
        const char* result;
        if (message)
        {
            DebugFormat("Message passed in is:");
            DebugFormat(message);
            DebugFormat("\r\n");

            SHA1String((unsigned char**)&lpBuffer, &length, (const unsigned char*)message);
            DebugFormat("Processed Message to Buffer Length: %i\r\n", DIGESTSIZE::DigestSizeUSHA);
            result = ToHex(lpBuffer, DIGESTSIZE::DigestSizeSHA1, algo_sha1);
            if (result != NULL)
            {
                DebugFormat("Processed ToHex\r\n");
                if (strlength((const unsigned char*)result) != (DIGESTSIZE::DigestSizeSHA1 * 2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength((const unsigned char*)result), (DIGESTSIZE::DigestSizeSHA1 * 2), result);
                    return NULL;
                }
            }
            else
            {
                DebugFormat("Failed to convert to hex\r\n");
            }
            FreeCryptoResult(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            DebugFormat("Message passed in is NULL\r\n");
        }
        return NULL;
    }

    ShaBlobContextPtr Sha1Initialize()
    {
        ShaBlobContextPtr contextPtr = (ShaBlobContextPtr)AllocCryptoResult(sizeof(ShaBlobContext));
        if (contextPtr != NULL)
        {
            USHAReset(&contextPtr->blobContext, SHAversion::VersionSHA1);
            contextPtr->initialized = TRUE;
        }
        return contextPtr;
    }

    void Sha1Update(ShaBlobContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->initialized && message != NULL && length > 0)
        {
            USHAInput(&context->blobContext, (unsigned char*)message, length);
        }
    }

    const char* Sha1Finalize(ShaBlobContextPtr context)
    {
        char* digestBuffer = NULL;
        const char* result = NULL;
        if (context != NULL && context->initialized)
        {
            digestBuffer = (char*)AllocCryptoResult(DIGESTSIZE::DigestSizeUSHA);
            if (digestBuffer != NULL)
            {
                USHAResult(&context->blobContext,(unsigned char*)digestBuffer);
                result = ToHex(digestBuffer, DIGESTSIZE::DigestSizeSHA1, algo_sha1);
                if (result != NULL)
                {
                    if (strlength((const unsigned char*)result) != (DIGESTSIZE::DigestSizeSHA1 * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength((const unsigned char*)result), (DIGESTSIZE::DigestSizeSHA1 * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugFormat("Failed to convert to hex\r\n");
                }
                FreeCryptoResult(digestBuffer);
                digestBuffer = NULL;
            }
        }
        return result;
    }
#endif

    

#if defined ( __SHA224__ ) || defined(__ALL__)

    static void SHA224String(unsigned char** digest, unsigned int* digest_length, const unsigned char* string)
    {
        USHAContext context;
        unsigned int len = strlength(string);
        if (len != STRLENGTH_INVALID && string != NULL && digest_length != NULL && digest != NULL && *digest == NULL)
        {
            USHAReset(&context, SHAversion::VersionSHA224);
            USHAInput(&context, (unsigned char*)string, len);
            *digest_length = DIGESTSIZE::DigestSizeUSHA;
            *digest = (unsigned char*)AllocCryptoResult(DIGESTSIZE::DigestSizeUSHA); // DIGESTSIZE::DigestSizeSHA1);
            if ((*digest) != NULL)
            {
                USHAResult(&context, *digest);
            }
        }
    }

    const char* DoSha224(const char* message)
    {
        char* lpBuffer = NULL;
        unsigned int length = 0;
        const char* result;
        if (message)
        {
            DebugFormat("Message passed in is:");
            DebugFormat(message);
            DebugFormat("\r\n");

            SHA224String((unsigned char**)&lpBuffer, &length, (const unsigned char*)message);
            DebugFormat("Processed Message to Buffer Length: %i\r\n", DIGESTSIZE::DigestSizeUSHA);
            result = ToHex(lpBuffer, DIGESTSIZE::DigestSizeSHA224, algo_sha224);
            if (result != NULL)
            {
                DebugFormat("Processed ToHex\r\n");
                if (strlength((const unsigned char*)result) != (DIGESTSIZE::DigestSizeSHA224 * 2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength((const unsigned char*)result), (DIGESTSIZE::DigestSizeSHA224 * 2), result);
                    return NULL;
                }
            }
            else
            {
                DebugFormat("Failed to convert to hex\r\n");
            }
            FreeCryptoResult(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            DebugFormat("Message passed in is NULL\r\n");
        }
        return NULL;
    }

    ShaBlobContextPtr Sha224Initialize()
    {
        ShaBlobContextPtr contextPtr = (ShaBlobContextPtr)AllocCryptoResult(sizeof(ShaBlobContext));
        if (contextPtr != NULL)
        {
            USHAReset(&contextPtr->blobContext, SHAversion::VersionSHA224);
            contextPtr->initialized = TRUE;
        }
        return contextPtr;
    }

    void Sha224Update(ShaBlobContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->initialized && message != NULL && length > 0)
        {
            USHAInput(&context->blobContext, (unsigned char*)message, length);
        }
    }

    const char* Sha224Finalize(ShaBlobContextPtr context)
    {
        char* digestBuffer = NULL;
        const char* result = NULL;
        if (context != NULL && context->initialized)
        {
            digestBuffer = (char*)AllocCryptoResult(DIGESTSIZE::DigestSizeUSHA);
            if (digestBuffer != NULL)
            {
                USHAResult(&context->blobContext, (unsigned char*)digestBuffer);
                result = ToHex(digestBuffer, DIGESTSIZE::DigestSizeSHA224, algo_sha224);
                if (result != NULL)
                {
                    if (strlength((const unsigned char*)result) != (DIGESTSIZE::DigestSizeSHA224 * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength((const unsigned char*)result), (DIGESTSIZE::DigestSizeSHA224 * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugFormat("Failed to convert to hex\r\n");
                }
                FreeCryptoResult(digestBuffer);
                digestBuffer = NULL;
            }
        }
        return result;
    }

#endif

#if defined ( __SHA256__ ) || defined(__ALL__)
    static void SHA256String(unsigned char** digest, unsigned int* digest_length, const unsigned char* string)
    {
        USHAContext context;
        unsigned int len = strlength(string);
        if (len != STRLENGTH_INVALID && string != NULL && digest_length != NULL && digest != NULL && *digest == NULL)
        {
            USHAReset(&context, SHAversion::VersionSHA256);
            USHAInput(&context, (unsigned char*)string, len);
            *digest_length = DIGESTSIZE::DigestSizeUSHA;
            *digest = (unsigned char*)AllocCryptoResult(DIGESTSIZE::DigestSizeUSHA); // DIGESTSIZE::DigestSizeSHA256);
            if ((*digest) != NULL)
            {
                USHAResult(&context, *digest);
            }
        }
    }
    const char* DoSha256(const char* message)
    {
        char* lpBuffer = NULL;
        unsigned int length = 0;
        const char* result;
        if (message)
        {
            DebugFormat("Message passed in is:");
            DebugFormat(message);
            DebugFormat("\r\n");

            SHA256String((unsigned char**)&lpBuffer, &length, (const unsigned char*)message);
            DebugFormat("Processed Message to Buffer Length: %i\r\n", DIGESTSIZE::DigestSizeUSHA);
            result = ToHex(lpBuffer, DIGESTSIZE::DigestSizeSHA256, algo_sha256);
            if (result != NULL)
            {
                DebugFormat("Processed ToHex\r\n");
                if (strlength((const unsigned char*)result) != (DIGESTSIZE::DigestSizeSHA256 * 2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength((const unsigned char*)result), (DIGESTSIZE::DigestSizeSHA256 * 2), result);
                    return NULL;
                }
            }
            else
            {
                DebugFormat("Failed to convert to hex\r\n");
            }
            FreeCryptoResult(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            DebugFormat("Message passed in is NULL\r\n");
        }
        return NULL;
    }

    ShaBlobContextPtr Sha256Initialize()
    {
        ShaBlobContextPtr contextPtr = (ShaBlobContextPtr)AllocCryptoResult(sizeof(ShaBlobContext));
        if (contextPtr != NULL)
        {
            USHAReset(&contextPtr->blobContext, SHAversion::VersionSHA256);
            contextPtr->initialized = TRUE;
        }
        return contextPtr;
    }
    
    void Sha256Update(ShaBlobContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->initialized && message != NULL && length > 0)
        {
            USHAInput(&context->blobContext, (unsigned char*)message, length);
        }
    }
    
    const char* Sha256Finalize(ShaBlobContextPtr context)
    {
        char* digestBuffer = NULL;
        const char* result = NULL;
        if (context != NULL && context->initialized)
        {
            digestBuffer = (char*)AllocCryptoResult(DIGESTSIZE::DigestSizeUSHA);
            if (digestBuffer != NULL)
            {
                USHAResult(&context->blobContext, (unsigned char*)digestBuffer);
                result = ToHex(digestBuffer, DIGESTSIZE::DigestSizeSHA256, algo_sha256);
                if (result != NULL)
                {
                    if (strlength((const unsigned char*)result) != (DIGESTSIZE::DigestSizeSHA256 * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength((const unsigned char*)result), (DIGESTSIZE::DigestSizeSHA256 * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugFormat("Failed to convert to hex\r\n");
                }
                FreeCryptoResult(digestBuffer);
                digestBuffer = NULL;
            }
        }
        return result;
    }


#endif

#if defined ( __SHA384__ ) || defined(__ALL__)
    static void SHA384String(unsigned char** digest, unsigned int* digest_length, const unsigned char* string)
    {
        USHAContext context;
        unsigned int len = strlength(string);
        if (len != STRLENGTH_INVALID && string != NULL && digest_length != NULL && digest != NULL && *digest == NULL)
        {
            USHAReset(&context, SHAversion::VersionSHA384);
            USHAInput(&context, (unsigned char*)string, len);
            *digest_length = DIGESTSIZE::DigestSizeUSHA;
            *digest = (unsigned char*)AllocCryptoResult(DIGESTSIZE::DigestSizeUSHA); // DIGESTSIZE::DigestSizeSHA256);
            if ((*digest) != NULL)
            {
                USHAResult(&context, *digest);
            }
        }
    }

    const char* DoSha384(const char* message)
    {
        char* lpBuffer = NULL;
        unsigned int length = 0;
        const char* result;
        if (message)
        {
            DebugFormat("Message passed in is:");
            DebugFormat(message);
            DebugFormat("\r\n");

            SHA384String((unsigned char**)&lpBuffer, &length, (const unsigned char*)message);
            DebugFormat("Processed Message to Buffer Length: %i\r\n", DIGESTSIZE::DigestSizeUSHA);
            result = ToHex(lpBuffer, DIGESTSIZE::DigestSizeSHA384, algo_sha384);
            if (result != NULL)
            {
                DebugFormat("Processed ToHex\r\n");
                if (strlength((const unsigned char*)result) != (DIGESTSIZE::DigestSizeSHA384 * 2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength((const unsigned char*)result), (DIGESTSIZE::DigestSizeSHA384 * 2), result);
                    return NULL;
                }
            }
            else
            {
                DebugFormat("Failed to convert to hex\r\n");
            }
            FreeCryptoResult(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            DebugFormat("Message passed in is NULL\r\n");
        }
        return NULL;
    }

    ShaBlobContextPtr Sha384Initialize()
    {
        ShaBlobContextPtr contextPtr = (ShaBlobContextPtr)AllocCryptoResult(sizeof(ShaBlobContext));
        if (contextPtr != NULL)
        {
            USHAReset(&contextPtr->blobContext, SHAversion::VersionSHA384);
            contextPtr->initialized = TRUE;
        }
        return contextPtr;
    }

    void Sha384Update(ShaBlobContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->initialized && message != NULL && length > 0)
        {
            USHAInput(&context->blobContext, (unsigned char*)message, length);
        }
    }

    const char* Sha384Finalize(ShaBlobContextPtr context)
    {
        char* digestBuffer = NULL;
        const char* result = NULL;
        if (context != NULL && context->initialized)
        {
            digestBuffer = (char*)AllocCryptoResult(DIGESTSIZE::DigestSizeUSHA);
            if (digestBuffer != NULL)
            {
                USHAResult(&context->blobContext, (unsigned char*)digestBuffer);
                result = ToHex(digestBuffer, DIGESTSIZE::DigestSizeSHA384, algo_sha384);
                if (result != NULL)
                {
                    if (strlength((const unsigned char*)result) != (DIGESTSIZE::DigestSizeSHA384 * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength((const unsigned char*)result), (DIGESTSIZE::DigestSizeSHA384 * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugFormat("Failed to convert to hex\r\n");
                }
                FreeCryptoResult(digestBuffer);
                digestBuffer = NULL;
            }
        }
        return result;
    }


#endif

#if defined ( __SHA512__ ) || defined(__ALL__)
    static void SHA512String(unsigned char** digest, unsigned int* digest_length, const unsigned char* string)
    {
        USHAContext context;
        unsigned int len = strlength(string);
        if (len != STRLENGTH_INVALID && string != NULL && digest_length != NULL && digest != NULL && *digest == NULL)
        {
            USHAReset(&context, SHAversion::VersionSHA512);
            USHAInput(&context, (unsigned char*)string, len);
            *digest_length = DIGESTSIZE::DigestSizeUSHA;
            *digest = (unsigned char*)AllocCryptoResult(DIGESTSIZE::DigestSizeUSHA); // DIGESTSIZE::DigestSizeSHA256);
            if ((*digest) != NULL)
            {
                USHAResult(&context, *digest);
            }
        }
    }

    const char* DoSha512(const char* message)
    {
        char* lpBuffer = NULL;
        unsigned int length = 0;
        const char* result;
        if (message)
        {
            DebugFormat("Message passed in is:");
            DebugFormat(message);
            DebugFormat("\r\n");

            SHA512String((unsigned char**)&lpBuffer, &length, (const unsigned char*)message);
            DebugFormat("Processed Message to Buffer Length: %i\r\n", DIGESTSIZE::DigestSizeUSHA);
            result = ToHex(lpBuffer, DIGESTSIZE::DigestSizeSHA512, algo_sha512);
            if (result != NULL)
            {
                DebugFormat("Processed ToHex\r\n");
                if (strlength((const unsigned char*)result) != (DIGESTSIZE::DigestSizeSHA512 * 2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength((const unsigned char*)result), (DIGESTSIZE::DigestSizeSHA512 * 2), result);
                    return NULL;
                }
            }
            else
            {
                DebugFormat("Failed to convert to hex\r\n");
            }
            FreeCryptoResult(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            DebugFormat("Message passed in is NULL\r\n");
        }
        return NULL;
    }

    ShaBlobContextPtr Sha512Initialize()
    {
        ShaBlobContextPtr contextPtr = (ShaBlobContextPtr)AllocCryptoResult(sizeof(ShaBlobContext));
        if (contextPtr != NULL)
        {
            USHAReset(&contextPtr->blobContext, SHAversion::VersionSHA512);
            contextPtr->initialized = TRUE;
        }
        return contextPtr;
    }

    void Sha512Update(ShaBlobContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->initialized && message != NULL && length > 0)
        {
            USHAInput(&context->blobContext, (unsigned char*)message, length);
        }
    }

    const char* Sha512Finalize(ShaBlobContextPtr context)
    {
        char* digestBuffer = NULL;
        const char* result = NULL;
        if (context != NULL && context->initialized)
        {
            digestBuffer = (char*)AllocCryptoResult(DIGESTSIZE::DigestSizeUSHA);
            if (digestBuffer != NULL)
            {
                USHAResult(&context->blobContext, (unsigned char*)digestBuffer);
                result = ToHex(digestBuffer, DIGESTSIZE::DigestSizeSHA512, algo_sha512);
                if (result != NULL)
                {
                    if (strlength((const unsigned char*)result) != (DIGESTSIZE::DigestSizeSHA512 * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength((const unsigned char*)result), (DIGESTSIZE::DigestSizeSHA512 * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugFormat("Failed to convert to hex\r\n");
                }
                FreeCryptoResult(digestBuffer);
                digestBuffer = NULL;
            }
        }
        return result;
    }

#endif

#ifdef __cplusplus
}
#endif