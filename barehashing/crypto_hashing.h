#include "pch.h"

#ifndef BOOL
typedef int                 BOOL;
#endif

#ifndef FALSE
#define FALSE               0
#endif

#ifndef TRUE
#define TRUE                1
#endif

#if (defined(__MD2__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct md2BlobContext Md2BlobContext, * Md2BlobContextPtr;

#endif

#if (defined(__MD4__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct md4BlobContext Md4BlobContext, * Md4BlobContextPtr;

#endif

#if (defined(__MD5__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct md5BlobContext Md5BlobContext, * Md5BlobContextPtr;

#endif

#if (defined(__SHA1__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct shaBlobContext ShaBlobContext, * ShaBlobContextPtr;

#endif

#ifdef __cplusplus

#if defined(__MD2__) || (defined __ALL__)
extern "C" const char* DoMd2(const char* message);
extern "C" Md2BlobContextPtr Md2Initialize();
extern "C" void Md2Update(Md2BlobContextPtr context, const char* message, unsigned int length);
extern "C" const char * Md2Finalize(Md2BlobContextPtr context);
#endif
#if defined(__MD4__) || (defined __ALL__)
extern "C" const char* DoMd4(const char* message);
extern "C" Md4BlobContextPtr Md4Initialize();
extern "C" void Md4Update(Md4BlobContextPtr context, const char* message, unsigned int length);
extern "C" const char* Md4Finalize(Md4BlobContextPtr context);
#endif
#if defined(__MD5__) || (defined __ALL__)
extern "C" const char* DoMd5(const char* message);
extern "C" Md5BlobContextPtr Md5Initialize();
extern "C" void Md5Update(Md5BlobContextPtr context, const char* message, unsigned int length);
extern "C" const char* Md5Finalize(Md5BlobContextPtr context);
#endif
#if defined(__SHA1__) || (defined __ALL__)
extern "C" const char* DoSha1(const char* message);
extern "C" ShaBlobContextPtr Sha1Initialize();
extern "C" void Sha1Update(ShaBlobContextPtr context, const char* message, unsigned int length);
extern "C" const char* Sha1Finalize(ShaBlobContextPtr context);
#endif
#if defined(__SSH224__) || (defined __ALL__)
extern "C" const char* DoSha224(const char* message);
extern "C" ShaBlobContextPtr Sha224Initialize();
extern "C" void Sha224Update(ShaBlobContextPtr context, const char* message, unsigned int length);
extern "C" const char* Sha224Finalize(ShaBlobContextPtr context);
#endif
#if defined(__SSH256__) || (defined __ALL__)
extern "C" const char* DoSha256(const char* message);
extern "C" ShaBlobContextPtr Sha256Initialize();
extern "C" void Sha256Update(ShaBlobContextPtr context, const char* message, unsigned int length);
extern "C" const char* Sha256Finalize(ShaBlobContextPtr context);
#endif
#if defined(__SSH384__) || (defined __ALL__)
extern "C" const char* DoSha384(const char* message);
extern "C" ShaBlobContextPtr Sha384Initialize();
extern "C" void Sha384Update(ShaBlobContextPtr context, const char* message, unsigned int length);
extern "C" const char* Sha384Finalize(ShaBlobContextPtr context);
#endif
#if defined(__SSH512__) || (defined __ALL__)
extern "C" const char* DoSha512(const char* message);
extern "C" ShaBlobContextPtr Sha512Initialize();
extern "C" void Sha512Update(ShaBlobContextPtr context, const char* message, unsigned int length);
extern "C" const char* Sha512Finalize(ShaBlobContextPtr context);
#endif
#else
#if defined(__MD2__) || (defined __ALL__)
const char* DoMd2(const char* message);
Md2BlobContextPtr Md2Initialize();
void Md2Update(Md2BlobContextPtr context, const char* message, unsigned int length);
const char* Md2Finalize(Md2BlobContextPtr context);
#endif
#if defined(__MD4__) || (defined __ALL__)
const char* DoMd4(const char* message);
Md4BlobContextPtr Md4Initialize();
void Md4Update(Md4BlobContextPtr context, const char* message, unsigned int length);
const char* Md4Finalize(Md4BlobContextPtr context);
#endif
#if defined(__MD5__) || (defined __ALL__)
const char* DoMd5(const char* message);
Md5BlobContextPtr Md5Initialize();
void Md5Update(Md5BlobContextPtr context, const char* message, unsigned int length);
const char* Md5Finalize(Md5BlobContextPtr context);
#endif

#if defined(__SHA__) || (defined __ALL__)
const char* DoSha1(const char* message);
ShaBlobContextPtr Sha1Initialize();
void Sha1Update(ShaBlobContextPtr context, const char* message, unsigned int length);
const char* Sha1Finalize(ShaBlobContextPtr context);
#endif
#if defined(__SHA224__) || (defined __ALL__)
const char* DoSha224(const char* message);
ShaBlobContextPtr Sha224Initialize();
void Sha224Update(ShaBlobContextPtr context, const char* message, unsigned int length);
const char* Sha224Finalize(ShaBlobContextPtr context);
#endif
#if defined(__SHA256__) || (defined __ALL__)
const char* DoSha256(const char* message);
ShaBlobContextPtr Sha256Initialize();
void Sha256Update(ShaBlobContextPtr context, const char* message, unsigned int length);
const char* Sha256Finalize(ShaBlobContextPtr context);
#endif
#if defined(__SHA384__) || (defined __ALL__)
const char* DoSha384(const char* message);
ShaBlobContextPtr Sha384Initialize();
void Sha384Update(ShaBlobContextPtr context, const char* message, unsigned int length);
const char* Sha384Finalize(ShaBlobContextPtr context);
#endif
#if defined(__SHA512__) || (defined __ALL__)
const char* DoSha512(const char* message);
ShaBlobContextPtr Sha512Initialize();
void Sha512Update(ShaBlobContextPtr context, const char* message, unsigned int length);
const char* Sha512Finalize(ShaBlobContextPtr context);
#endif
#endif