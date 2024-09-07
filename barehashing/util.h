
#pragma once

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))||defined(__linux__)
#include <unistd.h>
#endif
const int STRLENGTH_INVALID = -1;

#if defined(__cplusplus)
extern "C" unsigned int strlength(const unsigned char * length);
extern "C" void* AllocCryptoResult(size_t size);
extern "C" void FreeCryptoResult(const void* object);
#ifdef WIN32
extern "C" void DebugFormat(const char* format, ...);
#else
#define DebugFormat //
#endif
extern "C" const char* ToHex(const char* value, unsigned int length, unsigned int algorithms);
extern "C" unsigned int SelfCheckToHex(const char* value, unsigned int length, unsigned int algorithm);

#else
unsigned int strlength(const unsigned char* length);
void* AllocCryptoResult(size_t size);
void FreeCryptoResult(const void* object);
#ifdef WIN32
void DebugFormat(const char* format, ...);
#else
#define DebugFormat //
#endif
const char* ToHex(const char* value, unsigned int length, unsigned int algorithms);
unsigned int SelfCheckToHex(const char* value, unsigned int length, unsigned int algorithm);
#endif

