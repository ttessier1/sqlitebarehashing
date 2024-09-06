
#pragma once

const int STRLENGTH_INVALID = -1;

#if defined(__cplusplus)
extern "C" unsigned int strlength(const unsigned char * length);
extern "C" void* AllocCryptoResult(size_t size);
extern "C" void FreeCryptoResult(const void* object);
extern "C" void DebugFormat(const char* format, ...);
extern "C" const char* ToHex(const char* value, unsigned int length, unsigned int algorithms);
extern "C" unsigned int SelfCheckToHex(const char* value, unsigned int length, unsigned int algorithm);
/*extern "C" unsigned int GetDigestSize(unsigned int algorithms);
extern "C" const char* ToHexSZ(const char* value);
extern "C" const char* ToHex(const char* value, unsigned int length, unsigned int algorithms);
extern "C" const char* FromHex(const char* value, unsigned int length, unsigned int* resultLength);
extern "C" const char* FromHexSZ(const char* value, unsigned int* resultLength);
extern "C" unsigned int SelfCheckToHexSZ(const char* value, unsigned int length);
extern "C" unsigned int SelfCheckToHex(const char* value, unsigned int length, unsigned int algorithm);
extern "C" void DebugFormat(const char* format, ...);
extern "C" void FreeCryptoResult(const void* object);
*/
#else
unsigned int strlength(const unsigned char* length);
void* AllocCryptoResult(size_t size);
void FreeCryptoResult(const void* object);
void DebugFormat(const char* format, ...);
const char* ToHex(const char* value, unsigned int length, unsigned int algorithms);
unsigned int SelfCheckToHex(const char* value, unsigned int length, unsigned int algorithm);
/*
unsigned int GetDigestSize(unsigned int algorithms);
const char* ToHexSZ(const char* value);
const char* ToHex(const char* value, unsigned int length, unsigned int algorithms);
const char* FromHex(const char* value, unsigned int length, unsigned int* resultLength);
const char* FromHexSZ(const char* value, unsigned int* resultLength);
unsigned int SelfCheckToHexSZ(const char* value, unsigned int length);
unsigned int SelfCheckToHex(const char* value, unsigned int length, unsigned int algorithm);
void DebugFormat(const char* format, ...);
void FreeCryptoResult(const void* object);
*/
#endif

