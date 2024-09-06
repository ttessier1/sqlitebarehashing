// barehashing.cpp : Defines the exported functions for the DLL.
//


#include "pch.h"
#include "framework.h"
#include "barehashing.h"

#define PING_MESSAGE "ping"

static int hash_ping(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    nIn = strlength((const unsigned char *)PING_MESSAGE);
    if (argc != 0)
    {
        return-1;
    }
    zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
    if (zOut == 0)
    {
        sqlite3_result_error_nomem(context);
        return-1;
    }
    strcpy_s((char * )zOut, nIn + 1, PING_MESSAGE);

    sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
    sqlite3_free(zToFree);
    return 0;
}

#ifdef _WIN32
__declspec(dllexport)
#endif
extern int sqlite3_hashing_init(
    sqlite3* db,
    char** pzErrMsg,
    const sqlite3_api_routines* pApi
) {
    int rc = SQLITE_OK;

    SQLITE_EXTENSION_INIT2(pApi);

    rc = sqlite3_create_function(db, "hash_ping", 0, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, hash_ping, 0, 0);
    if (rc != SQLITE_OK) return rc;

    return rc;
}