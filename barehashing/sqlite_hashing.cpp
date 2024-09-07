#include "pch.h"
#include <inttypes.h>
#include <sqlite3ext.h> /* Do not use <sqlite3.h>! */
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#define WIN32_LEAN_AND_MEAN      // Exclude rarely-used stuff from Windows headers
#ifdef WIN32
#include <windows.h>
#endif
SQLITE_EXTENSION_INIT1

#define PING_MESSAGE "ping"

#ifdef __cplusplus
extern "C" {
#endif

    int pagesize_callback(void* callbackVerify, int numberOfColumns, char** values, char** column_names)
    {
        if (callbackVerify != NULL)
        {
            if (numberOfColumns == 1)
            {
                (*(int*)callbackVerify) = atoi(values[0]);
            }
        }
        return SQLITE_OK;
    }

    int get_schema_page_size(sqlite3_context* context, sqlite3* db, const char* schema, int length)
    {
        int bufferLength = 0;
        char* buffer = NULL;
        char* errmsg;
        int pagesize;
        if (db != NULL && schema != NULL)
        {
            bufferLength = length + strlength((const unsigned char*)"PRAGMA %s.page_size") + 1 - 2; // subtract %s from string but add null character length
            buffer = (char*)AllocCryptoResult(bufferLength);
            if (buffer)
            {

                sqlite3_snprintf(bufferLength, buffer, "PRAGMA %s.page_size", schema);
                if (sqlite3_exec(
                    db,
                    buffer,                           /* SQL to be evaluated */
                    (sqlite3_callback)pagesize_callback,  /* Callback function */
                    (void*)&pagesize,                                    /* 1st argument to callback */
                    &errmsg                              /* Error msg written here */
                ) == SQLITE_OK)
                {
                    FreeCryptoResult(buffer);
                    return pagesize;
                }
                FreeCryptoResult(buffer);
                return -1;
            }
            else
            {
                return -1;
            }
        }
        else
        {
            return -1;
        }
    }

static void hash_ping(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    nIn = strlength((const unsigned char*)PING_MESSAGE);
    if (argc != 0)
    {
        return;
    }
    zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
    if (zOut == 0)
    {
        sqlite3_result_error_nomem(context);
        return;
    }
    memset(zOut, 0, nIn + 1);
#ifdef WIN32
    strcpy_s((char *)zOut, nIn+1, PING_MESSAGE);
#else
    strcpy((char*)zOut, PING_MESSAGE);
#endif
    sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
    sqlite3_free(zToFree);
    return ;
}


#if defined(__MD2__)|| defined(__ALL__)

static int hash_md2(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugFormat("Md2 Called\r\n");
    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int index = 0;
    const char* result;
    int rc = 0;
    if (argc != 1)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    else if (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);

        DebugFormat("Non Buffered Read\r\n");
        zIn = (const unsigned char*)sqlite3_value_text(argv[0]);
        DebugFormat((const char *)zIn);
        result = DoMd2((const char*)zIn);
        if (result != NULL)
        {
            DebugFormat("Result Not NULL\r\n");
            DebugFormat(result);
            nIn = strlength((const unsigned char *)result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugFormat("ZOut Not NULL\r\n");
#ifdef WIN32
                strncpy_s((char*)zOut, nIn + 1, result, strlen(result));
#else
                strncpy((char*)zOut, result, strlen(result));
#endif
                DebugFormat("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
                rc = SQLITE_OK;
            }
            else
            {
                DebugFormat("ZOut  NULL\r\n");
                rc = SQLITE_ERROR;
            }
            FreeCryptoResult(result);

        }
        else
        {
            DebugFormat("Result is NULL\r\n");
            sqlite3_result_error(context, "Possible memory allocation failure\r\n", strlength((const unsigned char*)"Possible memory allocation failure\r\n"));
            rc = SQLITE_ERROR;
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength((const unsigned char*)"Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return rc;
}

#endif


#if (defined(__MD2__) || defined(__ALL__)) && defined(__USE_BLOB__)
static int hash_blobmd2(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Md2BlobContextPtr md2BlobContext;

    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugFormat("Md2Blob Called\r\n");
    if (argc != 4)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = (const char*)sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        if(buffer_size>-1)
        {
            buffer_size = 4096;
        }
        table = (const char*)sqlite3_value_text(argv[1]);
        column = (const char*)sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)AllocCryptoResult(buffer_size);
            if (buffer != NULL)
            {
                md2BlobContext = Md2Initialize();
                if (md2BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = min(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Md2Update(md2BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Md2Finalize(md2BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength((const unsigned char *)result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugFormat("ZOut Not NULL\r\n");
#ifdef WIN32
                                strncpy_s((char*)zOut, nIn + 1, result, strlength((const unsigned char*)result));
#else
                                strncpy((char*)zOut, result, strlength((const unsigned char*)result));
#endif
                                DebugFormat("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugFormat("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength((const unsigned char*)"Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength((const unsigned char*)"Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength((const unsigned char*)"Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                FreeCryptoResult(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength((const unsigned char*)"Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return rc;
}
#endif
static int hash_md4(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugFormat("Md4 Called\r\n");
    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int index = 0;
    const char* result;
    int rc = 0;
    if (argc != 1)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    else if (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);

        DebugFormat("Non Buffered Read\r\n");
        zIn = (const unsigned char*)sqlite3_value_text(argv[0]);
        DebugFormat((const char*)zIn);
        result = DoMd4((const char*)zIn);
        if (result != NULL)
        {
            DebugFormat("Result Not NULL\r\n");
            DebugFormat(result);
            nIn = strlength((const unsigned char*)result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugFormat("ZOut Not NULL\r\n");
#ifdef WIN32
                strncpy_s((char*)zOut, nIn + 1, result, strlen(result));
#else
                strncpy((char*)zOut, result, strlen(result));
#endif
                DebugFormat("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
                rc = SQLITE_OK;
            }
            else
            {
                DebugFormat("ZOut  NULL\r\n");
                rc = SQLITE_ERROR;
            }
            FreeCryptoResult(result);

        }
        else
        {
            DebugFormat("Result is NULL\r\n");
            sqlite3_result_error(context, "Possible memory allocation failure\r\n", strlength((const unsigned char*)"Possible memory allocation failure\r\n"));
            rc = SQLITE_ERROR;
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength((const unsigned char*)"Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return rc;
}

static int hash_blobmd4(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Md4BlobContextPtr md4BlobContext;

    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugFormat("Md4Blob Called\r\n");
    if (argc != 4)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = (const char*)sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        if (buffer_size > -1)
        {
            buffer_size = 4096;
        }
        table = (const char*)sqlite3_value_text(argv[1]);
        column = (const char*)sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)AllocCryptoResult(buffer_size);
            if (buffer != NULL)
            {
                md4BlobContext = Md4Initialize();
                if (md4BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = min(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Md4Update(md4BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Md4Finalize(md4BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength((const unsigned char*)result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugFormat("ZOut Not NULL\r\n");
#ifdef WIN32
                                strncpy_s((char*)zOut, nIn + 1, result, strlength((const unsigned char*)result));
#else
                                strncpy((char*)zOut, result, strlength((const unsigned char*)result));
#endif

                                DebugFormat("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugFormat("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength((const unsigned char*)"Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength((const unsigned char*)"Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength((const unsigned char*)"Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                FreeCryptoResult(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength((const unsigned char*)"Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return rc;
}

static int hash_md5(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugFormat("Md5 Called\r\n");
    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int index = 0;
    const char* result;
    int rc = 0;
    if (argc != 1)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    else if (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);

        DebugFormat("Non Buffered Read\r\n");
        zIn = (const unsigned char*)sqlite3_value_text(argv[0]);
        DebugFormat((const char*)zIn);
        result = DoMd5((const char*)zIn);
        if (result != NULL)
        {
            DebugFormat("Result Not NULL\r\n");
            DebugFormat(result);
            nIn = strlength((const unsigned char*)result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugFormat("ZOut Not NULL\r\n");
#ifdef WIN32
                strncpy_s((char*)zOut, nIn + 1, result, strlen(result));
#else
                strncpy((char*)zOut, result, strlen(result));
#endif

                DebugFormat("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
                rc = SQLITE_OK;
            }
            else
            {
                DebugFormat("ZOut  NULL\r\n");
                rc = SQLITE_ERROR;
            }
            FreeCryptoResult(result);

        }
        else
        {
            DebugFormat("Result is NULL\r\n");
            sqlite3_result_error(context, "Possible memory allocation failure\r\n", strlength((const unsigned char*)"Possible memory allocation failure\r\n"));
            rc = SQLITE_ERROR;
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength((const unsigned char*)"Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return rc;
}

static int hash_blobmd5(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Md5BlobContextPtr md5BlobContext;

    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugFormat("Md5Blob Called\r\n");
    if (argc != 4)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = (const char*)sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        if (buffer_size > -1)
        {
            buffer_size = 4096;
        }
        table = (const char*)sqlite3_value_text(argv[1]);
        column = (const char*)sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)AllocCryptoResult(buffer_size);
            if (buffer != NULL)
            {
                md5BlobContext = Md5Initialize();
                if (md5BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = min(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Md5Update(md5BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Md5Finalize(md5BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength((const unsigned char*)result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugFormat("ZOut Not NULL\r\n");
#ifdef WIN32
                                strncpy_s((char*)zOut, nIn + 1, result, strlength((const unsigned char*)result));
#else
                                strncpy((char*)zOut, result, strlength((const unsigned char*)result));
#endif
                                DebugFormat("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugFormat("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength((const unsigned char*)"Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength((const unsigned char*)"Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength((const unsigned char*)"Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                FreeCryptoResult(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength((const unsigned char*)"Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return rc;
}

static int hash_sha1(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugFormat("Sha1 Called\r\n");
    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int index = 0;
    const char* result;
    int rc = 0;
    if (argc != 1)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    else if (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);

        DebugFormat("Non Buffered Read\r\n");
        zIn = (const unsigned char*)sqlite3_value_text(argv[0]);
        DebugFormat((const char*)zIn);
        result = DoSha1((const char*)zIn);
        if (result != NULL)
        {
            DebugFormat("Result Not NULL\r\n");
            DebugFormat(result);
            nIn = strlength((const unsigned char*)result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugFormat("ZOut Not NULL\r\n");
#ifdef WIN32
                strncpy_s((char*)zOut, nIn + 1, result, strlen(result));
#else
                strncpy((char*)zOut, result, strlen(result));
#endif

                DebugFormat("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
                rc = SQLITE_OK;
            }
            else
            {
                DebugFormat("ZOut  NULL\r\n");
                rc = SQLITE_ERROR;
            }
            FreeCryptoResult(result);

        }
        else
        {
            DebugFormat("Result is NULL\r\n");
            sqlite3_result_error(context, "Possible memory allocation failure\r\n", strlength((const unsigned char*)"Possible memory allocation failure\r\n"));
            rc = SQLITE_ERROR;
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength((const unsigned char*)"Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return rc;
}

static int hash_blobsha1(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    ShaBlobContextPtr shaBlobContext;

    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugFormat("Sha1Blob Called\r\n");
    if (argc != 4)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = (const char*)sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        if (buffer_size > -1)
        {
            buffer_size = 4096;
        }
        table = (const char*)sqlite3_value_text(argv[1]);
        column = (const char*)sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)AllocCryptoResult(buffer_size);
            if (buffer != NULL)
            {
                shaBlobContext = Sha1Initialize();
                if (shaBlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = min(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Sha1Update(shaBlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Sha1Finalize(shaBlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength((const unsigned char*)result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugFormat("ZOut Not NULL\r\n");
#ifdef WIN32
                                strncpy_s((char*)zOut, nIn + 1, result, strlength((const unsigned char*)result));
#else
                                strncpy((char*)zOut, result, strlength((const unsigned char*)result));
#endif

                                DebugFormat("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugFormat("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength((const unsigned char*)"Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength((const unsigned char*)"Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength((const unsigned char*)"Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                FreeCryptoResult(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength((const unsigned char*)"Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return rc;
}

static int hash_sha224(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugFormat("Sha224 Called\r\n");
    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int index = 0;
    const char* result;
    int rc = 0;
    if (argc != 1)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    else if (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);

        DebugFormat("Non Buffered Read\r\n");
        zIn = (const unsigned char*)sqlite3_value_text(argv[0]);
        DebugFormat((const char*)zIn);
        result = DoSha224((const char*)zIn);
        if (result != NULL)
        {
            DebugFormat("Result Not NULL\r\n");
            DebugFormat(result);
            nIn = strlength((const unsigned char*)result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugFormat("ZOut Not NULL\r\n");
#ifdef WIN32
                strncpy_s((char*)zOut, nIn + 1, result, strlen(result));
#else
                strncpy((char*)zOut, result, strlen(result));
#endif
                DebugFormat("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
                rc = SQLITE_OK;
            }
            else
            {
                DebugFormat("ZOut  NULL\r\n");
                rc = SQLITE_ERROR;
            }
            FreeCryptoResult(result);

        }
        else
        {
            DebugFormat("Result is NULL\r\n");
            sqlite3_result_error(context, "Possible memory allocation failure\r\n", strlength((const unsigned char*)"Possible memory allocation failure\r\n"));
            rc = SQLITE_ERROR;
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength((const unsigned char*)"Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return rc;
}

static int hash_blobsha224(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    ShaBlobContextPtr shaBlobContext;

    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugFormat("Sha224Blob Called\r\n");
    if (argc != 4)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = (const char*)sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        if (buffer_size > -1)
        {
            buffer_size = 4096;
        }
        table = (const char*)sqlite3_value_text(argv[1]);
        column = (const char*)sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)AllocCryptoResult(buffer_size);
            if (buffer != NULL)
            {
                shaBlobContext = Sha224Initialize();
                if (shaBlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = min(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Sha224Update(shaBlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Sha224Finalize(shaBlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength((const unsigned char*)result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugFormat("ZOut Not NULL\r\n");
#ifdef WIN32
                                strncpy_s((char*)zOut, nIn + 1, result, strlength((const unsigned char*)result));
#else
                                strncpy((char*)zOut, result, strlength((const unsigned char*)result));
#endif
                                DebugFormat("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugFormat("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength((const unsigned char*)"Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength((const unsigned char*)"Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength((const unsigned char*)"Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                FreeCryptoResult(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength((const unsigned char*)"Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return rc;
}

static int hash_sha256(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugFormat("Sha256 Called\r\n");
    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int index = 0;
    const char* result;
    int rc = 0;
    if (argc != 1)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    else if (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);

        DebugFormat("Non Buffered Read\r\n");
        zIn = (const unsigned char*)sqlite3_value_text(argv[0]);
        DebugFormat((const char*)zIn);
        result = DoSha256((const char*)zIn);
        if (result != NULL)
        {
            DebugFormat("Result Not NULL\r\n");
            DebugFormat(result);
            nIn = strlength((const unsigned char*)result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugFormat("ZOut Not NULL\r\n");
#ifdef WIN32
                strncpy_s((char*)zOut, nIn + 1, result, strlen(result));
#else
                strncpy((char*)zOut, result, strlen(result));
#endif

                DebugFormat("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
                rc = SQLITE_OK;
            }
            else
            {
                DebugFormat("ZOut  NULL\r\n");
                rc = SQLITE_ERROR;
            }
            FreeCryptoResult(result);

        }
        else
        {
            DebugFormat("Result is NULL\r\n");
            sqlite3_result_error(context, "Possible memory allocation failure\r\n", strlength((const unsigned char*)"Possible memory allocation failure\r\n"));
            rc = SQLITE_ERROR;
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength((const unsigned char*)"Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return rc;
}

static int hash_blobsha256(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    ShaBlobContextPtr shaBlobContext;

    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugFormat("Sha256Blob Called\r\n");
    if (argc != 4)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = (const char*)sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        if (buffer_size > -1)
        {
            buffer_size = 4096;
        }
        table = (const char*)sqlite3_value_text(argv[1]);
        column = (const char*)sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)AllocCryptoResult(buffer_size);
            if (buffer != NULL)
            {
                shaBlobContext = Sha256Initialize();
                if (shaBlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = min(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Sha256Update(shaBlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Sha256Finalize(shaBlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength((const unsigned char*)result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugFormat("ZOut Not NULL\r\n");
#ifdef WIN32
                                strncpy_s((char*)zOut, nIn + 1, result, strlength((const unsigned char*)result));
#else
                                strncpy((char*)zOut, result, strlength((const unsigned char*)result));
#endif

                                DebugFormat("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugFormat("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength((const unsigned char*)"Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength((const unsigned char*)"Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength((const unsigned char*)"Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                FreeCryptoResult(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength((const unsigned char*)"Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return rc;
}

static int hash_sha384(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugFormat("Sha384 Called\r\n");
    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int index = 0;
    const char* result;
    int rc = 0;
    if (argc != 1)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    else if (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);

        DebugFormat("Non Buffered Read\r\n");
        zIn = (const unsigned char*)sqlite3_value_text(argv[0]);
        DebugFormat((const char*)zIn);
        result = DoSha384((const char*)zIn);
        if (result != NULL)
        {
            DebugFormat("Result Not NULL\r\n");
            DebugFormat(result);
            nIn = strlength((const unsigned char*)result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugFormat("ZOut Not NULL\r\n");
#ifdef WIN32
                strncpy_s((char*)zOut, nIn + 1, result, strlen(result));
#else
                strncpy((char*)zOut, result, strlen(result));
#endif

                DebugFormat("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
                rc = SQLITE_OK;
            }
            else
            {
                DebugFormat("ZOut  NULL\r\n");
                rc = SQLITE_ERROR;
            }
            FreeCryptoResult(result);

        }
        else
        {
            DebugFormat("Result is NULL\r\n");
            sqlite3_result_error(context, "Possible memory allocation failure\r\n", strlength((const unsigned char*)"Possible memory allocation failure\r\n"));
            rc = SQLITE_ERROR;
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength((const unsigned char*)"Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return rc;
}

static int hash_blobsha384(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    ShaBlobContextPtr shaBlobContext;

    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugFormat("Sha384Blob Called\r\n");
    if (argc != 4)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = (const char*)sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        if (buffer_size > -1)
        {
            buffer_size = 4096;
        }
        table = (const char*)sqlite3_value_text(argv[1]);
        column = (const char*)sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)AllocCryptoResult(buffer_size);
            if (buffer != NULL)
            {
                shaBlobContext = Sha384Initialize();
                if (shaBlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = min(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Sha384Update(shaBlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Sha384Finalize(shaBlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength((const unsigned char*)result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugFormat("ZOut Not NULL\r\n");
#ifdef WIN32
                                strncpy_s((char*)zOut, nIn + 1, result, strlength((const unsigned char*)result));
#else
                                strncpy((char*)zOut, result, strlength((const unsigned char*)result));
#endif
                                DebugFormat("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugFormat("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength((const unsigned char*)"Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength((const unsigned char*)"Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength((const unsigned char*)"Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                FreeCryptoResult(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength((const unsigned char*)"Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return rc;
}

static int hash_sha512(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugFormat("Sha512 Called\r\n");
    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int index = 0;
    const char* result;
    int rc = 0;
    if (argc != 1)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    else if (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);

        DebugFormat("Non Buffered Read\r\n");
        zIn = (const unsigned char*)sqlite3_value_text(argv[0]);
        DebugFormat((const char*)zIn);
        result = DoSha512((const char*)zIn);
        if (result != NULL)
        {
            DebugFormat("Result Not NULL\r\n");
            DebugFormat(result);
            nIn = strlength((const unsigned char*)result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugFormat("ZOut Not NULL\r\n");
#ifdef WIN32
                strncpy_s((char*)zOut, nIn + 1, result, strlen(result));
#else
                strncpy((char*)zOut, result, strlen(result));
#endif
                DebugFormat("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
                rc = SQLITE_OK;
            }
            else
            {
                DebugFormat("ZOut  NULL\r\n");
                rc = SQLITE_ERROR;
            }
            FreeCryptoResult(result);

        }
        else
        {
            DebugFormat("Result is NULL\r\n");
            sqlite3_result_error(context, "Possible memory allocation failure\r\n", strlength((const unsigned char*)"Possible memory allocation failure\r\n"));
            rc = SQLITE_ERROR;
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength((const unsigned char*)"Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return rc;
}

static int hash_blobsha512(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    ShaBlobContextPtr shaBlobContext;

    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugFormat("Sha512Blob Called\r\n");
    if (argc != 4)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength((const unsigned char*)"Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = (const char*)sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        if (buffer_size > -1)
        {
            buffer_size = 4096;
        }
        table = (const char*)sqlite3_value_text(argv[1]);
        column = (const char*)sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)AllocCryptoResult(buffer_size);
            if (buffer != NULL)
            {
                shaBlobContext = Sha512Initialize();
                if (shaBlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = min(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Sha512Update(shaBlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Sha512Finalize(shaBlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength((const unsigned char*)result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugFormat("ZOut Not NULL\r\n");
#ifdef WIN32
                                strncpy_s((char*)zOut, nIn + 1, result, strlength((const unsigned char*)result));
#else
                                strncpy((char*)zOut, result, strlength((const unsigned char*)result));
#endif
                                DebugFormat("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugFormat("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength((const unsigned char*)"Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength((const unsigned char*)"Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength((const unsigned char*)"Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                FreeCryptoResult(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength((const unsigned char*)"Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return rc;
}



#ifdef _WIN32
    __declspec(dllexport)
#endif
        extern int sqlite3_barehashing_init(
            sqlite3* db,
            char** pzErrMsg,
            const sqlite3_api_routines* pApi
        ) {
        int rc = SQLITE_OK;

        SQLITE_EXTENSION_INIT2(pApi);

        rc = sqlite3_create_function(db, "hash_ping", 0, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, (void (*)(sqlite3_context*, int, sqlite3_value**))hash_ping, 0, 0);
        if (rc != SQLITE_OK) return rc;

        rc = sqlite3_create_function(db, "md2", 1, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, (void (*)(sqlite3_context*, int, sqlite3_value**))hash_md2, 0, 0);
        if (rc != SQLITE_OK) return rc;

        rc = sqlite3_create_function(db, "md4", 1, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, (void (*)(sqlite3_context*, int, sqlite3_value**))hash_md4, 0, 0);
        if (rc != SQLITE_OK) return rc;

        rc = sqlite3_create_function(db, "md5", 1, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, (void (*)(sqlite3_context*, int, sqlite3_value**))hash_md5, 0, 0);
        if (rc != SQLITE_OK) return rc;

        rc = sqlite3_create_function(db, "sha1", 1, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, (void (*)(sqlite3_context*, int, sqlite3_value**))hash_sha1, 0, 0);
        if (rc != SQLITE_OK) return rc;

        rc = sqlite3_create_function(db, "sha224", 1, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, (void (*)(sqlite3_context*, int, sqlite3_value**))hash_sha224, 0, 0);
        if (rc != SQLITE_OK) return rc;

        rc = sqlite3_create_function(db, "sha256", 1, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, (void (*)(sqlite3_context*, int, sqlite3_value**))hash_sha256, 0, 0);
        if (rc != SQLITE_OK) return rc;

        rc = sqlite3_create_function(db, "sha384", 1, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, (void (*)(sqlite3_context*, int, sqlite3_value**))hash_sha384, 0, 0);
        if (rc != SQLITE_OK) return rc;

        rc = sqlite3_create_function(db, "sha512", 1, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, (void (*)(sqlite3_context*, int, sqlite3_value**))hash_sha512, 0, 0);
        if (rc != SQLITE_OK) return rc;


        rc = sqlite3_create_function(db, "blobmd2", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, (void (*)(sqlite3_context*, int, sqlite3_value**))hash_blobmd2, 0, 0);
        if (rc != SQLITE_OK) return rc;

        rc = sqlite3_create_function(db, "blobmd4", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, (void (*)(sqlite3_context*, int, sqlite3_value**))hash_blobmd4, 0, 0);
        if (rc != SQLITE_OK) return rc;

        rc = sqlite3_create_function(db, "blobmd5", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, (void (*)(sqlite3_context*, int, sqlite3_value**))hash_blobmd5, 0, 0);
        if (rc != SQLITE_OK) return rc;

        rc = sqlite3_create_function(db, "blobsha1", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, (void (*)(sqlite3_context*, int, sqlite3_value**))hash_blobsha1, 0, 0);
        if (rc != SQLITE_OK) return rc;

        rc = sqlite3_create_function(db, "blobsha224", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, (void (*)(sqlite3_context*, int, sqlite3_value**))hash_blobsha224, 0, 0);
        if (rc != SQLITE_OK) return rc;

        rc = sqlite3_create_function(db, "blobsha256", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, (void (*)(sqlite3_context*, int, sqlite3_value**))hash_blobsha256, 0, 0);
        if (rc != SQLITE_OK) return rc;

        rc = sqlite3_create_function(db, "blobsha384", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, (void (*)(sqlite3_context*, int, sqlite3_value**))hash_blobsha384, 0, 0);
        if (rc != SQLITE_OK) return rc;

        rc = sqlite3_create_function(db, "blobsha512", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, (void (*)(sqlite3_context*, int, sqlite3_value**))hash_blobsha512, 0, 0);
        if (rc != SQLITE_OK) return rc;

        return rc;
    }

#ifdef __cplusplus
}
#endif