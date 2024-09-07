#pragma once

#include <inttypes.h>
#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace std;

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#ifdef WIN32
#include <windows.h>
#endif

#include <sqlite3ext.h> /* Do not use <sqlite3.h>! */

#include "util.h"
#include "algorithms.h"
#include "digestsize.h"

#include "md2.h"
#include "md4.h"
#include "md5.h"
#include "sha.h"
#include "crypto_hashing.h"