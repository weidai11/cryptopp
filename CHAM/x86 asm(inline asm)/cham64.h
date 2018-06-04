#pragma once

#include <stdint.h>
#include <string.h>

/*
---------------------------------------------------
cipher		     n      k 	  r	    w     k/w
---------------------------------------------------
CHAM-64/128     64     128    80    16     8
CHAM-128/128    128    128    80    32     4
CHAM-128/256    128    256    96    32     8
-------------------------------------------------
*/

void cham64_setkey(void*, void*);
void cham64_encrypt(void*, void*);
void cham64_decrypt(void*, void*);
