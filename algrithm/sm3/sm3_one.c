#include <stdio.h>
#include <string.h>
#include "sm3.h"

#ifdef CHARSET_EBCDIC
#include "openssl/ebcdic.h"
#endif

unsigned char *SM3(const unsigned char *d, size_t n, unsigned char *md)
	{
	SM3_CTX c;
	static unsigned char m[SM3_DIGEST_LENGTH];

	if (md == NULL) md=m;
	if (!SM3_Init(&c))
		return NULL;
#ifndef CHARSET_EBCDIC
	SM3_Update(&c,d,n);
#else
	{
		char temp[1024];
		unsigned long chunk;

		while (n > 0)
		{
			chunk = (n > sizeof(temp)) ? sizeof(temp) : n;
			ebcdic2ascii(temp, d, chunk);
			SM3_Update(&c,temp,chunk);
			n -= chunk;
			d += chunk;
		}
	}
#endif
	SM3_Final(&c, md);
	return(md);
	}
