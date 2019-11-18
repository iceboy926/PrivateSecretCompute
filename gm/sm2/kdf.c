#include "ec_operations.h"
#include "kdf.h"
#include "jvcrypto.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
//#include "crypto.h"

int kdf(/*out*/unsigned char *mask, /*in*/int klen, /*in*/unsigned char *z, /*in*/ int zlen)
{
#define hLen (HASH_NUMBITS/8)
	int ct;
	unsigned char T[hLen];
	unsigned int T_len = hLen;
	int k;
	unsigned char *seed;
	unsigned int mask_len = 32;

	seed = (unsigned char*)malloc(zlen+4);
	if( seed == 0 )
	{
		return 1;
	}
	memset(seed, 0, zlen+4);
	memcpy(seed, z, zlen);

	for(ct=0;ct<(klen/hLen);ct++)
	{
		seed[zlen]=(unsigned char)((ct+1)>>24);
		seed[zlen+1]=(unsigned char)((ct+1)>>16);
		seed[zlen+2]=(unsigned char)((ct+1)>>8);
		seed[zlen+3]=(unsigned char)(ct+1);
		jvc_sm3(seed, zlen+4, &mask[ct*32], &mask_len);
	}

	if(klen%hLen !=0)
	{
		seed[zlen]=(unsigned char)((ct+1)>>24);
		seed[zlen+1]=(unsigned char)((ct+1)>>16);
		seed[zlen+2]=(unsigned char)((ct+1)>>8);
		seed[zlen+3]=(unsigned char)(ct+1);
		jvc_sm3(seed, zlen+4, T, &T_len);
		for(ct=ct*hLen,k=0;ct<klen;ct++,k++)
			mask[ct]=T[k];
	}

	free(seed);
	return 0;
}

/**
  param1-aaid : 004A#FFF1
  param2-ta guid: 30ab36e4-7b93-4e5f-98c7-5a62ccd24e35
  param3-:purpose(1-AuthenticatorKey  2-ProtectKey 3-AdminVerifyKey)

*/

int generate_key(/*out*/unsigned char *outdata,  /*in*/unsigned char *param1, /*in*/ int param1len,/*in*/unsigned char *param2, /*in*/ int param2len, /*in*/unsigned char *param3, /*in*/ int param3len)
{
	unsigned char szData[1024] = {0};
	unsigned char digest[40] = {0};
	unsigned int datalen = 0;
	unsigned int digestlen = 32;
	unsigned char szmask2[128] = {0};
	unsigned char szmask4[128] = {0};
	int klen = 128;
    //1 Hash (param1 || param2)
    
    memcpy(szData, param1, param1len);
    memcpy(szData+param1len, param2, param2len);
    datalen = param1len+param2len;
    jvc_sm3(szData, datalen, digest, &digestlen);

    //2 kdf (hash1||param3)
    memset(szData, 0, sizeof(szData));
    memcpy(szData, digest, digestlen);
    memcpy(szData + digestlen, param3, param3len);
    datalen = digestlen+param3len;
    kdf(szmask2, klen, szData, datalen);

    //3 Hash (param2 || param3)
    memset(szData, 0, sizeof(szData));
    memcpy(szData, param2, param2len);
    memcpy(szData+param2len, param3, param3len);
    datalen = param2len+param3len;
    memset(digest, 0, sizeof(digest));
    jvc_sm3(szData, datalen, digest, &digestlen); 

    //4 kdf(hash2||param1)
    memset(szData, 0, sizeof(szData));
    memcpy(szData, digest, digestlen);
    memcpy(szData + digestlen, param1, param1len);
    datalen = digestlen+param1len;
    kdf(szmask4, klen, szData, datalen);

    // hash(kdf2||kdf4)
    memset(szData, 0, sizeof(szData));
    memcpy(szData, szmask2, klen);
    memcpy(szData + klen, szmask4, klen);
    memset(digest, 0, sizeof(digest));
    jvc_sm3(szData, klen*2, digest, &digestlen);
    //output(32byte)

    memcpy(outdata, digest, digestlen);

    return 0;

}




