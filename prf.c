#include "prf.h"
#include "jvcrypto.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*

P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                             HMAC_hash(secret, A(2) + seed) +
                             HMAC_hash(secret, A(3) + seed) + ...
                             
PRF(secret, label, seed) = P_<hash>(secret, label + seed)

说明
	+  代表连接
	A() 表示如下
         A(0) = seed
         A(i) = HMAC_hash(secret, A(i-1))
    hash指的是单向hash函数，如sha1，sha256等等。
    以sha256为例，一次HMAC产生的数据为32bytes。因此，如果想得到80bytes数据，
    需要i=3，这样会得到96bytes数据，将后16bytes丢弃即可。
    label必须是ASCII字符串，不包含结尾的'\0'。
    
*/

// for all hash alg B is 64
//ipad = the byte 0x36 repeated B times
//opad = the byte 0x5C repeated B times.
// if Klen < 64 than append zeros to the end of K to create a B byte string
// else if Klen > 64  than  hash(ken) get len < 64
//H(K XOR opad, H(K XOR ipad, text))      
//
int hash_mac(unsigned char *outdata, unsigned char *key, int keylen, unsigned char *txt, int txtlen)
{
	unsigned char k_ipad[65] = {0};    /* inner padding * key XORd with ipad*/
    unsigned char k_opad[65] = {0};    /* outer padding -* key XORd with opad*/
    unsigned char tk[35] = {0};
    int i = 0;
    unsigned int tklen = sizeof(tk);
    unsigned char digest[33] = {0};
    unsigned int digestlen = sizeof(digest);
    
     /* if key is longer than 64 bytes reset it to key=sm3(key) */
    if (keylen > 64){
        
        jvc_sm3(key, keylen, tk, &tklen);

        key = tk;
        keylen = 32;
    }

    /*
         * the HMAC_SM3 transform looks like:
         *
         * SM3(K XOR opad, SM3(K XOR ipad, text))
         *
         * where K is an n byte key
         * ipad is the byte 0x36 repeated 64 times
         * opad is the byte 0x5c repeated 64 times
         * and text is the data being protected
    */

     memset( k_ipad, 0, sizeof(k_ipad));
     memset( k_opad, 0, sizeof(k_opad));
     memcpy( k_ipad, key, keylen);
     memcpy( k_opad, key, keylen);

    for (i=0; i<64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    /*
    * perform inner SM3
    * SM3(K XOR ipad, text)
    */
    jvc_sm3_update(k_ipad, 64, txt, txtlen, digest, &digestlen);

    /*
    * perform outer SM3
    * SM3(K XOR opad, digest)
    */
    
    jvc_sm3_update(k_opad, 64, digest, digestlen, outdata, &digestlen);
   
    return 0;
}

// A(0) = seed
// A(1) = HMAC_hash(secret, A(0))
//P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +HMAC_hash(secret, A(2) + seed) +HMAC_hash(secret, A(3) + seed) + ...
int  prf(/*out*/unsigned char *outdata, /*in*/int outlen, /*in*/unsigned char *secret, /*in*/ int secretlen, /*in*/unsigned char *seed, /*in*/ int seedlen)
{
	int ct, i, left;
	//unsigned char T[1024];
	//unsigned int T_len = sizeof(T);
	unsigned char A_Temp[1024] = {0};
	int a_temp_len = sizeof(A_Temp);
	unsigned char digest[33] = {0};
	unsigned char *pOut = outdata;


	ct = outlen/SM3_DIGEST_LEN;

    left = outlen%SM3_DIGEST_LEN;

    //
    if(seedlen > sizeof(A_Temp)-32)
    {
        return -1;
    }

    memcpy(A_Temp, seed, seedlen);
    a_temp_len = seedlen;
    
    for(i =0; i < ct; i++)
    {
    	memset(digest, 0, sizeof(digest));
        hash_mac(digest, secret, secretlen, A_Temp, a_temp_len);
        memset(A_Temp, 0, sizeof(A_Temp));
        a_temp_len = 0;
        memcpy(A_Temp, digest, 32);
        memcpy(A_Temp + 32, seed, seedlen);
        a_temp_len = 32 + seedlen;
        memcpy(pOut, digest, 32);
        pOut += 32;

    }
    
    if(left)
    {
    	hash_mac(digest, secret, secretlen, A_Temp, a_temp_len);
    	memcpy(pOut, digest, left);
    }
    

	return 0;
}





