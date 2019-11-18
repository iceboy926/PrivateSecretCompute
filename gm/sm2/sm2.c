#include "bn.h"
#include "bnEx.h"
#include "ec_operations.h"
#include "sm2.h"
#include "jvcrypto.h"
#include <stdlib.h>
#include <string.h>

int sm2_encrypt(unsigned char *plaintext, unsigned int plaintext_len, unsigned char *pubkey, unsigned int pubkey_len, unsigned char *cipher, unsigned int *cipher_len)
{
#define CIPHER_LEN (1+2*g_uNumbits/8 + plaintext_len+ HASH_NUMBITS/8)

	unsigned int i;
	int ret = 0;
	unsigned char*	pstr_r=NULL;
	unsigned char*	pstr_s=NULL;
	
	BIGNUM	*x, *y, *one;
	EC_SM2_POINT	*P;

	/* check plaintext */
	if( (plaintext == NULL) || (plaintext_len <= 0) )
	{
		return SM2_ERROR_PLAINTEXT;
	}

	/* check cipher */
	if( cipher == NULL || *cipher_len < CIPHER_LEN )
	{
		return SM2_ERROR_CIPHER;
	}

	/* check pubkey */
	if ( pubkey_len != PUBKEY_LEN || pubkey == NULL )
	{
		return SM2_ERROR_PUBKEY;
	}
	
	/* pubkey[0] must be 0x04 */
	if( pubkey[0] != 0x04 )
	{
		return SM2_ERROR_PUBKEY;
	}

	/* alloc memory */
	pstr_r=(unsigned char*)malloc(g_uNumbits/8);
	pstr_s=(unsigned char*)malloc(g_uNumbits/8);

	x = BN_new();
	y = BN_new();
	one = BN_new();
	P = EC_SM2_POINT_new();

	if ( pstr_r == NULL || pstr_s == NULL ||
		x == NULL || y == NULL || one == NULL || P == NULL)
	{
		return SM2_ERROR_MEMORY_ALLOC;
	}


	/* split pubkey[] to str_r and str_s */
	for (i = 0; i < (g_uNumbits/8); i++) {
		pstr_r[i] = pubkey[1+i];
		pstr_s[i] = pubkey[1+g_uNumbits/8 + i];
	}

	/* string to big number */
	BN_bin2bn(pstr_r, g_uNumbits/8, x);
	BN_bin2bn(pstr_s, g_uNumbits/8, y);

	BN_hex2bn(&one, "1");
	
	/* generate pubkey point P */
	EC_SM2_POINT_set_point(P, x, y, one);
	if (!(ecc_encrypt(cipher, group, G, P, plaintext, plaintext_len)))
	{
		ret = 0;
		*cipher_len = CIPHER_LEN;
#ifdef TEST_FIXED
		/* plaintext_len == 19*/
		*cipher_len = (1+2*g_uNumbits/8 + 19+ HASH_NUMBITS/8);
#endif
	} else
		ret = 1;

	free(pstr_r);
	free(pstr_s);

	BN_free(x);
	BN_free(y);
	BN_free(one);
	EC_SM2_POINT_free(P);

	return ret;
}

int sm2_decrypt(unsigned char *cipher, unsigned int cipher_len, unsigned char *prikey, unsigned int prikey_len, unsigned char *plaintext, unsigned int *plaintext_len)
{

#define PLAIN_LEN (cipher_len - (1+2*g_uNumbits/8 + HASH_NUMBITS/8) )
	int ret = 0;
	BIGNUM *skey;

	if ( (int)PLAIN_LEN <= 0 )
		return SM2_ERROR_CIPHER;

	/* check plaintext */
	if ( plaintext_len == NULL)
		return SM2_ERROR_PLAINTEXT;

	if ( plaintext == NULL || *plaintext_len < (unsigned int)PLAIN_LEN )
	{
		*plaintext_len = PLAIN_LEN;
		return SM2_ERROR_PLAINTEXT;
	}

	/* check cipher */
	if ( cipher == NULL || cipher_len < (1+2*g_uNumbits/8 + HASH_NUMBITS/8) )
	{
		return SM2_ERROR_CIPHER;
	}

	/* cipher[0] must be 0x04 */
	if ( cipher[0] != 0x04 )
	{
		return SM2_ERROR_CIPHER;
	}

	/* check prikey */
	if ( prikey == NULL || prikey_len != g_uNumbits/8 )
	{
		return SM2_ERROR_PRIKEY;
	}

	skey = BN_new();
	if (skey == NULL)
      		return SM2_ERROR_MEMORY_ALLOC;

	/* string to big number */
	BN_bin2bn(prikey, g_uNumbits/8, skey);
	if (!(ecc_decrypt(plaintext, group, cipher, cipher_len, skey)))
	{
		*plaintext_len = PLAIN_LEN;
		ret = 0;
	} else {
		*plaintext_len = 0;
		ret = 1;
	}

	BN_free(skey);
	return ret;
}



int sm2_signature(unsigned char *digest, unsigned int digest_len,
		      unsigned char *prikey, unsigned int prikey_len, 
		      unsigned char *sig, unsigned int *sig_len)
{
	int ret = 0;
	BIGNUM *skey;


	/* check sig */
	if( sig == NULL )
		return SM2_ERROR_SIG;

	if( *sig_len < 2*g_uSCH_Numbits/8 )
	{
		*sig_len = 2*g_uSCH_Numbits/8;
		return SM2_ERROR_SIG;
	}

	/* check digest */
	if( digest==NULL || digest_len != g_uSCH_Numbits/8 )
		return SM2_ERROR_DIGEST;

	/* check prikey */
	if ( prikey == NULL || prikey_len != g_uNumbits/8 )
		return SM2_ERROR_PRIKEY;

	skey = BN_new();


	if ( skey == NULL )
    {
        return SM2_ERROR_MEMORY_ALLOC;
    }

	/* string to big number */
	BN_bin2bn(prikey, g_uNumbits/8, skey);

	if (!(ecc_signature(sig, group, G, skey, digest)))
	{
		*sig_len = 2*g_uSCH_Numbits/8;
		ret = 0;
	} else {
		*sig_len = 0;
		ret = 1;
	}


	BN_free(skey);


	return ret;
}


int sm2_verify(unsigned char *digest, unsigned int digest_len, unsigned char *sig, unsigned int sig_len, unsigned char *pubkey, unsigned int pubkey_len)
{
	unsigned int i;
	int ret = 0;
	unsigned char*	pstr_r = NULL;
	unsigned char*	pstr_s = NULL;
	
	BIGNUM	*x, *y, *one;
	EC_SM2_POINT	*P;
	
	/* check digetst */
	if( digest==NULL || digest_len != g_uSCH_Numbits/8 )
		return SM2_ERROR_DIGEST;

	/* check sig */
	if ( sig == NULL || sig_len != 2 * (g_uNumbits/8) )
		return SM2_ERROR_SIG;

	/* check pubkey */
	if ( pubkey == NULL || pubkey_len != PUBKEY_LEN )
		return SM2_ERROR_PUBKEY;

	if( pubkey[0] != 0x04 )
		return SM2_ERROR_PUBKEY;

	x = BN_new();
	y = BN_new();
	one = BN_new();
	P = EC_SM2_POINT_new();

	pstr_r = (unsigned char*)malloc(g_uNumbits/8);
	pstr_s = (unsigned char*)malloc(g_uNumbits/8);

	if ( x == NULL || y == NULL || one == NULL || P == NULL || pstr_r == NULL || pstr_s == NULL )
		return SM2_ERROR_MEMORY_ALLOC;

	/* split pubkey to str_r and str_s */
	for (i = 0; i < (g_uNumbits/8); i++) 
	{
		pstr_r[i] = pubkey[1+i];
		pstr_s[i] = pubkey[1+g_uNumbits/8 + i];
	}

	/* string to big number */
	BN_bin2bn(pstr_r, g_uNumbits/8, x);
	BN_bin2bn(pstr_s, g_uNumbits/8, y);

	BN_hex2bn(&one, "1");
   
	/* generate publio point P */
	EC_SM2_POINT_set_point(P, x, y, one);
	if (!(ecc_verify(group, G, P, digest, sig)))
		ret = 0;
	else
		ret = 1;
  
	BN_free(x);
	BN_free(y);
	BN_free(one);
	EC_SM2_POINT_free(P);
		
	free(pstr_r);
	free(pstr_s);
		
	return ret;
}


int sm2_string_is_odd(unsigned char *string,  unsigned int len)
{
	int iret;
	BIGNUM	*x;
	
	x = BN_new();
	if( x == NULL )
		return SM2_ERROR_MEMORY_ALLOC;

	BN_bin2bn(string, len, x);

	iret = BN_is_odd(x);

	BN_free(x);

	return iret;
}


int sm2_is_point_valid(unsigned char *point, unsigned int point_len)
{
#define	UNCOMP_LEN		(1 + 2*g_uNumbits/8)

	unsigned char *pstr_x = NULL;
	unsigned char *pstr_y = NULL;

	int bret;

	if( point_len != UNCOMP_LEN )
	{
		return 0;
	}

	if( (pstr_x = (unsigned char*)malloc(g_uNumbits/8)) == NULL )
	{
		return FALSE;
	}
	if( (pstr_y = (unsigned char*)malloc(g_uNumbits/8)) == NULL )
	{
		free(pstr_x);
		return FALSE;
	}

	if( point[0]!= 04 )
	{
		free(pstr_x);
		free(pstr_y);
		return FALSE;
	}

	memcpy( pstr_x, &point[1], g_uNumbits/8 );
	memcpy( pstr_y, &point[1+g_uNumbits/8], g_uNumbits/8 );
	

	{
		BIGNUM	*x, *y, *z;
		EC_SM2_POINT *P;

		x = BN_new();
		y = BN_new();
		z = BN_new();
		P = EC_SM2_POINT_new();

		BN_bin2bn(pstr_x, g_uNumbits/8, x);
		BN_bin2bn(pstr_y, g_uNumbits/8, y);
		BN_hex2bn(&z, "1");

		EC_SM2_POINT_set_point(P, x, y, z);
		bret = EC_SM2_POINT_is_on_curve(group, P);

		BN_free(x);
		BN_free(y);
		BN_free(z);
		EC_SM2_POINT_free(P);
	}

	free(pstr_x);
	free(pstr_y);

	return bret;
}
