#include "jvcrypto.h"
#include "sm2.h"
#include "sm3.h"
#include "sm4.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
//#include "crypto.h"

#define JVC_VERSION     "2.0.1"

void jvc_logger(const char *str)
{
	if(str == NULL)
		return ;
//#if 1
	printf("%s \n",str);
//#endif
}

/*
 * function：		init jvcrypto lib such as curve arguments and memory. Default curve is recommend one.
 * arguments:		null.
 * return value:	0 for success.  non-zero for error code.
 */
int jvc_init()
{
	int ret = 0;
	//jvc_logger("jvc_init() start");
	ret = sm2_init();
	//jvc_logger("jvc_init() finish");
	return ret;
}

/*
 * function：	 	release the lib such as curve arguments and memory.
 * arguments:		null.
 * return value:	null.
 */
void jvc_release()
{
	//jvc_logger("jvc_release() start");
	sm2_release();
	//jvc_logger("jvc_release() finish");
}


/*
 * function：	 	get jvcrypto lib’ version.
 * arguments:		version, input/output args, buffer pointer to store version info.
 * 			length, input args, the length of buffer version.
 * return value:	0 for success. version may be “1.0.0.13”, if length is smaller than 12 or version is null , JV
 * 			JVC_ERROR_VERSION_BUFFER returned.
 */
int jvc_getversion(char *version, unsigned int length)
{
	int ret = 0;
	int default_version_len = strlen(JVC_VERSION);

	jvc_logger("jvc_getversion() start");

	if (version == NULL || length < 10) {
		ret = JVC_ERROR_VERSION_BUFFER;
		goto out;
	}
	
	memcpy(version, JVC_VERSION, default_version_len);
out:
	jvc_logger("jvc_getversion() finish");

	return ret;
}

/*
 * function：	 	generate sm2 key, includes public key and private key.
 * arguments:		prikey, input/output args, private key of sm2.
 * 			prikey_len, input/output args, the length of private key. Default 32 returned.
 * 			pubkey, input/output args, private key of sm2.
 * 			pubkey_len, input/output args, the length of public key. Default 65 returned.
 * return value:	0 for success.  non-zero for error code.
 */
int jvc_sm2_gen_key(unsigned char *prikey, unsigned int *prikey_len, unsigned char *pubkey, unsigned int *pubkey_len)
{
	int ret = 0;

	//jvc_logger("jvc_sm2_gen_key() start");

	if (prikey_len == NULL) {
		ret = SM2_ERROR_PRIKEY;
		goto out; 
	}

	if (prikey == NULL || *prikey_len < SM2_PRIKEY_LEN) {
		ret = SM2_ERROR_PRIKEY;
		*prikey_len = SM2_PRIKEY_LEN;
		goto out; 
	}

	if (pubkey_len == NULL) {
		ret = SM2_ERROR_PUBKEY;
		goto out; 
	}

	if (pubkey == NULL || *pubkey_len < SM2_PUBKEY_LEN) {
		ret = SM2_ERROR_PUBKEY;
		*pubkey_len = SM2_PUBKEY_LEN;
		goto out; 
	}

	ret = sm2_genkey(prikey, prikey_len, pubkey, pubkey_len);

out:
	//jvc_logger("jvc_sm2_gen_key() finish");

	return ret;
}

/*
 * function：	 	verify that if public key and private key are matched.
 * arguments:		prikey, input args, private key of sm2.
 * 			prikey_len, input args, the length of private key. Default is 32.
 * 			pubkey, input args, private key of sm2.
 * 			pubkey_len, input args, the length of public key. Default is 65.
 * return value:	0 for success.  non-zero for error code.
 */
int jvc_sm2_is_key_match(const unsigned char *prikey, const unsigned int prikey_len,
                         const unsigned char *pubkey, const unsigned int pubkey_len)
{
	int ret = 0;

	//jvc_logger("jvc_sm2_is_key_match() start");

	if (prikey == NULL || prikey_len != SM2_PRIKEY_LEN) {
		ret = SM2_ERROR_PRIKEY;
		goto out; 
	}

	if (pubkey == NULL || pubkey_len != SM2_PUBKEY_LEN) {
		ret = SM2_ERROR_PUBKEY;
		goto out; 
	}

	ret = sm2_is_key_match(prikey, prikey_len, pubkey, pubkey_len);
	if (ret != 0) ret = SM2_ERROR_KEY_DISMATCH;
out:
	//jvc_logger("jvc_sm2_is_key_match() finish");

	return ret;
}

/*
 * function:	 	get sm2 pubkey from prikey.
 * arguments: 		pubkey, input args, public key buffer.
 * 			pubkey_len, input/ourt args, the length of public key.
 * 			prikey, input/ouput args, private key buffer.
 * 			prikey_len, input args, the length of prikey_len.
 * return value:	0 for success.  non-zero for error code.
 */
int jvc_sm2_get_pubkey_from_prikey(unsigned char *pubkey, unsigned int *pubkey_len, unsigned char *prikey, unsigned int prikey_len)
{
	int ret = 0;

	//jvc_logger("sm2_point_from_privatekey() start");

	if (prikey == NULL || prikey_len != SM2_PRIKEY_LEN) {
		ret = SM2_ERROR_PRIKEY;
		jvc_logger("sm2_point_from_privatekey() SM2_ERROR_PRIKEY");
		goto out; 
	}

	if (pubkey == NULL || *pubkey_len < SM2_PUBKEY_LEN) {
		ret = SM2_ERROR_PUBKEY;
		jvc_logger("sm2_point_from_privatekey() SM2_ERROR_PUBKEY");
		goto out; 
	}

	ret = sm2_point_from_privatekey(prikey, prikey_len, pubkey, pubkey_len);
out:
	//jvc_logger("sm2_point_from_privatekey() finish");

	return ret;
}

/*
 * function：	 	encrypt sm2 plaintext by pubkey
 * arguments:		plaintext, input args, plaintext needs to be encrypted.
 * 			plaintext_len, input args, the length of plaintext.
 * 			pubkey, input args, public key used to encrypt plaintext.
 * 			pubkey_len, input args, the length of public key. Default is 65.
 * 			ciphertext, input/ouput args, cipher buffer for encrypted plaintext
 * 			ciphertext_len, input/output args, the length of ciphertext buffer.
 * return value:	0 for success.  non-zero for error code.
 */
int jvc_sm2_encrypt(unsigned char *plaintext, unsigned int plaintext_len, unsigned char *pubkey, unsigned int pubkey_len, unsigned char *ciphertext, unsigned int *ciphertext_len)
{
	int ret = 0;

	jvc_logger("jvc_sm2_encrypt() start");

	ret = sm2_encrypt(plaintext, plaintext_len, pubkey, pubkey_len, ciphertext, ciphertext_len);

	jvc_logger("jvc_sm2_encrypt() finish");

	return ret;
}

/*
 * function：	 	decrypt sm2 ciphertext by prikey.
 * arguments:		ciphertext, input args, ciphertext needs to be decrypted.
 * 			ciphertext_len, input args, the length of ciphertext.
 * 			prikey, input args, private key used to decrypt ciphertext.
 * 			prikey_len, input args, the length of private key. Default is 32.
 * 			plaintext, input/ouput args, plain buffer for decrypted ciphertext.
 * 			plaintext_len, input/output args, the length of plaintext buffer.
 * return value:	0 for success.  non-zero for error code.
 */
int jvc_sm2_decrypt(unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *prikey, unsigned int prikey_len, unsigned char *plaintext, unsigned int *plaintext_len)
{
	int ret = 0;

	jvc_logger("jvc_sm2_decrypt() start");

	ret = sm2_decrypt(ciphertext, ciphertext_len, prikey, prikey_len, plaintext, plaintext_len);

	jvc_logger("jvc_sm2_decrypt() finish");

	return ret;
}



/*
 * function：		sign data by sm2 private key.
 * arguments:		data, input args, the data to be signed.
 * 			data_len, input args, the length of data. Must <= SM2_MAX_DATA_LEN.
 * 			prikey, input args, private key string buffer.
 * 			prikey_len, input args, the length of private key. Default is 32.
 * 			sig, input/output args, buffer to store the sm2 signature of data.
 * 			sig_len, input/output args, the length of sig buffer. Default 64 returned.
 * return value:	0 for success. non-zero for error code.
 */
int jvc_sm2_sign(unsigned char *data, unsigned int data_len,
		 unsigned char *prikey, unsigned int prikey_len,
		 unsigned char *sig, unsigned int *sig_len)
{
	int ret = 0;
	
	/* hard coding , but don't fix now. perhaps next release.*/
	//char id[18] = "ALICE123@YAHOO.COM";
	char id[16] = "1234567812345678";
	//unsigned char entla[2] = {0x00, 0x90};
	unsigned char entla[2] = {0x00, 0x80};
/*
	unsigned char a[32] = {0x78, 0x79, 0x68, 0xB4, 0xFA, 0x32, 0xC3, 0xFD, 
		0x24, 0x17, 0x84, 0x2E, 0x73, 0xBB, 0xFE, 0xFF,
		0x2F, 0x3C, 0x84, 0x8B, 0x68, 0x31, 0xD7, 0xE0,
		0xEC, 0x65, 0x22, 0x8B, 0x39, 0x37, 0xE4, 0x98};
	unsigned char b[32] = {0x63, 0xE4, 0xC6, 0xD3, 0xB2, 0x3B, 0x0C, 0x84,
		0x9C, 0xF8, 0x42, 0x41, 0x48, 0x4B, 0xFE, 0x48, 
		0xF6, 0x1D, 0x59, 0xA5, 0xB1, 0x6B, 0xA0, 0x6E, 
		0x6E, 0x12, 0xD1, 0xDA, 0x27, 0xC5, 0x24, 0x9A};
	unsigned char xg[32] = {0x42, 0x1D, 0xEB, 0xD6, 0x1B, 0x62, 0xEA, 0xB6, 
		0x74, 0x64, 0x34, 0xEB, 0xC3, 0xCC, 0x31, 0x5E, 
		0x32, 0x22, 0x0B, 0x3B, 0xAD, 0xD5, 0x0B, 0xDC,
		0x4C, 0x4E, 0x6C, 0x14, 0x7F, 0xED, 0xD4, 0x3D};
	unsigned char yg[32] = {0x06, 0x80, 0x51, 0x2B, 0xCB, 0xB4, 0x2C, 0x07,
		0xD4, 0x73, 0x49, 0xD2, 0x15, 0x3B, 0x70, 0xC4,
		0xE5, 0xD7, 0xFD, 0xFC, 0xBF, 0xA3, 0x6E, 0xA1, 
		0xA8, 0x58, 0x41, 0xB9, 0xE4, 0x6E, 0x09, 0xA2};
*/
	/*       
	unsigned char pubkey_xa[32] = {0x0A, 0xE4, 0xC7, 0x79, 0x8A, 0xA0, 0xF1, 0x19,
	0x47, 0x1B, 0xEE, 0x11, 0x82, 0x5B, 0xE4, 0x62,
	0x02, 0xBB, 0x79, 0xE2, 0xA5, 0x84, 0x44, 0x95,
	0xE9, 0x7C, 0x04, 0xFF, 0x4D, 0xF2, 0x54, 0x8A};
	unsigned char pubkey_ya[32] = {0x7C, 0x02, 0x40, 0xF8, 0x8F, 0x1C, 0xD4, 0xE1,
	0x63, 0x52, 0xA7, 0x3C, 0x17, 0xB7, 0xF1, 0x6F,
	0x07, 0x35, 0x3E, 0x53, 0xA1, 0x76, 0xD6, 0x84,
	0xA9, 0xFE, 0x0C, 0x6B, 0xB7, 0x98, 0xE8, 0x57};
	*/

	unsigned char sm2_par_dig[128] =
	{
    		0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
    		0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
    		0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
    		0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
    		0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
    		0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
    		0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
	};

	unsigned char string[212];
	unsigned char digest[SM2_MAX_DATA_LEN + 33];
	unsigned char pubkey[SM2_PUBKEY_LEN + 1];
	unsigned int pubkey_len = SM2_PUBKEY_LEN + 1;
	unsigned int digest_len = SM2_MAX_DATA_LEN + 32;

	//jvc_logger("jvc_sm2_sign() start");

	if ( prikey == NULL || prikey_len != SM2_PRIKEY_LEN) {
		ret = SM2_ERROR_PRIKEY;
		goto out;
	}

	if ( data == NULL ) {
		ret = SM2_ERROR_MESSAGE;
		goto out;
	}

	if ( data_len > SM2_MAX_DATA_LEN || data_len == 0 )
	{
		ret = SM2_ERROR_MESSAGE;
		jvc_logger("data_len > SM2_MAX_DATA_LEN");
		goto out;
	}

	memcpy(string, entla, 2);
	memcpy(string+2, id, 16);
/*
	memcpy(string+20, a, 32);
	memcpy(string+52, b, 32);
	memcpy(string+84, xg, 32);
	memcpy(string+116, yg, 32);
*/
	memcpy(string+18, sm2_par_dig, 128);
	ret = sm2_point_from_privatekey(prikey, prikey_len, pubkey, &pubkey_len);
	if( ret == 1 )
	{
		jvc_logger("jvc_sm2_sign() : sm2_point_from_privatekey failed.");
		goto out;
	}

	memcpy(string+146, pubkey+1, pubkey_len-1);
	/*
	memcpy(string+148, pubkey_xa, 32);
	memcpy(string+180, pubkey_ya, 32);
	*/
	jvc_sm3(string, 210, digest, &digest_len); //Computes  id_Z = sm3(id_bit_length||id||ECC_a||ECC_b||ECC_BaseX||ECC_BaseY||PubX||PubY)

	memcpy(digest+32, data, data_len);
	jvc_sm3(digest, 32+data_len, digest, &digest_len);

	ret = sm2_signature(digest, 32, prikey, prikey_len, sig, sig_len);
out:
	//jvc_logger("jvc_sm2_sign() finish");
	memset(digest, 0, sizeof(digest));
	return ret;
}

/*
 * function：		verify the signature of the data signed by sm2 key handle.
 * arguments:		data, input args, the data to be signed.
 * 			data_len, input args, the length of data. Must <= SM2_MAX_DATA_LEN.
 * 			sig, input args, the sm2 signature of data.
 * 			sig_len, input args, the length of sig. Default is 64.
 * 			pubkey, input args, public key string buffer.
 * 			pubkey_len, input args, the length of public key. Default is 65.
 * return value:	0 for success. -1 for verify failed, other non-zero for error code.
 */
int jvc_sm2_verify(unsigned char *data, unsigned int data_len, unsigned char *sig, unsigned int sig_len, unsigned char *pubkey, unsigned int pubkey_len)
{
	int ret = 0;

	/* hard coding , but don't fix now. perhaps next release.*/
	/*
	char id[18] = "ALICE123@YAHOO.COM";
	unsigned char entla[2] = {0x00, 0x90};
	unsigned char a[32] = {0x78, 0x79, 0x68, 0xB4, 0xFA, 0x32, 0xC3, 0xFD,
		0x24, 0x17, 0x84, 0x2E, 0x73, 0xBB, 0xFE, 0xFF,
		0x2F, 0x3C, 0x84, 0x8B, 0x68, 0x31, 0xD7, 0xE0,
		0xEC, 0x65, 0x22, 0x8B, 0x39, 0x37, 0xE4, 0x98};
	unsigned char b[32] = {0x63, 0xE4, 0xC6, 0xD3, 0xB2, 0x3B, 0x0C, 0x84,
		0x9C, 0xF8, 0x42, 0x41, 0x48, 0x4B, 0xFE, 0x48,
		0xF6, 0x1D, 0x59, 0xA5, 0xB1, 0x6B, 0xA0, 0x6E,
		0x6E, 0x12, 0xD1, 0xDA, 0x27, 0xC5, 0x24, 0x9A};
	unsigned char xg[32] = {0x42, 0x1D, 0xEB, 0xD6, 0x1B, 0x62, 0xEA, 0xB6,
		0x74, 0x64, 0x34, 0xEB, 0xC3, 0xCC, 0x31, 0x5E,
		0x32, 0x22, 0x0B, 0x3B, 0xAD, 0xD5, 0x0B, 0xDC,
		0x4C, 0x4E, 0x6C, 0x14, 0x7F, 0xED, 0xD4, 0x3D};
	unsigned char yg[32] = {0x06, 0x80, 0x51, 0x2B, 0xCB, 0xB4, 0x2C, 0x07,
		0xD4, 0x73, 0x49, 0xD2, 0x15, 0x3B, 0x70, 0xC4,
		0xE5, 0xD7, 0xFD, 0xFC, 0xBF, 0xA3, 0x6E, 0xA1,
		0xA8, 0x58, 0x41, 0xB9, 0xE4, 0x6E, 0x09, 0xA2};
	*/
	/*
	unsigned char pubkey_xa[32] = {0x0A, 0xE4, 0xC7, 0x79, 0x8A, 0xA0, 0xF1, 0x19,
	0x47, 0x1B, 0xEE, 0x11, 0x82, 0x5B, 0xE4, 0x62,
	0x02, 0xBB, 0x79, 0xE2, 0xA5, 0x84, 0x44, 0x95,
	0xE9, 0x7C, 0x04, 0xFF, 0x4D, 0xF2, 0x54, 0x8A};
	unsigned char pubkey_ya[32] = {0x7C, 0x02, 0x40, 0xF8, 0x8F, 0x1C, 0xD4, 0xE1,
	0x63, 0x52, 0xA7, 0x3C, 0x17, 0xB7, 0xF1, 0x6F,
	0x07, 0x35, 0x3E, 0x53, 0xA1, 0x76, 0xD6, 0x84,
	0xA9, 0xFE, 0x0C, 0x6B, 0xB7, 0x98, 0xE8, 0x57};
	*/

	char id[16] = "1234567812345678";
	unsigned char entla[2] = {0x00, 0x80};

        unsigned char sm2_par_dig[128] =
        {
                0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
                0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
                0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
                0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
                0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
                0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
                0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
        };

	unsigned char string[256] = {0};
	unsigned char digest[33] = {0};
	unsigned int digest_len = 33;

	//PRINT_INFO("jvc_sm2_verify() start");

        if ( pubkey == NULL || pubkey_len != SM2_PUBKEY_LEN) {
                ret = SM2_ERROR_PUBKEY;
                goto out;
        }

        if ( data == NULL ) {
                ret = SM2_ERROR_MESSAGE;
                goto out;
        }

        if ( data_len == 0 )
        {
                ret = SM2_ERROR_MESSAGE;
                goto out;
        }

	memcpy(string, entla, 2);
	memcpy(string+2, id, 16);
	memcpy(string+18, sm2_par_dig, 128);
	memcpy(string+146, pubkey+1, pubkey_len-1);

	jvc_sm3(string, 210, digest, &digest_len);


    memset(string, 0, sizeof(string));
    memcpy(string, digest, digest_len);

    memset(digest, 0, sizeof(digest));
    jvc_sm3_update(string, digest_len, data, data_len, digest, &digest_len);
	
	//memcpy(digest+32, data, data_len);

	//jvc_sm3(digest, 32+data_len, digest, &digest_len);

	//CAL_HexDump("digest is ", digest, digest_len);
	//CAL_HexDump("sig is ", sig, sig_len);
	//CAL_HexDump("pubkey is ", pubkey, pubkey_len);

	ret = sm2_verify(digest, digest_len, sig, sig_len, pubkey, pubkey_len);
out:
	//PRINT_INFO("jvc_sm2_verify() finish, ret = %d", ret);

	memset(digest, 0, sizeof(digest));

	return ret;
}



int jvc_sm3_update(unsigned char *data1, unsigned int data1_len, unsigned char *data2, unsigned int data2_len, unsigned char *digest, unsigned int *digest_len)
{
	int ret = 0;
	SM3_CTX c;
	int blocklen = 40000;
	int n = data2_len;
	unsigned char *temp = (unsigned char *)data2;

	if ( digest == NULL )
	{
		*digest_len = SM3_DIGEST_LEN;
		ret = SM3_ERROR_NULLDIGEST;
		goto out;
	}

	if ( data1 == NULL || data1_len == 0 )
	{
		ret = SM3_ERROR_DATA;
		goto out;
	}

	if ( data2 == NULL || data2_len == 0 )
	{
		ret = SM3_ERROR_DATA;
		goto out;
	}


	if (!SM3_Init(&c))
	{
		jvc_logger("jvc_sm3() finish");
		ret = SM3_ERROR_INTERNAL;
		goto out;
	}


	SM3_Update(&c,data1,data1_len);

	while (n > 0)
	{   
		if(n < blocklen)
			blocklen = n;
		SM3_Update(&c,temp,blocklen);
		n -= blocklen;
		temp += blocklen;
	}


	SM3_Final(&c,digest);


out:

	*digest_len = SM3_DIGEST_LEN;

	//jvc_logger("jvc_sm3() finish");

	return ret;
}


/*
 * function：		compute the sm3 hash value of the given data string.
 * arguments:		data, input args, the data to be hashed.
 * 			data_len, input args, the length of data.
 * 			digest, input/output args, the hash value buffer with at least 32 bytes.
 * 			digest_len, input/output args, the length of buffer digest.
 * return value:	0 for success. other non-zero for error code.
 */
int jvc_sm3(unsigned char *data, unsigned int data_len, unsigned char *digest, unsigned int *digest_len)
{
	int ret = 0;
	SM3_CTX c;
	unsigned char *d = (unsigned char *)data;
	size_t n = data_len;

	//jvc_logger("jvc_sm3() start");
	
	if ( digest == NULL )
	{
		*digest_len = SM3_DIGEST_LEN;
		ret = SM3_ERROR_NULLDIGEST;
		goto out;
	}

	if ( data == NULL || data_len == 0 )
	{
		ret = SM3_ERROR_DATA;
		goto out;
	}

	if (!SM3_Init(&c))
	{
		jvc_logger("jvc_sm3() finish");
		return SM3_ERROR_INTERNAL;
	}
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
	SM3_Final(&c,digest);

	//OPENSSL_cleanse(&c,sizeof(c)); /* security consideration */
out:

	*digest_len = SM3_DIGEST_LEN;

	//jvc_logger("jvc_sm3() finish");

	return ret;
}


extern void print_hex(uint8_t *label, uint8_t *data, uint16_t data_len);

int jvc_sm2_selftest()
{
	 //the private key
    unsigned char privatekey[32]={0x39,0x45,0x20,0x8f,0x7b,0x21,0x44,0xb1,0x3f,0x36,0xe3,0x8a,0xc6,0xd3,0x9f,
        0x95,0x88,0x93,0x93,0x69,0x28,0x60,0xb5,0x1a,0x42,0xfb,0x81,0xef,0x4d,0xf7,0xc5,0xb8};
    //unsigned char privatekey[SM2_PRIKEY_LEN] = {0};
    unsigned int privatekeylen = sizeof(privatekey);

    unsigned char publickey[SM2_PUBKEY_LEN] = {0};
    unsigned int publickeylen = sizeof(publickey);

    unsigned char sign[128] = {0};
    unsigned int signlen = sizeof(sign);

    unsigned char message[15] = {0};
    unsigned int len = sizeof(message);

    int temp = 0;

    temp = jvc_init();
    if(temp)
    {
        jvc_logger("jvc_init error");
    	return 1;
    }
    
    strcpy(message, "message");
    
    len = strlen(message);
 
    temp = jvc_sm2_get_pubkey_from_prikey(publickey, &publickeylen, privatekey, privatekeylen);
    //temp = jvc_sm2_gen_key(privatekey, &privatekeylen, publickey, &publickeylen);
    //temp = jvc_sm2_gen_key(privatekey, &privatekeylen, publickey, &publickeylen);
    if(temp)
    {
        jvc_logger("jvc_sm2_gen_key error");
        jvc_release();
    	return 1;
    }
    
    print_hex("pubkey is", publickey, publickeylen);

    temp=jvc_sm2_sign(message,len,privatekey,privatekeylen,sign,&signlen);
    if(temp)
    {
        jvc_logger("jvc_sm2_sign error");
        jvc_release();
        return 1;
    }
    
    print_hex("sign data is", sign, signlen);

    temp=jvc_sm2_verify(message,len,sign,signlen,publickey, publickeylen);
    if(temp)
    {
        jvc_logger("jvc_sm2_verify failed !");
        jvc_release();
        return 1;
    }


    jvc_release();
    jvc_logger("jvc_sm2_verify success");
    return 0;
}

int jvc_sm2_key_match_test()
{

    unsigned char privatekey[SM2_PRIKEY_LEN] = {0};
    unsigned int privatekeylen = sizeof(privatekey);

    unsigned char publickey[SM2_PUBKEY_LEN] = {0};
    unsigned int publickeylen = sizeof(publickey);

    unsigned char sign[128] = {0};
    unsigned int signlen = sizeof(sign);

    unsigned char message[10] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a};
    unsigned int len = sizeof(message);

    int temp = 0;

    temp = jvc_init();
    if(temp)
    {
        jvc_logger("self test error");
    	return 1;
    }

    temp = jvc_sm2_gen_key(privatekey, &privatekeylen, publickey, &publickeylen);
    if(temp)
    {
        jvc_logger("self test error");
        jvc_release();
    	return 1;
    }

    temp=jvc_sm2_sign(message,len,privatekey,privatekeylen,sign,&signlen);
    if(temp)
    {
        jvc_logger("self test error");
        jvc_release();
        return 1;
    }

    temp=jvc_sm2_verify(message,len,sign,signlen,publickey, publickeylen);
    if(temp)
    {
        jvc_logger("self test error");
        jvc_release();
        return 1;
    }


    jvc_release();
    jvc_logger("self test success");
    return 0;
}

int jvc_sm3_selftest()
{
	 unsigned int a=1,b=1;
    unsigned char Msg1[3]={0x61,0x62,0x63};
    int MsgLen1=3;
    unsigned char MsgHash1[32]={0};
    unsigned int MsgHash1len = 32;
    unsigned char StdHash1[32]={0x66,0xC7,0xF0,0xF4,0x62,0xEE,0xED,0xD9,0xD1,0xF2,0xD4,0x6B,0xDC,0x10,0xE4,0xE2,
    0x41,0x67,0xC4,0x87,0x5C,0xF2,0xF7,0xA2,0x29,0x7D,0xA0,0x2B,0x8F,0x4B,0xA8,0xE0};
    unsigned char
     Msg2[64]={0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
     0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
     0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
     0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64};
    int MsgLen2=64;
    unsigned char MsgHash2[32]={0};
    unsigned int MsgHash2len = 32;
    unsigned char StdHash2[32]={0xde,0xbe,0x9f,0xf9,0x22,0x75,0xb8,0xa1,0x38,0x60,0x48,0x89,0xc1,0x8e,0x5a,0x4d,
    0x6f,0xdb,0x70,0xe5,0x38,0x7e,0x57,0x65,0x29,0x3d,0xcb,0xa3,0x9c,0x0c,0x57,0x32};
    jvc_sm3(Msg1,MsgLen1,MsgHash1,&MsgHash1len);
    jvc_sm3(Msg2,MsgLen2,MsgHash2,&MsgHash2len);
    a=memcmp(MsgHash1,StdHash1,MsgHash1len);
    b=memcmp(MsgHash2,StdHash2,MsgHash2len);
    if ((a==0) && (b==0))
    {
        jvc_logger("self test success");
        return 0; 
    }
    else 
    {
        jvc_logger("self test error");
        return 1; 
    }
}


int jvc_sm4_selftest()
{
	int i;
	    //Standard data
	    unsigned char key[16]  =
	{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	    unsigned char plain[16]=
	{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	    unsigned char
	cipher[16]={0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46}
	;
	//
	unsigned char En_output[16] = {0};
	unsigned char De_output[16] = {0};
	jvc_sms4_encrypt(NULL,plain,16,En_output,key,SMS4_MODE_ECB);
	jvc_sms4_decrypt(NULL,cipher,16,De_output,key,SMS4_MODE_ECB);
	for(i=0;i<16;i++)
	{
	      if ( (En_output[i]!=cipher[i]) | (De_output[i]!=plain[i]) )
	      {
              jvc_logger("self test error");
	            return 1; 
	      }
	}
    jvc_logger("self test success");
    return 0;
}


/*
 * function：		sms4 encryption.
 * arguments:		iv, input args, the IV string of sms4 encryption, the length must be 16 bytes. 
 * 			iv changed while encrypt in CBC mode.
 * 			in, input args, the data to be encrypted, plaintext.
 * 			in_len, input args, the length of in string.
 * 			out, output args, the buffer to store encrypted data, ciphertext.
 * 			key, input args, the key of sms4 encryption, could be a 128-bits string.
 * 			mode, input args, encryption mode, only support ECB(0) and CBC(1). 
 * return value:	0 for success. non-zero for error code.
 */

int jvc_sms4_encrypt(unsigned char *iv, unsigned char *in, int in_len, unsigned char *out, unsigned char *key, unsigned int mode)
{
	int ret = 0;
	//char buffer[SMS4_MAX_DATA_LEN + 17] = {0};

	jvc_logger("jvc_sm4_encrypt() start");
	
	if ( iv == NULL && mode == SMS4_MODE_CBC) {
		ret = SMS4_ERROR_IV;
		goto out; 
	}	

	if ( in == NULL || in_len > SMS4_MAX_DATA_LEN || in_len == 0) {
		ret = SMS4_ERROR_IN;
		goto out;
	}

	if ( mode != SMS4_MODE_CBC && mode != SMS4_MODE_ECB ) {
		ret = SMS4_ERROR_MODE;
		goto out;
	}

	if ( out == NULL ) {
		ret = SMS4_ERROR_OUT;
		goto out;
	}

	if ( key == NULL ) {
		ret = SMS4_ERROR_KEY;
		goto out;
	}

	//memset(buffer, 0, SMS4_MAX_DATA_LEN + 17);
	//memcpy(buffer, in, in_len);

	//void sm4_setkey_enc( sm4_context *ctx, unsigned char key[16] );
	sm4_context ctx;
	sm4_setkey_enc(&ctx, key);

	if(mode == SMS4_MODE_ECB)
	{
		sm4_crypt_ecb(&ctx, SM4_ENCRYPT, in_len, in, out);
	}
	else
	{
		sm4_crypt_cbc(&ctx, SM4_ENCRYPT, in_len, iv, in, out);
	}
out:
	jvc_logger("jvc_sm4_encrypt() finish");

	return ret;
}


/*
 * function：		sms4 decryption.
 * arguments:		iv, input args, the IV string of sms4 encryption, the length must be 16 bytes. 
 * 			iv changed while decrypt in CBC mode.
 * 			in, input args, the data to be decrypted, ciphertext.
 * 			in_len, input args, the length of in string.
 * 			out, output args, the buffer to store decrypted data, plaintext.
 * 			key, input args, the key of sms4 encryption, could be a 128-bits string.
 * 			mode, input args, encryption mode, only support ECB(0) and CBC(1). 
 * return value:		0 for success. non-zero for error code.
 */

int jvc_sms4_decrypt(unsigned char *iv, unsigned char *in, int in_len, unsigned char *out, unsigned char *key, unsigned int mode)
{
	int ret = 0;	

	jvc_logger("jvc_sm4_decrypt() start");

    if ( iv == NULL && mode == SMS4_MODE_CBC) {
          ret = SMS4_ERROR_IV;
          goto out;
    }

	if ( in == NULL || in_len > SMS4_MAX_DATA_LEN + SMS4_BLOCK_SIZE || in_len == 0 ) {
		ret = SMS4_ERROR_IN;

		goto out;
	}

	if (mode != SMS4_MODE_CBC && mode != SMS4_MODE_ECB) {
		ret = SMS4_ERROR_MODE;
		goto out;
	}

	if ( out == NULL ) {
		ret = SMS4_ERROR_OUT;
		goto out;
	}

    if ( key == NULL ) {
        ret = SMS4_ERROR_KEY;
        goto out;
    }

	sm4_context ctx;
	sm4_setkey_dec(&ctx, key);

	if(mode == SMS4_MODE_ECB)
	{
		sm4_crypt_ecb(&ctx, SM4_DECRYPT, in_len, in, out);
	}
	else
	{
		sm4_crypt_cbc(&ctx, SM4_DECRYPT, in_len, iv, in, out);
	}
out:
	jvc_logger("jvc_sm4_decrypt() finish ret");

	return ret;
}


