/* sm2.h */

#ifndef __SM2_H_
#define __SM2_H_

#include <stdio.h>

#ifdef	__cplusplus
extern "C" {
#endif

int sm2_init(void);
int sm2_release(void);

int sm2_encrypt(unsigned char *plaintext, unsigned int plaintext_len, 
	        unsigned char *pubkey, unsigned int pubkey_len, 
                unsigned char *ciphertext, unsigned int *ciphertext_len);

int sm2_decrypt(unsigned char *ciphertext, unsigned int ciphertext_len, 
                unsigned char *prikey, unsigned int prikey_len, 
                unsigned char *plaintext, unsigned int *plaintext_len);

int sm2_signature( unsigned char *digest, unsigned int digest_len,
		   unsigned char *prikey, unsigned int prikey_len, 
		   unsigned char *sig, unsigned int *sig_len);

int sm2_verify(unsigned char *digest, unsigned int digest_len, 
	       unsigned char *sig, unsigned int sig_len, 
               unsigned char *pubkey, unsigned int pubkey_len);

int sm2_is_point_valid(unsigned char *point, unsigned int point_len);
int sm2_gen_prikey(unsigned char *prikey, unsigned int *prikey_len);

int sm2_genkey(unsigned char *prikey, unsigned int *prikey_len, 
               unsigned char *pubkey, unsigned int *pubkey_len);

int sm2_point_from_privatekey(const unsigned char *prikey, const unsigned int prikey_len, 
                              unsigned char *pubkey, unsigned int *pubkey_en);

int sm2_is_key_match(const unsigned char *prikey, const unsigned int prikey_len, 
		     const unsigned char *pubkey, const unsigned int pubkey_len);

void print_hex(uint8_t *label, uint8_t *data, uint16_t data_len);


//(1)、A: 协商的A1--A3步骤
/*
功能：密钥协商的发起方A调用此函数产生一对临时公钥a_temp_pubkey(x, y)和相应的随机数。公钥发送给对方，随机数a_temp_random自己保存。
[输出] a_temp_pubkey：   公钥 (x,y)
[输出] a_temp_pubkey_len：公钥的字节数，64
[输出] a_temp_random:     随机数
[输出] a_temp_random_len: ra的字节数，32

返回值：0 success 1 failed
*/
int sm2_keyAgreement_a1_3(unsigned char * a_temp_random, unsigned int *a_temp_random_len, unsigned char*a_temp_pubkey, unsigned int *a_temp_pubkey_len);


//(2)、B: 协商的B1--B9步骤

/*
功能：密钥协商的接收方B调用此函数协商出密钥keybuff，同时产生一对临时公钥b_temp_pubkey 、v_pubkey和sb。
     b_temp_pubkey和sb发送给对方A，keybuff和v_pubkey自己保存。
说明：
[输入] a_temp_pubkey是发起方A产生的临时公钥
[输入] a_pubkey是发起方A的公钥
[输入] b_prikey是接收方B的私钥
[输入] b_pubkey是接收方B的公钥
[输入] ida是发起方A的用户标识
[输入] idb是接收方B的用户标识
[输入] keylen是要约定的密钥字节数

[输出] keybuff是协商密钥输出缓冲区
[输出] b_temp_pubkey是接收方B产生的临时公钥
[输出] v_pubkey(xv, yv)是接收方B产生的中间结果，自己保存，用于验证协商的正确性。，如果v_pubkey=NULL，则不输出。
[输出] sb是接收方B产生的32字节的HASH值，要传送给发起方A，用于验证协商的正确性。如果为sb=NULL，则不输出。

返回值：0 success  1 failed
*/
int sm2_keyAgreement_b1_9(unsigned char *a_temp_pubkey, unsigned int a_temp_pubkey_len,
                          unsigned char *a_pubkey, unsigned int a_pubkey_len,
                          unsigned char *b_prikey, unsigned int b_prikey_len,
                          unsigned char *b_pubkey, unsigned int b_pubkey_len, 
                          unsigned char *ida, unsigned int ida_len,
                          unsigned char *idb, unsigned int idb_len,
                          unsigned int keylen,unsigned char *keybuff,
                          unsigned char *b_temp_pubkey, unsigned int *b_temp_pubkey_len,
                          unsigned char *v_pubkey, unsigned int *v_pubkey_len,
                          unsigned char *sb);


//(3)、A: 协商的A4--A10的步骤

/*

功能：密钥协商的发起方A调用此函数协商出密钥keybuff，同时产生s1和sa。s1和keybuff自己保存，sa发送给接收方B，用于确认协商过程的正确性。
说明：
[输入] a_temp_pubkey是发起方产生的临时公钥
[输入] a_temp_random是发起方调用sm2_keyagreement_a1_3产生的随机数
[输入] a_pubkey是发起方的公钥
[输入] a_prikey是发起方的私钥
[输入] b_pubkey是接收方的公钥
[输入] b_temp_pubkey是接收方产生的临时公钥
[输入] ida是发起方的用户标识
[输入] idb是接收方的用户标识
[输入] keylen是要约定的密钥字节数

[输出] keybuff是协商密钥输出缓冲区
[输出] s1和sa是发起方产生的32字节的HASH值，s1自己保存（应等于sb），sa要传送给接收方，用于验证协商的正确性


返回值：0 － success  1－ failed
  
*/
int sm2_keyAgreement_a4_10(unsigned char *a_temp_pubkey, unsigned int a_temp_pubkey_len,
                           unsigned char *a_temp_random, unsigned int a_temp_random_len,
                           unsigned char *a_pubkey, unsigned int a_pubkey_len,
                           unsigned char *a_prikey, unsigned int a_prikey_len, 
                           unsigned char *b_pubkey, unsigned int b_pubkey_len,
                           unsigned char *b_temp_pubkey, unsigned int b_temp_pubkey_len,
                           unsigned char *ida, unsigned int ida_len,
                           unsigned char *idb, unsigned int idb_len,
                           unsigned int keylen,
                           unsigned char *keybuff,
                           unsigned char *s1,
                           unsigned char *sa);

//(3)、B: 协商的B10的步骤
/*

功能：密钥协商的接收方调用此函数产生s2，用于验证协商过程的正确性。
说明：
[输入] a_pubkey是发起方的公钥
[输入] b_pubkey是接收方的公钥
[输入] a_temp_pubkey是发起方产生的临时公钥
[输入] b_temp_pubkey是接收方产生的临时公钥
[输入] v_pubkey是接收方产生sm2_keyAgreement_b1_9的中间结果
[输入] ida是发起方的用户标识
[输入] idb是接收方的用户标识

[输出] s2是接收方产生的32字节的HASH值，应等于sa。


返回值：0 － success  1－ failed
  
*/

int sm2_keyAgreement_b10(unsigned char *a_pubkey, unsigned int a_pubkey_len,
                         unsigned char *b_pubkey, unsigned int b_pubkey_len,
                         unsigned char *a_temp_pubkey, unsigned int a_temp_pubkey_len,
                         unsigned char *b_temp_pubkey, unsigned int b_temp_pubkey_len,
                         unsigned char *v_pubkey, unsigned int v_pubkey_len,
                         unsigned char *ida, unsigned int ida_len,
                         unsigned char *idb, unsigned int idb_len,
                         unsigned char *s2);


void sm2_test_threshold_sign();
    


#ifdef	__cplusplus
}
#endif


#endif
