//
// main.cpp
//  testmpc
//
//  Created by zuoyongyong on 2019/10/12.
//  Copyright © 2019年 zuoyongyong. All rights reserved.
//
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "sm2.h"
#include "jvcrypto.h"
#include "one-of-two-OT.h"
#include "one-of-more-OT.h"
#include "fledman_vss.hpp"
#include "Pedersen_vss.hpp"
#include "singel_schnorr_sign.h"
#include "RingSignProtocols.h"
#include "hashCommitments.h"
#include "pedersenCommitments.h"
#include "sigmaProtocol.h"
#include "monero_ring_sign.h"
#include "search_sym_enc.h"
#include "randlib.h"
#include "kdf.h"

unsigned char test_key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
unsigned char test_plaintext[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
unsigned char test_ciphertext[16] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};

typedef unsigned char BYTE;


typedef BYTE   BIJECT4X4[16];   // 4 x 4 bits table => 16 row

int main(int argc, char **argv){
    // Override point for customization after application launch.
    
    
    sm2_init();
     unsigned char rand_out[64] = {0};
    unsigned char rand_seed[32] = {
        0x9c, 0x91, 0x59, 0x34, 0x7f, 0xa5, 0x07, 0xab,
        0x9e, 0x11, 0x9d, 0xab, 0xf5, 0x4e, 0x10, 0x25,
        0x1e, 0xff, 0xbb, 0x12, 0x76, 0x7a, 0xd5, 0x3c,
        0xe9, 0x09, 0x63, 0x9b, 0x13, 0x09, 0x6a, 0x72
    };
    
    

    ssl_rand_add(rand_seed, sizeof(rand_seed), sizeof(rand_seed));
    ssl_rand_add(rand_seed, sizeof(rand_seed), sizeof(rand_seed));
    ssl_rand_bytes(rand_out, 32);
    
    print_hex((uint8_t *)"rand_out is ", rand_out, 32);
    
    
    unsigned char rand_seed_2[32] = {
        0x9c, 0x91, 0x59, 0x34, 0x7f, 0xa5, 0x07, 0xab,
        0x9e, 0x11, 0x9d, 0xab, 0xf5, 0x4e, 0x10, 0x25,
        0x1e, 0xff, 0xbb, 0x12, 0x76, 0x7a, 0xd5, 0x3c,
        0xe9, 0x09, 0x63, 0x9b, 0x13, 0x09, 0x6a, 0x72
    };
    
    unsigned char rand_out_2[64] = {0};
    
    ssl_rand_add(rand_seed_2, sizeof(rand_seed_2), sizeof(rand_seed_2));
    ssl_rand_bytes(rand_out_2, 32);
    
    print_hex((uint8_t *)"rand_out2 is ", rand_out_2, 32);

    /*
    const char *plainText_0 = "the plain 0 text is one";
    
    BIJECT4X4 data = {0};
    
    data[0] = 2;
    data[1] = 3;
    data[2] = 4;
    
    
    //jvc_sm2_selftest();
    
    printf(" BIJECT4X4 size is %d", sizeof(BIJECT4X4));
    
    unsigned char szkey[16] = {0xC8,0xC4,0xF8,0x6F,0x8D,0x7A,0x3F,0x49,0xF7,0x11,0xF1,0xAC,0x27,0xC2,0x26,0x8A};
    
    unsigned char cipherText_0[128] = {0};
    unsigned int cipher_len_0 = sizeof(cipherText_0);
    
    
    //int ret = sm4_enc(szkey, 16, (unsigned char *)plainText_0, strlen(plainText_0), (unsigned char *)cipherText_0, &cipher_len_0);
    */
    
    

    
    //testSecretShare();
    
    //for(int i = 0; i < 10000; i++)
    //sm2_test_threshold_sign();
    
    //test_ed25519();

    //test_Pedersen_vss();
    
    //test_private_equality_test();
    
    //test_one_of_more_oblivious_transfer(4);
    
    //test_Ring_Sign();
    
    //test_schnorr_sign_verify();
    
    //test_hashCommit();
    
    //test_pedersenCommit();
    
    //test_sigma_proof_verify();
    
   // test_monero_ring_signature();

    test_symmetric_searchable_encryption();
    
    return 0;
}
