//
//  one-of-two-OT.c
//  testSM2
//
//  Created by zuoyongyong on 2019/11/5.
//  Copyright © 2019年 zuoyongyong. All rights reserved.
//

#include "search_sym_enc.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "bn.h"
#include "bnEx.h"
#include "ec_operations.h"
#include "bn_operations.h"
#include "rand.h"
#include "sm2.h"
#include "sm3.h"
#include "sm4.h"
#include "kdf.h"
#include "jvcrypto.h"


#define TEST


extern void gen_randomBytes(unsigned char *data, unsigned int len);


void test_symmetric_searchable_encryption()
{
    // two party  alice has secret: Sec_a   Bob has secret: Sec_b
    // using 1-out-of-2-OT  check they have  same seccret
    // accroding to the following protocol
    char alice_secret = 0x58;
    char bob_secret = 0x58;
    
    unsigned char alice_bit[8] = {0};
    unsigned char bob_bit[8] = {0};
    
    unsigned char bit01_str[8][2][32] = {{0}};
    unsigned char alice_str[8][32] = {{0}};
    unsigned char bob_str[8][32] = {{0}};
    
    unsigned int i = 0;
    
    // 1、convert Sec_a and Sec_b  to binary like  00101101 and  01011100 ( bit i from 1 to 8 )
    
    for(i = 0; i < sizeof(char)*8; i++)
    {
        alice_bit[i] = (alice_secret>>i)&0x01;
        bob_bit[i] = (bob_secret>>i)&0x01;
    }
    
    
    //2、for every bit i Bob choose random k-bit string {0 <=> i_string_0}, {1 <== >i_string_1}，
    for(i = 0; i < sizeof(bob_bit); i++)
    {
        gen_randomBytes(bit01_str[i][0],16);
        print_hex((uint8_t *)"bit0_str is ", bit01_str[i][0], 32);
        gen_randomBytes(bit01_str[i][1], 16);
        print_hex((uint8_t *)"bit1_str is", bit01_str[i][1], 32);
        if(bob_bit[i] == 0)
        {
            memcpy(bob_str[i], bit01_str[i][0], 32);
        }
        else
        {
            memcpy(bob_str[i], bit01_str[i][1], 32);
        }
        
    }
    

    //6、alice for all stri (i from 1 to n)  compute xor for every str generate datastr_A
    unsigned char alicexor[32] = {0};
    for(i = 0; i < 32; i++)
    {
        alicexor[i] = alice_str[0][i];
        for(int j = 0; j < 8; j++)
        {
            alicexor[i] ^= alice_str[j][i];
        }
    }
    
    //7、alice send datastr_A to Bob
    
    //8、Bob for all bit Sec_b  compute xor for every str then generate datastr_B
    unsigned char bobxor[32] = {0};
    for (i = 0; i < 32; i++)
    {
        bobxor[i] = bob_str[0][i];
        for(int j = 0; j < 8; j++)
            bobxor[i] ^= bob_str[j][i];
    }
    
    //9. Bob compare datastr_B with datastr_A to check Sec_a  Sec_b equality
    if(memcmp(alicexor, bobxor, 32) == 0)
    {
        printf("alice's secret is equal to bob's secret \n");
    }
    else
    {
        printf("alice's secret is not equal to bob's secret \n");
    }
    

}
