//
//  hashCommitments.c
//  testSM2
//
//  Created by zuoyongyong on 2019/12/3.
//  Copyright © 2019年 zuoyongyong. All rights reserved.
//

/// compute C = Hash(m||r)
/// where m is the commited value, r is blind factor,
/// C is Hash commitment

/// calculate commitment c = H(m,r) using SHA3 CRHF.
/// r is 256bit blinding factor, m is the commited value

#include <stdlib.h>
#include <string.h>
#include "hashCommitments.h"
#include "sm3.h"
#include "rand.h"

typedef struct HashCommSt
{
    unsigned char comm[32];
    unsigned char blind[32];
}hashComm;

void genHashCommit(unsigned char *message, unsigned int messagelen, hashComm *comm)
{
    if(message == NULL || comm == NULL)
        return ;
    
    //1、gen 256bit random blind factor
    unsigned char blindFactor[32] = {0};
    unsigned char hash[32] = {0};
    unsigned int datalen = messagelen + sizeof(blindFactor);
    
    GenerateRandomBytes(blindFactor, 32);
    
    //2、compose message && blind factor
    unsigned char *pData = malloc(datalen);
    if(pData == NULL)
        return ;
    
    memset(pData, 0, datalen);
    
    memcpy(pData, message, messagelen);
    memcpy(pData + messagelen, blindFactor, sizeof(blindFactor));
    
    SM3(pData, datalen, hash);
    
    memcpy(comm->comm, hash, 32);
    memcpy(comm->blind, blindFactor, 32);
    
    if(pData)
    {
        free(pData);
        pData = NULL;
    }
    return ;
}

extern void print_hex(uint8_t *label, uint8_t *data, uint16_t data_len);

void test_hashCommit()
{
    unsigned char *message = "the message to hash commit";
    unsigned int len = strlen(message);
    
    hashComm commit;
    memset(&commit, 0, sizeof(hashComm));
    
    genHashCommit(message, len, &commit);

    print_hex((uint8_t *)"hash commit is ", commit.comm, sizeof(commit.comm));
    print_hex((uint8_t *)"blind factor is ", commit.blind, sizeof(commit.blind));
}


