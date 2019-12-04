/* seal.c - SEAL encryption algorithm */
#include "ec_operations.h"
#include <stdlib.h>
#include <string.h>
//#include "crypto.h"
//#include "tal.h"
#include <stdio.h>
#include <time.h>
//#include <random.h>
//#include "tee_ext_api.h"
//#include "stat_fncs.h"

#ifndef DWORD
typedef unsigned long DWORD;
#endif

#ifndef NULL
#define NULL    0
/*#define NULL ((void *)0)*/
#endif
 
typedef struct SealKey {
	unsigned long t[520]; /* 512 rounded up to a multiple of 5 + 5 */
	unsigned long s[265]; /* 256 rounded up to a multiple of 5 + 5 */
	unsigned long r[265];  /* 16 rounded up to multiple of 5 */
}SEALKEY;

#define ALG_OK 0
#define ALG_NOTOK 1

#define ROT2(x) (((x) >> 2) | ((x) << 30))
#define ROT9(x) (((x) >> 9) | ((x) << 23))
#define ROT8(x) (((x) >> 8) | ((x) << 24))
#define ROT16(x) (((x) >> 16) | ((x) << 16))
#define ROT24(x) (((x) >> 24) | ((x) << 8))
#define ROT27(x) (((x) >> 27) | ((x) << 5))

#define WORD(cp)  ((cp[0] << 24)|(cp[1] << 16)|(cp[2] << 8)|(cp[3]))

#define F1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define F2(x, y, z) ((x)^(y)^(z))
#define F3(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define F4(x, y, z) ((x)^(y)^(z))


unsigned char randomSeed[128] = {0};
static int funcall = 0;


int g(unsigned char *in,int i,unsigned char *h)
{
	unsigned long h0;
	unsigned long h1;
	unsigned long h2;
	unsigned long h3;
	unsigned long h4;
	unsigned long a;
	unsigned long b;
	unsigned long c;
	unsigned long d;
	unsigned long e;
	unsigned char *kp;
	unsigned long w[80];
	unsigned long temp;

	kp = in;
	h0 = WORD(kp); kp += 4;
	h1 = WORD(kp); kp += 4;
	h2 = WORD(kp); kp += 4;
	h3 = WORD(kp); kp += 4;
	h4 = WORD(kp); kp += 4;

	/* step 1 */
	w[0] = i;
	for (i=1;i<16;i++)
		w[i] = 0;

	/* step 2 */
	for (i=16;i<80;i++)
		w[i] = w[i-3]^w[i-8]^w[i-14]^w[i-16];			/* ���㷨������ͬ */

	/* step 3 */
	a = h0;
	b = h1;
	c = h2;
	d = h3;
	e = h4;

	/* step 4 */
	for (i=0;i<20;i++)
	{
		temp = ROT27(a) + F1(b, c, d) + e + w[i] + 0x5a827999;
		e = d;
		d = c;
		c = ROT2(b);
		b = a;
		a = temp;
	}
	for (i=20;i<40;i++)
	{
		temp = ROT27(a) + F2(b, c, d) + e + w[i] + 0x6ed9eba1;
		e = d;
		d = c;
		c = ROT2(b);
		b = a;
		a = temp;
	}
	for (i=40;i<60;i++)
	{
		temp = ROT27(a) + F3(b, c, d) + e + w[i] + 0x8f1bbcdc;
		e = d;
		d = c;
		c = ROT2(b);
		b = a;
		a = temp;
	}
	for (i=60;i<80;i++)
	{
		temp = ROT27(a) + F4(b, c, d) + e + w[i] + 0xca62c1d6;
		e = d;
		d = c;
		c = ROT2(b);
		b = a;
		a = temp;
	}

	/* step 5 */
	h[0] =(unsigned char)(h0+a);
	h[1] =(unsigned char)(h1+b);
	h[2] =(unsigned char)(h2+c);
	h[3] =(unsigned char)(h3+d);
	h[4] =(unsigned char)(h4+e);

	return (ALG_OK);
}	

int  seal_init(unsigned char *key, SEALKEY  *result)
{
 
	int i;
	unsigned long h[5];
     
 
	if (result == NULL)
		return (ALG_NOTOK);

   	for (i=0;i<510;i+=5)
		g(key, i/5, (unsigned char *)&(result->t[i]));
	/* horrible special case for the end */
	g(key, 510/5, (unsigned char *)h);
	for (i=510;i<512;i++)
		result->t[i] = h[i-510];
	/* 0x1000 mod 5 is +1, so have horrible special case for the start */
	g(key, (-1+0x1000)/5, (unsigned char *)h);
	for (i=0;i<4;i++)
		result->s[i] = h[i+1];
	for (i=4;i<254;i+=5)
		g(key, (i+0x1000)/5, (unsigned char *)&(result->s[i]));
	/* horrible special case for the end */
	g(key, (254+0x1000)/5, (unsigned char *)h);
	for (i=254;i<256;i++)
		result->s[i] = h[i-254];
	/*my code */
	/* 0x2000 mod 5 is +2, so have horrible special case at the start */
	g(key, (-2+0x2000)/5, (unsigned char *)h);
	for (i=0;i<3;i++)
		result->r[i] = h[i+2];
	for (i=3;i<253;i+=5)
		g(key, (i+0x2000)/5, (unsigned char *)&(result->r[i]));
	/* horrible special case for the end */
	g(key, (253+0x2000)/5, (unsigned char *)h);
	for (i=253;i<256;i++)
		result->r[i] = h[i-253];
	/* 0x2000 mod 5 is +2, so have horrible special case at the start */
	/*g(key, (-2+0x2000)/5, (unsigned char *)h);
	for (i=0;i<3;i++)
		result->r[i] = h[i+2];
	for (i=3;i<13;i+=5)
		g(key, (i+0x2000)/5, (unsigned char *)&(result->r[i]));*/

	/* horrible special case for the end */
	/*i
  	g(key, (13+0x2000)/5, (unsigned char *)h);
	for (i=13;i<16;i++)
		result->r[i] = h[i-13];
    
	*ks = result;
	ExFreePool(result);
	*/
	return (ALG_OK);
}

int seal( struct SealKey *key, unsigned int n, unsigned int L, unsigned long *out )
{
	int i;
	int j;
	int l;
	unsigned long a;
	unsigned long b;
	unsigned long c;
	unsigned long d;
	unsigned short p;
	unsigned short q;
	unsigned long n1;
	unsigned long n2;
	unsigned long n3;
	unsigned long n4;
	unsigned long *wp;

	unsigned long counter = 0;

	wp = out;

	for (l=0;l<((int)L/8192 + 1);l++)
	{
		a = n ^ key->r[4*l];
		b = ROT8(n) ^ key->r[4*l+1];
		c = ROT16(n) ^ key->r[4*l+2];
		d = ROT24(n) ^ key->r[4*l+3];
	
		for (j=0;j<2;j++)
		{
			p =(unsigned short) a & 0x7fc;
			b += key->t[p/4];
			a = ROT9(a);
	
			p =(unsigned short) b & 0x7fc;
			c += key->t[p/4];
			b = ROT9(b);
	
			p =(unsigned short) c & 0x7fc;
			d += key->t[p/4];
			c = ROT9(c);
	
			p =(unsigned short) d & 0x7fc;
			a += key->t[p/4];
			d = ROT9(d);
	
		}
		n1 = d;
		n2 = b;
		n3 = a;
		n4 = c;
	
		p = (unsigned short)a & 0x7fc;
		b += key->t[p/4];
		a = ROT9(a);
	
		p =(unsigned short) b & 0x7fc;
		c += key->t[p/4];
		b = ROT9(b);
	
		p = (unsigned short)c & 0x7fc;
		d += key->t[p/4];
		c = ROT9(c);
	
		p =(unsigned short) d & 0x7fc;
		a += key->t[p/4];
		d = ROT9(d);
		
		/* generate 8192 bits */
		for (i=0;i<64;i++)
		{
			p =(unsigned short) a & 0x7fc;
			b += key->t[p/4];
			a = ROT9(a);
			b ^= a;
	
			q =(unsigned short) b & 0x7fc;
			c ^= key->t[q/4];
			b = ROT9(b);
			c += b;
	
			p = (unsigned short)(p+c) & 0x7fc;
			d += key->t[p/4];
			c = ROT9(c);
			d ^= c;
	
			q =(unsigned short) (q+d) & 0x7fc;
			a ^= key->t[q/4];
			d = ROT9(d);
			a += d;
	
			p = (unsigned short)(p+a) & 0x7fc;
			b ^= key->t[p/4];
			a = ROT9(a);
	
			q =(unsigned short) (q+b) & 0x7fc;
			c += key->t[q/4];
			b = ROT9(b);
	
			p =(unsigned short) (p+c) & 0x7fc;
			d ^= key->t[p/4];
			c = ROT9(c);
	
			q = (unsigned short)(q+d) & 0x7fc;
			a += key->t[q/4];
			d = ROT9(d);
	
			*wp = b + key->s[4*i];
			wp++, counter++;
			*wp = c ^ key->s[4*i+1];
			wp++, counter++;
			*wp = d + key->s[4*i+2];
			wp++, counter++;
			*wp = a ^ key->s[4*i+3];
			wp++, counter++;
	
			if( (counter * 32) >= L )
				return (ALG_OK);

			if (i & 1)
			{
				a += n3;
				c += n4;
			}
			else
			{
				a += n1;
				c += n2;
			}				
		}
	}
	return (ALG_OK);
}


extern void print_hex(uint8_t *label, uint8_t *data, uint16_t data_len);

unsigned char g_random[128] = {0};
unsigned int g_random_len = 32;
BOOL b_gen = FALSE;

int rng(unsigned int rng_len, unsigned char *prngdata_out)
{
    if(b_gen == FALSE)
    {
        unsigned long* seed = malloc( sizeof( unsigned long ) );
        FILE* file = fopen("/dev/random", "r");
        //printf( "%d \n", sizeof( unsigned long ) );
        int i;
        for( i = 0; i < rng_len/8; ++i)
        {
            fread( seed, 1, sizeof( unsigned long ), file );
            //printf( "0x%x ", *seed%0xFF);
            g_random[i] = *seed%255+1;
        }
        if(seed)
        {
            free(seed);
            seed = NULL;
        }
        
        fclose(file);
        
        //b_gen = TRUE;
    }
    
    memcpy(prngdata_out, g_random, rng_len/8);
    
    //printf("\n");
    
    //print_hex((uint8_t *)" random is ", prngdata_out, rng_len/8);
    
    return 0;
}
/*
int rng(unsigned int rng_len, 
			 unsigned char *prngdata_out )
{
    srand((unsigned)time(NULL));
    for(int i = 0; i < rng_len/8; i++)
    {
        prngdata_out[i] = random()%255;
    }
    
    print_hex((uint8_t *)" random is ", prngdata_out, rng_len/8);
    
    /*
    cal_blob_t  RandBLOB = {0,0};
    cal_blob_t  RandSeed = {0,0};
    int rngcount = 0;

begin:
    if(funcall >= CAL_SEED_LEN/64)
    {
    	funcall = 0;
    }

	RandBLOB.pData = prngdata_out;
	RandBLOB.length = rng_len/8;

	//TEE_GenerateRandom(randomSeed, sizeof(randomSeed));

	RandSeed.pData = randomSeed+funcall*64;
	RandSeed.length = 64;

	PRINT_INFO("funcall %d",funcall);

	//CAL_HexDump("rng Seed : ", RandSeed.pData, RandSeed.length);

	///TEE_GenerateRandom(RandBLOB.pData, RandBLOB.length);


	gCAL_tee.CAL_RandGen(&RandSeed, &RandBLOB);

	funcall++;

	
    //CAL_HexDump("rng Random : ", prngdata_out, rng_len/8);


    int ret = Random_PokerCheck(prngdata_out, rng_len/8);

    PRINT_INFO("Random_PokerCheck ret is %d", ret);

    if(ret)
    {
        rngcount++;
        if(rngcount < 3)
    	      goto begin;
    }
	return 0;
}
*/
