#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sm3.h"

extern void ReverseSM3_LONG(SM3_LONG *var);

extern void extMess(SM3_LONG* mess, SM3_LONG* externMess, SM3_LONG* externMess1);

extern void cf(SM3_LONG* iv, SM3_LONG* externMess, SM3_LONG* externMess1, SM3_LONG* ivo);

const char SM3_version[]="SM3";

/* Implemented from GM/T 0004-2012 the SM2 Message-Digest Algorithm
 */

static unsigned char iv[32] = {
	0x73, 0x80, 0x16, 0x6f, 0x49, 0x14, 0xb2, 0xb9, 
	0x17, 0x24, 0x42, 0xd7, 0xda, 0x8a, 0x06, 0x00, 
	0xa9, 0x6f, 0x30, 0xbc, 0x16, 0x31, 0x38, 0xaa, 
	0xe3, 0x8d, 0xee, 0x4d, 0xb0, 0xfb, 0x0e, 0x4e
};

void SM3_Transform(SM3_CTX* ctx, const unsigned int* in)
{
	SM3_LONG externMess[68];
	SM3_LONG externMess1[64];

	extMess((SM3_LONG*)in, externMess, externMess1);
	cf(ctx->reg, externMess, externMess1, ctx->reg);
}

int SM3_Init(SM3_CTX *ctx)
{
	SM3_LONG* p;
	SM3_LONG i;
	SM3_LONG iv1[8];

	const union { long one; char little; } is_endian = {1};

	if (!ctx) {
		return 0;
	}
		
	memset(ctx, 0 , sizeof(SM3_CTX));
	
	if (is_endian.little) {
		memcpy(iv1, iv, 32);
		p = iv1;
		for (i=0; i<8; i++) {
			ReverseSM3_LONG(p);
			p++;
		}
		memcpy(ctx->reg, iv1, 32);
	} else {
		memcpy(ctx->reg, iv, 32);
	}
	
	return 1;
}

int SM3_Update(SM3_CTX *ctx, const unsigned char *inBuf, size_t inLen)
{
	SM3_LONG in[16];
	int mdi;
	SM3_LONG i, ii;

	/* compute number of bytes mod 64 */
	mdi = (int)((ctx->i0 >> 3) & 0x3F);

	/* update number of bits */
	if ((ctx->i0 + ((SM3_LONG)inLen << 3)) < ctx->i0)
		ctx->i1++;
	ctx->i0 += ((SM3_LONG)inLen << 3);
	ctx->i1 += ((SM3_LONG)inLen >> 29);

	while (inLen--) {
		/* add new character to buffer, increment mdi */
		ctx->in[mdi++] = *inBuf++;

		/* transform if necessary */ 
		if (mdi == 0x40) {
			for (i = 0, ii = 0; i < 16; i++, ii += 4)
				in[i] = (((SM3_LONG)ctx->in[ii+3]) << 24) |
				(((SM3_LONG)ctx->in[ii+2]) << 16) |
				(((SM3_LONG)ctx->in[ii+1]) << 8) |
				((SM3_LONG)ctx->in[ii]);

			SM3_Transform(ctx, in);
			mdi = 0;
		}
	}

	return 1;
}

int SM3_Final (SM3_CTX *ctx, unsigned char *md)
{
	SM3_LONG in[16];
	int mdi;
	SM3_LONG i, ii;
	SM3_LONG padLen;
	unsigned char PADDING[64] = {0x80};
	const union { long one; char little; } is_endian = {1};

	/* save number of bits */
	in[14] = ctx->i1;
	in[15] = ctx->i0;

	if (is_endian.little) {
		ReverseSM3_LONG(&(in[14]));
		ReverseSM3_LONG(&(in[15]));
	}

	/* compute number of bytes mod 64 */
	mdi = (int)((ctx->i0 >> 3) & 0x3F);

	/* pad out to 56 mod 64 */
	padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
	SM3_Update (ctx, PADDING, padLen);

	/* append length in bits and transform */
	for (i = 0, ii = 0; i < 14; i++, ii += 4)
		in[i] = (((SM3_LONG)ctx->in[ii+3]) << 24) |
		(((SM3_LONG)ctx->in[ii+2]) << 16) |
		(((SM3_LONG)ctx->in[ii+1]) << 8) |
		((SM3_LONG)ctx->in[ii]);

	SM3_Transform(ctx, in);

	/* store buffer in digest */
	for (i = 0, ii = 0; i < 8; i++, ii += 4) {

		if (is_endian.little) 
		{
			ReverseSM3_LONG(&(ctx->reg[i]));
		}

		ctx->digest[ii] = (unsigned char)(ctx->reg[i] & 0xFF);
		ctx->digest[ii+1] =
			(unsigned char)((ctx->reg[i] >> 8) & 0xFF);
		ctx->digest[ii+2] =
			(unsigned char)((ctx->reg[i] >> 16) & 0xFF);
		ctx->digest[ii+3] =
			(unsigned char)((ctx->reg[i] >> 24) & 0xFF);
	}

	for (i=0; i<SM3_DIGEST_LENGTH; i++)
		md[i]=(unsigned char)(ctx->digest[i]&0xff);

	/* memset((char *)ctx,0,sizeof(SM3_CTX)); */
	return 1;
}
