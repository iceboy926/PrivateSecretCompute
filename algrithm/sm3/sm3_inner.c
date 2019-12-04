#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sm3.h"
//#include "crt.h"

#define SM3_SMALL_ENDIAN


void ReverseSM3_LONG(SM3_LONG *var)
{
	unsigned char tmp;
	tmp = ((unsigned char*)var)[0];
	((unsigned char*)var)[0] = ((unsigned char*)var)[3];
	((unsigned char*)var)[3] = tmp;
	tmp = ((unsigned char*)var)[1];
	((unsigned char*)var)[1] = ((unsigned char*)var)[2];
	((unsigned char*)var)[2] = tmp;
	
}

static SM3_LONG tj(unsigned char j)
{
	/* #186-D: pointless comparison of unsigned integer with zero */
	//if (0<=j && j<=15) 
	if (j<=15) 
	{
		return 0x79cc4519;
	}
	else if (16<=j && j<=63)
	{
		return 0x7a879d8a;
	}
	else
	{
		return 0;
	}
}


static SM3_LONG ff(unsigned j, SM3_LONG x, SM3_LONG y, SM3_LONG z) 
{
	/* #186-D: pointless comparison of unsigned integer with zero */
	//if (0<=j && j<=15)
	if (j<=15)
	{
		return x^y^z;
	}
	else if (16<=j && j<=63)
	{
		return (x&y)|(x&z)|(y&z);
	}

	return 0;
}

static SM3_LONG gg(unsigned j, SM3_LONG x, SM3_LONG y, SM3_LONG z) 
{
	/* #186-D: pointless comparison of unsigned integer with zero */
	//if (0<=j && j<=15)
	if (j<=15)
	{
		return x^y^z;
	}
	else if (16<=j && j<=63)
	{
		return (x&y)|((~x)&z);
	}

	return 0;
}

static SM3_LONG rotate_left(SM3_LONG x, unsigned char n)
{
	SM3_LONG save;
	unsigned char i;
	for (i=0; i<n; i++)
	{
		save = x&0x80000000;
		x = x<<1;
		save = save>>31;
		x += save;
	}
	return x;
}

static SM3_LONG p0(SM3_LONG x)
{
	return x^(rotate_left(x,9))^(rotate_left(x,17));
}

static SM3_LONG p1(SM3_LONG x)
{
	return x^(rotate_left(x,15))^(rotate_left(x,23));
}

void extMess(SM3_LONG* mess, SM3_LONG* externMess, SM3_LONG* externMess1)
{
	int i;
	SM3_LONG temp;
	memcpy((unsigned char*)externMess, (unsigned char*)mess, 64);

#ifdef SM3_SMALL_ENDIAN
	for (i=0; i<16; i++)
	{
		ReverseSM3_LONG(&(externMess[i]));
	}
#endif

	for (i=16; i<=67; i++)
	{
		temp = externMess[i-16]^externMess[i-9]^(rotate_left(externMess[i-3], 15));
		temp = p1(temp)^(rotate_left(externMess[i-13], 7))^externMess[i-6];
		externMess[i] = temp;
	}

	for (i=0; i<=63; i++)
	{
		externMess1[i] = externMess[i]^externMess[i+4];
	}

}

void cf(SM3_LONG* iv, SM3_LONG* externMess, SM3_LONG* externMess1, SM3_LONG* ivo)
{
	int i;
	SM3_LONG ss1, ss2, tt1, tt2;
	SM3_LONG reg[8];
	SM3_LONG temp;
	memcpy(reg, iv, 32);
	for (i=0; i<=63; i++)
	{
		temp = rotate_left(reg[0], 12) + reg[4] + rotate_left(tj(i), i);
		ss1 = rotate_left(temp, 7);
		ss2 = ss1^rotate_left(reg[0], 12);

		tt1 = ff(i, reg[0], reg[1], reg[2]) + reg[3] + ss2 + externMess1[i];		
		tt2 = gg(i, reg[4], reg[5], reg[6]) + reg[7] + ss1 + externMess[i];

		reg[3] = reg[2];
		reg[2] = rotate_left(reg[1], 9);

		reg[1] = reg[0];
		reg[0] = tt1;

		reg[7] = reg[6];
		reg[6] = rotate_left(reg[5], 19);

		reg[5] = reg[4];
		reg[4] = p0(tt2);
	}

	for (i=0; i<8; i++)
	{
		reg[i] = reg[i]^iv[i];
	}

	memcpy(ivo, reg, 32);
}

