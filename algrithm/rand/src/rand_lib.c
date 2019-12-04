/* rand/rand_lib.c */

#include "rand_lib.h"


static const RAND_METHOD *default_RAND_meth = NULL;

int RAND_set_rand_method(const RAND_METHOD *meth)
	{
	default_RAND_meth = meth;
	return 1;
	}

const RAND_METHOD *RAND_get_rand_method(void)
	{
	if (!default_RAND_meth)
		{
			default_RAND_meth = RAND_SSLeay();
		}
	return default_RAND_meth;
	}

void RAND_cleanup(void)
	{
	const RAND_METHOD *meth = RAND_get_rand_method();
	if (meth && meth->cleanup)
		meth->cleanup();
	RAND_set_rand_method(NULL);
	}

void RAND_seed(const void *buf, int num)
	{
	const RAND_METHOD *meth = RAND_get_rand_method();
	if (meth && meth->seed)
		meth->seed(buf,num);
	}

void RAND_add(const void *buf, int num, int entropy)
	{
	const RAND_METHOD *meth = RAND_get_rand_method();
	if (meth && meth->add)
		meth->add(buf,num,entropy);
	}

int RAND_bytes(unsigned char *buf, int num)
	{
	const RAND_METHOD *meth = RAND_get_rand_method();
	if (meth && meth->bytes)
		return meth->bytes(buf,num);
	return(-1);
	}

int RAND_status(void)
	{
	const RAND_METHOD *meth = RAND_get_rand_method();
	if (meth && meth->status)
		return meth->status();
	return 0;
	}
