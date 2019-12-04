#include "rand.h"
#include "rand_lib.h"
//#include "crt.h"
#include <stdlib.h>
#include <string.h>

int RAND_poll(void)
{
	void*	pBuffer;
	void**	ppBuffer = &pBuffer;
	unsigned char rpArray[ENTROPY_NEEDED];


	/* A bit more entropy from uninitialized pointer and pointer to the pointer values. */
	RAND_add(&pBuffer, sizeof(pBuffer), 0);
	RAND_add(&ppBuffer, sizeof(ppBuffer), 0);

	/* Add allocated on stack uninitialized array values and array location in memory */
	RAND_add(rpArray, sizeof(rpArray), 0);
	RAND_add(&rpArray, sizeof(unsigned char *), 0);

    /* We will use TEE RNG to seed OpenSSL PRNG */
    //TEE_GenerateRandom(rpArray, sizeof(rpArray));

    /* We imply that TAL_GetRandom is a good source of entropy */
    RAND_add(rpArray, sizeof(rpArray), sizeof(rpArray));
    memset(rpArray, 0, sizeof(rpArray));


    pBuffer = malloc(ENTROPY_NEEDED);
	if(NULL == pBuffer)
		return 0;
	RAND_add(pBuffer, ENTROPY_NEEDED, ENTROPY_NEEDED);
	RAND_add(&pBuffer, sizeof(pBuffer), 0.0);
    memset(pBuffer, 0, ENTROPY_NEEDED);
	free(pBuffer);


	return 1;
}
