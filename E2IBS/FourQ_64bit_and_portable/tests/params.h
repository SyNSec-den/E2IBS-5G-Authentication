#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <time.h>
#include <stdint.h>

#ifndef PARAMS_H
#define PARAMS_H




#define MODULUS_SIZE 3072                   /* This is the number of bits we want in the modulus */
#define BLOCK_SIZE (MODULUS_SIZE/8)         /* This is the size of a block that gets en/decrypted at once */
#define BUFFER_SIZE ((MODULUS_SIZE/8) / 2)  /* This is the number of bytes in n and p */
 
#define SECRECT_SIZE 256U // the bit length of private key components 



#endif

#define BIT_SET(character, position) ((*character |= 1 << position))	
#define BIT_CLEAR(character, position) ((*character &= ~(1 << position)))
#define BIT_TOGGLE(character, position)	((*character ^= 1 << position))
#define BIT_CHECK(var,pos) !!((*var) & (1<<(pos)))

#define bitRead(value) ((value) & 0x01)
#define shiftOne(value) ((value) >> 1)




