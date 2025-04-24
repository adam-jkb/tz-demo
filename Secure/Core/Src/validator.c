#include "main.h"
#include "uECC.h"
#include "secure_nsc.h"

// cpp style constexprs would be really nice here
#define PRIVKEYSIZE 32
#define PUBKEYSIZE 64

static uint8_t privk[PRIVKEYSIZE];
static uint8_t pubk[PUBKEYSIZE];
static uECC_Curve curvetype;

int initKeys() {
	curvetype = uECC_secp256k1();

	//uint32_t privkeysize = uECC_curve_private_key_size(curvetype);
	//uint32_t pubkeysize = uECC_curve_public_key_size(curvetype);

	if(!uECC_make_key(pubk, privk, curvetype))
		return 1;
	return 0;
}


CMSE_NS_ENTRY int signHash(uint8_t hash[32], uint8_t signature[64]) {
	if(!uECC_sign(privk, hash, 32, (uint8_t*)signature, curvetype))
		return 1;
	return 0;
}
CMSE_NS_ENTRY int verifyHashSignature(uint8_t hash[32], uint8_t signature[64]){
	return uECC_verify(pubk, hash, 32, signature, curvetype);
}

CMSE_NS_ENTRY int verifyHashSignatureWithWrongKey(uint8_t hash[32], uint8_t signature[64]){
	uint8_t privk2[PRIVKEYSIZE];
	uint8_t pubk2[PUBKEYSIZE];
	uECC_make_key(pubk2, privk2, curvetype);
	return uECC_verify(pubk2, hash, 32, signature, curvetype);
}