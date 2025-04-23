/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    Secure/Src/secure_nsc.c
  * @author  MCD Application Team
  * @brief   This file contains the non-secure callable APIs (secure world)
  ******************************************************************************
    * @attention
  *
  * Copyright (c) 2025 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* USER CODE BEGIN Non_Secure_CallLib */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "secure_nsc.h"
#include "rng.h"
#include "hash.h"
#include "uECC.h"
#include "curve-sizes.h"

#include "string.h"
#include "stdlib.h"
/** @addtogroup STM32L5xx_HAL_Examples

  * @{
  */

/** @addtogroup Templates
  * @{
  */

/* Global variables ----------------------------------------------------------*/
void *pSecureFaultCallback = NULL;   /* Pointer to secure fault callback in Non-secure */
void *pSecureErrorCallback = NULL;   /* Pointer to secure error callback in Non-secure */

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
#define sha256size 32
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/**
  * @brief  Secure registration of non-secure callback.
  * @param  CallbackId  callback identifier
  * @param  func        pointer to non-secure function
  * @retval None
  */
CMSE_NS_ENTRY void SECURE_RegisterCallback(SECURE_CallbackIDTypeDef CallbackId, void *func)
{
  if(func != NULL)
  {
    switch(CallbackId)
    {
      case SECURE_FAULT_CB_ID:           /* SecureFault Interrupt occurred */
        pSecureFaultCallback = func;
        break;
      case GTZC_ERROR_CB_ID:             /* GTZC Interrupt occurred */
        pSecureErrorCallback = func;
        break;
      default:
        /* unknown */
        break;
    }
  }
}

CMSE_NS_ENTRY int genRandomBytes(unsigned char* target, unsigned int size) {
	int count = (size % 4 == 0) ? (size / 4) : ((size / 4) + 1);	// ceiling division
	uint32_t ret[count];	// beautiful c var array
	int status;
	for(int i = 0; i < count; i++) {
		status = HAL_RNG_GenerateRandomNumber(&hrng, &ret[i]);
		if (status != HAL_OK)
			Error_Handler();
	}

	// ugly manual memcpy
	for(unsigned i = 0; i < size; i++) {
		target[i] = ((uint8_t*)ret)[i];
	}

	return 1;
}

CMSE_NS_ENTRY void hashN(uint8_t* in, uint32_t size, uint8_t* out) {
	int status = HAL_HASHEx_SHA256_Start(&hhash, in, size, out, HAL_MAX_DELAY);

	if(status != HAL_OK) {
		Error_Handler();
	}
}

CMSE_NS_ENTRY int key_demo() {
	uECC_Curve curvetype = uECC_secp256k1();
	uint32_t privkeysize = uECC_curve_private_key_size(curvetype);
	uint32_t pubkeysize = uECC_curve_public_key_size(curvetype);

	uint8_t privk1[privkeysize];
	uint8_t pubk1[pubkeysize];
	uint8_t privk2[privkeysize];
	uint8_t pubk2[pubkeysize];

	// test wheteher we can create keys succesfully
	if(
		!uECC_make_key(pubk1, privk1, curvetype) ||
		!uECC_make_key(pubk2, privk2, curvetype)
	) {
		return 1;
	}
	// test keys validity
	if(
		!uECC_valid_public_key(pubk1, curvetype) ||
		!uECC_valid_public_key(pubk2, curvetype)
	) {
		return 1;
	}
	// test whether public-private keys match
	uint8_t calcpubk1[pubkeysize];
	uint8_t calcpubk2[pubkeysize];

	uECC_compute_public_key(privk1, calcpubk1, curvetype);
	uECC_compute_public_key(privk2, calcpubk2, curvetype);

	if(
		memcmp(calcpubk1, pubk1, pubkeysize) ||
		memcmp(calcpubk2, pubk2, pubkeysize)
	) {
		return 1;
	}
	// test whether we can sign succesfully
	const char * msg1 = "message1";
	uint8_t hash1[sha256size];
	hashN((uint8_t*)msg1, strlen(msg1), (uint8_t*)hash1);

	const char * msg2 = "message2";
	uint8_t hash2[sha256size];
	hashN((uint8_t*)msg2, strlen(msg2), (uint8_t*)hash2);

	int sigsize = 2 * num_bytes_secp256k1;
	uint8_t sign1[sigsize];
	uint8_t sign2[sigsize];
	if(
		!uECC_sign(privk1, hash1, sha256size, (uint8_t*)sign1, curvetype) ||
		!uECC_sign(privk2, hash2, sha256size, (uint8_t*)sign2, curvetype)
	) {
		return 1;
	}
	// test whether we can signatures match
	if(
		!uECC_verify(pubk1, hash1, sha256size, sign1, curvetype) ||
		!uECC_verify(pubk2, hash2, sha256size, sign2, curvetype)
	) {
		return 1;
	}

	return 0;
}

/**
  * @}
  */

/**
  * @}
  */
/* USER CODE END Non_Secure_CallLib */

