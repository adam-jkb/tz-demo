/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    Secure_nsclib/secure_nsc.h
  * @author  MCD Application Team
  * @brief   Header for secure non-secure callable APIs list
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

/* USER CODE BEGIN Non_Secure_CallLib_h */
/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef SECURE_NSC_H
#define SECURE_NSC_H

/* Includes ------------------------------------------------------------------*/
#include <stdint.h>

/* Exported types ------------------------------------------------------------*/
/**
  * @brief  non-secure callback ID enumeration definition
  */
typedef enum
{
  SECURE_FAULT_CB_ID     = 0x00U, /*!< System secure fault callback ID */
  GTZC_ERROR_CB_ID       = 0x01U  /*!< GTZC secure error callback ID */
} SECURE_CallbackIDTypeDef;

/* Exported constants --------------------------------------------------------*/
/* Exported macro ------------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */
void SECURE_RegisterCallback(SECURE_CallbackIDTypeDef CallbackId, void *func);

void hashN(uint8_t* in, uint32_t size, uint8_t* out);
int genRandomBytes(unsigned char* target, unsigned int size);

int signHash(uint8_t hash[32], uint8_t signature[64]);
int verifyHashSignature(uint8_t hash[32], uint8_t signature[64]);
int verifyHashSignatureWithWrongKey(uint8_t hash[32], uint8_t signature[64]);

#ifdef KEY_DEMO
int key_demo();
#endif

#ifdef TZ_DEMO
typedef void (*tzfunc)();

void tz_demo_hidden();

tzfunc tz_demo_public();
#endif

int signHash(uint8_t hash[32], uint8_t signature[64]);
int verifyHashSignature(uint8_t hash[32], uint8_t signature[64]);

#endif /* SECURE_NSC_H */
/* USER CODE END Non_Secure_CallLib_h */

