/**
 * @file radius.h
 * @brief RADIUS (Remote Authentication Dial In User Service)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2022-2026 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneEAP Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.6.8
 **/

#ifndef _RADIUS_H
#define _RADIUS_H

//Dependencies
#include "eap/eap.h"

//RADIUS support
#ifndef RADIUS_SUPPORT
   #define RADIUS_SUPPORT ENABLED
#elif (RADIUS_SUPPORT != ENABLED && RADIUS_SUPPORT != DISABLED)
   #error RADIUS_SUPPORT parameter is not valid
#endif

//RADIUS port number
#define RADIUS_PORT 1812
//Maximum length of RADIUS packets
#define RADIUS_MAX_PACKET_SIZE 4096

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief RADIUS codes
 **/

typedef enum
{
   RADIUS_CODE_ACCESS_REQUEST       = 1,  ///<Access-Request
   RADIUS_CODE_ACCESS_ACCEPT        = 2,  ///<Access-Accept
   RADIUS_CODE_ACCESS_REJECT        = 3,  ///<Access-Reject
   RADIUS_CODE_ACCOUNTING_REQUEST   = 4,  ///<Accounting-Request
   RADIUS_CODE_ACCOUNTING_RESPONSE  = 5,  ///<Accounting-Response
   RADIUS_CODE_ACCESS_CHALLENGE     = 11, ///<Access-Challenge
   RADIUS_CODE_STATUS_SERVER        = 12, ///<Status-Server (experimental)
   RADIUS_CODE_STATUS_CLIENT        = 13  ///<Status-Client (experimental)
} RadiusCode;


//CC-RX, CodeWarrior or Win32 compiler?
#if defined(__CCRX__)
   #pragma pack
#elif defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief RADIUS packet
 **/

typedef __packed_struct
{
   uint8_t code;              //0
   uint8_t identifier;        //1
   uint16_t length;           //2-3
   uint8_t authenticator[16]; //4-19
   uint8_t attributes[];      //20
} RadiusPacket;


//CC-RX, CodeWarrior or Win32 compiler?
#if defined(__CCRX__)
   #pragma unpack
#elif defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
