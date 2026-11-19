/**
 * @file eap.h
 * @brief EAP (Extensible Authentication Protocol)
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
 * @version 2.6.6
 **/

#ifndef _EAP_H
#define _EAP_H

//Dependencies
#include "eap_config.h"
#include "core/net.h"
#include "core/crypto.h"
#include "core/crypto_mem.h"


/*
 * CycloneEAP Open is licensed under GPL version 2. In particular:
 *
 * - If you link your program to CycloneEAP Open, the result is a derivative
 *   work that can only be distributed under the same GPL license terms.
 *
 * - If additions or changes to CycloneEAP Open are made, the result is a
 *   derivative work that can only be distributed under the same license terms.
 *
 * - The GPL license requires that you make the source code available to
 *   whoever you make the binary available to.
 *
 * - If you sell or distribute a hardware product that runs CycloneEAP Open,
 *   the GPL license requires you to provide public and full access to all
 *   source code on a nondiscriminatory basis.
 *
 * If you fully understand and accept the terms of the GPL license, then edit
 * the os_port_config.h header and add the following directive:
 *
 * #define GPL_LICENSE_TERMS_ACCEPTED
 */

#ifndef GPL_LICENSE_TERMS_ACCEPTED
   #error Before compiling CycloneEAP Open, you must accept the terms of the GPL license
#endif

//Version string
#define CYCLONE_EAP_VERSION_STRING "2.6.6"
//Major version
#define CYCLONE_EAP_MAJOR_VERSION 2
//Minor version
#define CYCLONE_EAP_MINOR_VERSION 6
//Revision number
#define CYCLONE_EAP_REV_NUMBER 6

//EAP support
#ifndef EAP_SUPPORT
   #define EAP_SUPPORT ENABLED
#elif (EAP_SUPPORT != ENABLED && EAP_SUPPORT != DISABLED)
   #error EAP_SUPPORT parameter is not valid
#endif

//MD5-Challenge authentication method support
#ifndef EAP_MD5_SUPPORT
   #define EAP_MD5_SUPPORT DISABLED
#elif (EAP_MD5_SUPPORT != ENABLED && EAP_MD5_SUPPORT != DISABLED)
   #error EAP_MD5_SUPPORT parameter is not valid
#endif

//MS-CHAP-V2 authentication method support
#ifndef EAP_MSCHAPV2_SUPPORT
   #define EAP_MSCHAPV2_SUPPORT DISABLED
#elif (EAP_MSCHAPV2_SUPPORT != ENABLED && EAP_MSCHAPV2_SUPPORT != DISABLED)
   #error EAP_MSCHAPV2_SUPPORT parameter is not valid
#endif

//EAP-TLS authentication method support
#ifndef EAP_TLS_SUPPORT
   #define EAP_TLS_SUPPORT DISABLED
#elif (EAP_TLS_SUPPORT != ENABLED && EAP_TLS_SUPPORT != DISABLED)
   #error EAP_TLS_SUPPORT parameter is not valid
#endif

//Maximum fragment size
#ifndef EAP_MAX_FRAG_SIZE
   #define EAP_MAX_FRAG_SIZE 1000
#elif (EAP_MAX_FRAG_SIZE < 100 || EAP_MAX_FRAG_SIZE > 1500)
   #error EAP_DEFAULT_CLIENT_TIMEOUT parameter is not valid
#endif

//Default client timeout
#ifndef EAP_DEFAULT_CLIENT_TIMEOUT
   #define EAP_DEFAULT_CLIENT_TIMEOUT 60
#elif (EAP_DEFAULT_CLIENT_TIMEOUT < 0)
   #error EAP_DEFAULT_CLIENT_TIMEOUT parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief EAPOL protocol versions
 **/

typedef enum
{
   EAPOL_VERSION_1 = 1, ///<IEEE 802.1X-2001
   EAPOL_VERSION_2 = 2, ///<IEEE 802.1X-2004
   EAPOL_VERSION_3 = 3  ///<IEEE 802.1X-2010
} EapolVersion;


/**
 * @brief EAPOL packet types
 **/

typedef enum
{
   EAPOL_TYPE_EAP                    = 0, ///<EAPOL-EAP
   EAPOL_TYPE_START                  = 1, ///<EAPOL-Start
   EAPOL_TYPE_LOGOFF                 = 2, ///<EAPOL-Logoff
   EAPOL_TYPE_KEY                    = 3, ///<EAPOL-Key
   EAPOL_TYPE_ENCAPSULATED_ASF_ALERT = 4, ///<EAPOL-Encapsulated-ASF-Alert
   EAPOL_TYPE_MKA                    = 5, ///<EAPOL-MKA
   EAPOL_TYPE_ANNOUNCEMENT_GENERIC   = 6, ///<EAPOL-Announcement (Generic)
   EAPOL_TYPE_ANNOUNCEMENT_SPECIFIC  = 7, ///<EAPOL-Announcement (Specific)
   EAPOL_TYPE_ANNOUNCEMENT_REQ       = 8  ///<EAPOL-Announcement-Req
} EapolType;


/**
 * @brief EAP codes
 **/

typedef enum
{
   EAP_CODE_REQUEST  = 1, ///<Request
   EAP_CODE_RESPONSE = 2, ///<Response
   EAP_CODE_SUCCESS  = 3, ///<Success
   EAP_CODE_FAILURE  = 4  ///<Failure
} EapCode;


/**
 * @brief EAP method types
 **/

typedef enum
{
   EAP_METHOD_TYPE_NONE          = 0,  ///<None
   EAP_METHOD_TYPE_IDENTITY      = 1,  ///<Identity
   EAP_METHOD_TYPE_NOTIFICATION  = 2,  ///<Notification
   EAP_METHOD_TYPE_NAK           = 3,  ///<Legacy Nak
   EAP_METHOD_TYPE_MD5_CHALLENGE = 4,  ///<MD5-Challenge
   EAP_METHOD_TYPE_OTP           = 5,  ///<One-Time Password (OTP)
   EAP_METHOD_TYPE_GTC           = 6,  ///<Generic Token Card (GTC)
   EAP_METHOD_TYPE_TLS           = 13, ///<EAP-TLS
   EAP_METHOD_TYPE_TTLS          = 21, ///<EAP-TTLS
   EAP_METHOD_TYPE_PEAP          = 25, ///<PEAP
   EAP_METHOD_TYPE_MSCHAPV2      = 26, ///<MS-CHAP-V2
   EAP_METHOD_TYPE_EXPANDED_NAK  = 254 ///<Expanded NAK
} EapMethodType;


/**
 * @brief MS-CHAP-V2 opcodes
 **/

typedef enum
{
   EAP_MSCHAPV2_CODE_INVALID    = 0,
   EAP_MSCHAPV2_CODE_CHALLENGE  = 1, ///<Challenge
   EAP_MSCHAPV2_CODE_RESPONSE   = 2, ///<Response
   EAP_MSCHAPV2_CODE_SUCCESS    = 3, ///<Success
   EAP_MSCHAPV2_CODE_FAILURE    = 4  ///<Failure
} EapMschapv2Code;


/**
 * @brief EAP-TLS flags
 **/

typedef enum
{
   EAP_TLS_FLAGS_L = 0x80, ///<Length included
   EAP_TLS_FLAGS_M = 0x40, ///<More fragments
   EAP_TLS_FLAGS_S = 0x20, ///<EAP-TLS start
   EAP_TLS_FLAGS_R = 0x1F  ///<Reserved
} EapTlsFlags;


//CC-RX, CodeWarrior or Win32 compiler?
#if defined(__CCRX__)
   #pragma pack
#elif defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief EAPOL PDU
 **/

typedef __packed_struct
{
   uint8_t protocolVersion; //0
   uint8_t packetType;      //1
   uint16_t packetBodyLen;  //2-3
   uint8_t packetBody[];    //4
} EapolPdu;


/**
 * @brief EAP packet
 **/

typedef __packed_struct
{
   uint8_t code;       //0
   uint8_t identifier; //1
   uint16_t length;    //2-3
   uint8_t data[];     //4
} EapPacket;


/**
 * @brief EAP request
 **/

typedef __packed_struct
{
   uint8_t code;       //0
   uint8_t identifier; //1
   uint16_t length;    //2-3
   uint8_t type;       //4
   uint8_t data[];     //5
} EapRequest;


/**
 * @brief EAP response
 **/

typedef __packed_struct
{
   uint8_t code;       //0
   uint8_t identifier; //1
   uint16_t length;    //2-3
   uint8_t type;       //4
   uint8_t data[];     //5
} EapResponse;


/**
 * @brief EAP-MD5 packet
 **/

typedef __packed_struct
{
   uint8_t code;       //0
   uint8_t identifier; //1
   uint16_t length;    //2-3
   uint8_t type;       //4
   uint8_t valueSize;  //5
   uint8_t value[];    //6
} EapMd5Packet;


/**
 * @brief EAP MS-CHAP-V2 packet
 **/

typedef __packed_struct
{
   uint8_t code;       //0
   uint8_t identifier; //1
   uint16_t length;    //2-3
   uint8_t type;       //4
   uint8_t opcode;     //5
} EapMschapv2Packet;


/**
 * @brief EAP MS-CHAP-V2 Challenge packet
 **/

typedef __packed_struct
{
   uint8_t code;          //0
   uint8_t identifier;    //1
   uint16_t length;       //2-3
   uint8_t type;          //4
   uint8_t opcode;        //5
   uint8_t mschapv2Id;    //6
   uint16_t msLength;     //7-8
   uint8_t valueSize;     //9
   uint8_t challenge[16]; //10-25
   uint8_t name[];        //26
} EapMschapv2Challenge;


/**
 * @brief EAP MS-CHAP-V2 Response packet
 **/

typedef __packed_struct
{
   uint8_t code;              //0
   uint8_t identifier;        //1
   uint16_t length;           //2-3
   uint8_t type;              //4
   uint8_t opcode;            //5
   uint8_t mschapv2Id;        //6
   uint16_t msLength;         //7-8
   uint8_t valueSize;         //9
   uint8_t peerChallenge[16]; //10-25
   uint8_t reserved[8];       //26-33
   uint8_t ntResponse[24];    //34-57
   uint8_t flags;             //58
   uint8_t name[];            //59
} EapMschapv2Response;


/**
 * @brief EAP MS-CHAP-V2 Success Request packet
 **/

typedef __packed_struct
{
   uint8_t code;         //0
   uint8_t identifier;   //1
   uint16_t length;      //2-3
   uint8_t type;         //4
   uint8_t opcode;       //5
   uint8_t mschapv2Id;   //6
   uint16_t msLength;    //7-8
   uint8_t message[];    //9
} EapMschapv2SuccessRequest;


/**
 * @brief EAP MS-CHAP-V2 Success Response packet
 **/

typedef __packed_struct
{
   uint8_t code;         //0
   uint8_t identifier;   //1
   uint16_t length;      //2-3
   uint8_t type;         //4
   uint8_t opcode;       //5
} EapMschapv2SuccessResponse;


/**
 * @brief EAP MS-CHAP-V2 Failure Request packet
 **/

typedef __packed_struct
{
   uint8_t code;         //0
   uint8_t identifier;   //1
   uint16_t length;      //2-3
   uint8_t type;         //4
   uint8_t opcode;       //5
   uint8_t mschapv2Id;   //6
   uint16_t msLength;    //7-8
   uint8_t message[];    //9
} EapMschapv2FailureRequest;


/**
 * @brief EAP MS-CHAP-V2 Failure Response packet
 **/

typedef __packed_struct
{
   uint8_t code;         //0
   uint8_t identifier;   //1
   uint16_t length;      //2-3
   uint8_t type;         //4
   uint8_t opcode;       //5
} EapMschapv2FailureResponse;


/**
 * @brief EAP MS-CHAP-V2 Change-Password packet
 **/

typedef __packed_struct
{
   uint8_t code;       //0
   uint8_t identifier; //1
   uint16_t length;    //2-3
   uint8_t type;       //4
   uint8_t opcode;     //5
   uint8_t mschapv2Id; //6
   uint16_t msLength;  //7-8
   uint8_t data[];     //9
} EapMschapv2ChangePassword;


/**
 * @brief EAP-TLS packet
 **/

typedef __packed_struct
{
   uint8_t code;       //0
   uint8_t identifier; //1
   uint16_t length;    //2-3
   uint8_t type;       //4
   uint8_t flags;      //5
   uint8_t data[];     //6
} EapTlsPacket;


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
