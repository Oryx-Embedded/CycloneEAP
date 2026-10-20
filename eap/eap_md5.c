/**
 * @file eap_md5.c
 * @brief MD5-Challenge authentication method
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

//Switch to the appropriate trace level
#define TRACE_LEVEL EAP_TRACE_LEVEL

//Dependencies
#include "eap/eap.h"
#include "eap/eap_md5.h"
#include "eap/eap_debug.h"
#include "hash/md5.h"
#include "debug.h"

//Check EAP library configuration
#if (EAP_MD5_SUPPORT == ENABLED)


/**
 * @brief Check incoming EAP-MD5 request
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] request Pointer to the received request
 * @param[in] length Length of the request, in bytes
 **/

error_t eapMd5CheckRequest(SupplicantContext *context,
   const EapMd5Packet *request, size_t length)
{
   //Check the length of the EAP request
   if(length < sizeof(EapMd5Packet))
   {
      return ERROR_INVALID_LENGTH;
   }

   //The Value field is one or more octets (refer to RFC 1994, section 4.1)
   if(request->valueSize == 0)
   {
      return ERROR_INVALID_LENGTH;
   }

   //Check the length of the challenge value
   if(length < (sizeof(EapMd5Packet) + request->valueSize))
   {
      return ERROR_INVALID_LENGTH;
   }

   //The request is valid
   return NO_ERROR;
}


/**
 * @brief Process incoming EAP-MD5 request
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] request Pointer to the received request
 * @param[in] length Length of the request, in bytes
 **/

void eapMd5ProcessRequest(SupplicantContext *context,
   const EapMd5Packet *request, size_t length)
{
   Md5Context md5Context;

   //The MD5 challenge method is analogous to the PPP CHAP protocol (with MD5
   //as the specified algorithm)
   md5Init(&md5Context);
   md5Update(&md5Context, &request->identifier, sizeof(uint8_t));
   md5Update(&md5Context, context->password, osStrlen(context->password));
   md5Update(&md5Context, request->value, request->valueSize);
   md5Final(&md5Context, context->digest);
   md5Deinit(&md5Context);

   //The method never continues at this point
   context->methodState = EAP_METHOD_STATE_DONE;

   //We do not know what the server's decision is, but are willing to use the
   //access if the server allows. In this case, set decision to COND_SUCC
   context->decision = EAP_DECISION_COND_SUCC;
}


/**
 * @brief Build EAP-MD5 response
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void eapMd5BuildResponse(SupplicantContext *context)
{
   size_t n;
   EapMd5Packet *response;

   //Point to the buffer where to format the EAP packet
   response = (EapMd5Packet *) context->eapRespData;

   //Format EAP packet
   response->code = EAP_CODE_RESPONSE;
   response->identifier = context->reqId;
   response->type = EAP_METHOD_TYPE_MD5_CHALLENGE;
   response->valueSize = MD5_DIGEST_SIZE;

   //The length of the response value depends upon the hash algorithm used
   osMemcpy(response->value, context->digest, MD5_DIGEST_SIZE);

   //Determine the length of the user name
   n = osStrlen(context->username);

   //The Name field is one or more octets representing the identification of
   //the system transmitting the packet (refer to RFC 1994, section 4.1)
   osMemcpy(response->value + MD5_DIGEST_SIZE, context->username, n);

   //Total length of the EAP packet
   n += sizeof(EapMd5Packet) + MD5_DIGEST_SIZE;
   //Convert the length field to network byte order
   response->length = htons(n);

   //Debug message
   TRACE_DEBUG("Sending EAP packet (%" PRIuSIZE " bytes)\r\n", n);
   //Dump EAP packet for debugging purpose
   eapDumpPacket((EapPacket *) response, n);

   //Save the length of the EAP response
   context->eapRespDataLen = n;
}

#endif
