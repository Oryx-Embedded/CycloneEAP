/**
 * @file eap_peer_procedures.c
 * @brief EAP peer state machine procedures
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
#define TRACE_LEVEL SUPPLICANT_TRACE_LEVEL

//Dependencies
#include "supplicant/supplicant.h"
#include "supplicant/supplicant_procedures.h"
#include "eap/eap_md5.h"
#include "eap/eap_mschapv2.h"
#include "eap/eap_tls.h"
#include "eap/eap_debug.h"
#include "debug.h"

//Check EAP library configuration
#if (SUPPLICANT_SUPPORT == ENABLED)


/**
 * @brief Determine the code, identifier value, and type of the current request
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void eapParseReq(SupplicantContext *context)
{
   const EapPacket *packet;
   const EapRequest *request;

   //Debug message
   TRACE_DEBUG("parseEapReq() procedure...\r\n");

   //In the case of a parsing error, rxReq, rxSuccess, and rxFailure will all
   //be set to FALSE. The values of reqId and reqMethod may be undefined as a
   //result (refer to RFC 4137, section 4.4)
   context->rxReq = 0;
   context->rxSuccess = 0;
   context->rxFailure = 0;

   //Point to the EAP packet
   packet = (EapPacket *) context->eapReqData;

   //Save the identifier value associated with the current EAP request
   context->reqId = packet->identifier;

   //Check code field
   if(packet->code == EAP_CODE_REQUEST)
   {
      //Valid EAP request?
      if(context->eapReqDataLen >= sizeof(EapRequest))
      {
         //The current received packet is an EAP Request
         context->rxReq = TRUE;

         //Point to the EAP request
         request = (EapRequest *) context->eapReqData;
         //Determine the type of the current request
         context->reqMethod = (EapMethodType) request->type;
      }
   }
   else if(packet->code == EAP_CODE_SUCCESS)
   {
      //The current received packet is an EAP Success
      context->rxSuccess = TRUE;
   }
   else if(packet->code == EAP_CODE_FAILURE)
   {
      //The current received packet is an EAP Failure
      context->rxFailure = TRUE;
   }
   else
   {
      //Unless a host implements an EAP authenticator layer, EAP Response
      //packets will be silently discarded (refer to RFC 3748, section 2.3)
   }
}


/**
 * @brief Test for the validity of a message
 * @param[in] context Pointer to the 802.1X supplicant context
 * @return TRUE if the message is invalid and must be ignored, else FALSE
 **/

bool_t eapCheckReq(SupplicantContext *context)
{
   error_t error;

   //Debug message
   TRACE_DEBUG("m.check() procedure...\r\n");

#if (EAP_MD5_SUPPORT == ENABLED)
   //MD5-Challenge authentication method?
   if(context->selectedMethod == EAP_METHOD_TYPE_MD5_CHALLENGE)
   {
      //Test the validity of the message
      error = eapMd5CheckRequest(context, (EapMd5Packet *) context->eapReqData,
         context->eapReqDataLen);
   }
   else
#endif
#if (EAP_MSCHAPV2_SUPPORT == ENABLED)
   //MS-CHAP-V2 authentication method?
   if(context->selectedMethod == EAP_METHOD_TYPE_MSCHAPV2)
   {
      //Test the validity of the message
      error = eapMschapv2CheckRequest(context,
         (EapMschapv2Packet *) context->eapReqData, context->eapReqDataLen);
   }
   else
#endif
#if (EAP_TLS_SUPPORT == ENABLED)
   //EAP-TLS authentication method?
   if(context->selectedMethod == EAP_METHOD_TYPE_TLS)
   {
      //Test the validity of the message
      error = eapTlsCheckRequest(context, (EapTlsPacket *) context->eapReqData,
         context->eapReqDataLen);
   }
   else
#endif
   //Unknown EAP method?
   {
      //Report an error
      error = ERROR_INVALID_TYPE;
   }

   //Return TRUE if the message is invalid and must be ignored
   return error ? TRUE : FALSE;
}


/**
 * @brief Parse and process a request
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void eapProcessReq(SupplicantContext *context)
{
   //Debug message
   TRACE_DEBUG("m.process() procedure...\r\n");

#if (EAP_MD5_SUPPORT == ENABLED)
   //MD5-Challenge authentication method?
   if(context->selectedMethod == EAP_METHOD_TYPE_MD5_CHALLENGE)
   {
      //Parse and process the incoming request
      eapMd5ProcessRequest(context, (EapMd5Packet *) context->eapReqData,
         context->eapReqDataLen);
   }
   else
#endif
#if (EAP_MSCHAPV2_SUPPORT == ENABLED)
   //MS-CHAP-V2 authentication method?
   if(context->selectedMethod == EAP_METHOD_TYPE_MSCHAPV2)
   {
      //Parse and process the incoming request
      eapMschapv2ProcessRequest(context,
         (EapMschapv2Packet *) context->eapReqData, context->eapReqDataLen);
   }
   else
#endif
#if (EAP_TLS_SUPPORT == ENABLED)
   //EAP-TLS authentication method?
   if(context->selectedMethod == EAP_METHOD_TYPE_TLS)
   {
      //Parse and process the incoming request
      eapTlsProcessRequest(context, (EapTlsPacket *) context->eapReqData,
         context->eapReqDataLen);
   }
   else
#endif
   //Unknown EAP method?
   {
      //Just for sanity
   }

   //Finally, the method must set the allowNotifications variable (refer to
   //RFC 4137, section 4.2)
   if(context->methodState == EAP_METHOD_STATE_CONT ||
      context->methodState == EAP_METHOD_STATE_MAY_CONT)
   {
      //If the new methodState is either CONT or MAY_CONT, and if the method
      //specification does not forbid the use of Notification messages, set
      //allowNotifications to TRUE
      context->allowNotifications = TRUE;
   }
   else
   {
      //Otherwise, set allowNotifications to FALSE
      context->allowNotifications = FALSE;
   }
}


/**
 * @brief Create a response message
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void eapBuildResp(SupplicantContext *context)
{
   //Debug message
   TRACE_DEBUG("m.buildResp() procedure...\r\n");

#if (EAP_MD5_SUPPORT == ENABLED)
   //MD5-Challenge authentication method?
   if(context->selectedMethod == EAP_METHOD_TYPE_MD5_CHALLENGE)
   {
      //Create a response message
      eapMd5BuildResponse(context);
   }
   else
#endif
#if (EAP_MSCHAPV2_SUPPORT == ENABLED)
   //MS-CHAP-V2 authentication method?
   if(context->selectedMethod == EAP_METHOD_TYPE_MSCHAPV2)
   {
      //Create a response message
      eapMschapv2BuildResponse(context);
   }
   else
#endif
#if (EAP_TLS_SUPPORT == ENABLED)
   //EAP-TLS authentication method?
   if(context->selectedMethod == EAP_METHOD_TYPE_TLS)
   {
      //Create a response message
      eapTlsBuildResponse(context);
   }
   else
#endif
   //Unknown EAP method?
   {
      //Just for sanity
   }
}


/**
 * @brief Process the contents of Identity request
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void eapProcessIdentity(SupplicantContext *context)
{
   //Debug message
   TRACE_DEBUG("processIdentity() procedure...\r\n");
}


/**
 * @brief Create the appropriate Identity response
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void eapBuildIdentity(SupplicantContext *context)
{
   size_t n;
   EapResponse *response;

   //Debug message
   TRACE_DEBUG("buildIdentity() procedure...\r\n");

   //Point to the buffer where to format the EAP packet
   response = (EapResponse *) context->eapRespData;

   //A response of type 1 (Identity) should be sent in response to a request
   //with a type of 1 (Identity)
   response->code = EAP_CODE_RESPONSE;
   response->identifier = context->reqId;
   response->type = EAP_METHOD_TYPE_IDENTITY;

   //Determine the length of the user name
   n = osStrlen(context->username);
   //Copy user name
   osMemcpy(response->data, context->username, n);

   //Total length of the EAP packet
   n += sizeof(EapResponse);
   //Convert the length field to network byte order
   response->length = htons(n);

   //Debug message
   TRACE_DEBUG("Sending EAP packet (%" PRIuSIZE " bytes)\r\n", n);
   //Dump EAP packet for debugging purpose
   eapDumpPacket((EapPacket *) response, n);

   //Save the length of the EAP response
   context->eapRespDataLen = n;
}


/**
 * @brief Process the contents of Notification request
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void eapProcessNotify(SupplicantContext *context)
{
   //Debug message
   TRACE_DEBUG("processNotify() procedure...\r\n");
}


/**
 * @brief Create the appropriate Notification response
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void eapBuildNotify(SupplicantContext *context)
{
   size_t n;
   EapResponse *response;

   //Debug message
   TRACE_DEBUG("buildNotify() procedure...\r\n");

   //Point to the buffer where to format the EAP packet
   response = (EapResponse *) context->eapRespData;

   //A response must be sent in reply to the request with a Type field of
   //2 (Notification)
   response->code = EAP_CODE_RESPONSE;
   response->identifier = context->reqId;
   response->type = EAP_METHOD_TYPE_NOTIFICATION;

   //The Type-Data field of the response is zero octets in length
   n = sizeof(EapResponse);
   //Convert the length field to network byte order
   response->length = htons(n);

   //Debug message
   TRACE_DEBUG("Sending EAP packet (%" PRIuSIZE " bytes)\r\n", n);
   //Dump EAP packet for debugging purpose
   eapDumpPacket((EapPacket *) response, n);

   //Save the length of the EAP response
   context->eapRespDataLen = n;
}


/**
 * @brief Create a NAK response
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void eapBuildNak(SupplicantContext *context)
{
   size_t n;
   EapResponse *response;

   //Debug message
   TRACE_DEBUG("buildNak() procedure...\r\n");

   //Point to the buffer where to format the EAP packet
   response = (EapResponse *) context->eapRespData;

   //The legacy Nak Type is valid only in response messages. It is sent in
   //reply to a request where the desired authentication type is unacceptable
   //(refer to RFC 3748, section 5.3.1)
   response->code = EAP_CODE_RESPONSE;
   response->identifier = context->reqId;
   response->type = EAP_METHOD_TYPE_NAK;

   //The response contains one or more authentication types desired by the peer
   n = 0;

#if (EAP_MD5_SUPPORT == ENABLED)
   //Check whether MD5-Challenge authentication method is acceptable
   if(osStrlen(context->password) > 0)
   {
      response->data[n++] = EAP_METHOD_TYPE_MD5_CHALLENGE;
   }
#endif

#if (EAP_MSCHAPV2_SUPPORT == ENABLED)
   //Check whether MS-CHAP-V2 authentication method is acceptable
   if(osStrlen(context->password) > 0)
   {
      response->data[n++] = EAP_METHOD_TYPE_MSCHAPV2;
   }
#endif

#if (EAP_TLS_SUPPORT == ENABLED)
   //Check whether EAP-TLS authentication method is acceptable
   if(context->tlsInitCallback != NULL)
   {
      response->data[n++] = EAP_METHOD_TYPE_TLS;
   }
#endif

   //Type zero is used to indicate that the sender has no viable alternatives,
   //and therefore the authenticator should not send another request after
   //receiving a Nak Response containing a zero value
   if(n == 0)
   {
      response->data[n++] = EAP_METHOD_TYPE_NONE;
   }

   //Total length of the EAP packet
   n += sizeof(EapResponse);
   //Convert the length field to network byte order
   response->length = htons(n);

   //Debug message
   TRACE_DEBUG("Sending EAP packet (%" PRIuSIZE " bytes)\r\n", n);
   //Dump EAP packet for debugging purpose
   eapDumpPacket((EapPacket *) response, n);

   //Save the length of the EAP response
   context->eapRespDataLen = n;
}


/**
 * @brief Obtain key material for use by EAP or lower layers
 * @param[in] context Pointer to the 802.1X supplicant context
 * @return EAP key
 **/

uint8_t *eapPeerGetKey(SupplicantContext *context)
{
   //Debug message
   TRACE_DEBUG("m.getKey() procedure...\r\n");

   //Not implemented
   return NULL;
}


/**
 * @brief Check whether EAP key is available
 * @param[in] context Pointer to the 802.1X supplicant context
 * @return Boolean
 **/

bool_t eapIsKeyAvailable(SupplicantContext *context)
{
   //Debug message
   TRACE_DEBUG("m.isKeyAvailable() procedure...\r\n");

   //Not implemented
   return FALSE;
}


/**
 * @brief Check whether the specified EAP method is allowed
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] method EAP method
 * @return TRUE if the method is allowed, else FALSE
 **/

bool_t eapAllowMethod(SupplicantContext *context, EapMethodType method)
{
   bool_t acceptable;

   //Debug message
   TRACE_DEBUG("allowMethod() procedure...\r\n");

   //Initialize flag
   acceptable = FALSE;

#if (EAP_MD5_SUPPORT == ENABLED)
   //MD5-Challenge authentication method?
   if(method == EAP_METHOD_TYPE_MD5_CHALLENGE)
   {
      //Check whether MD5-Challenge authentication method is acceptable
      if(osStrlen(context->password) > 0)
      {
         acceptable = TRUE;
      }
   }
   else
#endif
#if (EAP_MSCHAPV2_SUPPORT == ENABLED)
   //MS-CHAP-V2 authentication method?
   if(method == EAP_METHOD_TYPE_MSCHAPV2)
   {
      //Check whether MS-CHAP-V2 authentication method is acceptable
      if(osStrlen(context->password) > 0)
      {
         acceptable = TRUE;
      }
   }
   else
#endif
#if (EAP_TLS_SUPPORT == ENABLED)
   //EAP-TLS authentication method?
   if(method == EAP_METHOD_TYPE_TLS)
   {
      //Check whether EAP-TLS authentication method is acceptable
      if(context->tlsInitCallback != NULL)
      {
         acceptable = TRUE;
      }
   }
   else
#endif
   //Unknown EAP method?
   {
      //Just for sanity
   }

   //Return TRUE if the EAP method is allowed
   return acceptable;
}

#endif
