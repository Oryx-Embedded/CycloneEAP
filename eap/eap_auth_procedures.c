/**
 * @file eap_auth_procedures.c
 * @brief EAP authenticator state machine procedures
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
#include "authenticator/authenticator.h"
#include "authenticator/authenticator_procedures.h"
#include "eap/eap_debug.h"
#include "debug.h"

//Check EAP library configuration
#if (AUTHENTICATOR_SUPPORT == ENABLED)


/**
 * @brief Calculate retransmission timeout
 * @param[in] port Pointer to the port context
 * @return Timeout value
 **/

uint_t eapCalculateTimeout(AuthenticatorPort *port)
{
   //Debug message
   TRACE_DEBUG("calculateTimeout() procedure...\r\n");

   //Calculate the retransmission timeout, taking into account the
   //retransmission count, round-trip time measurements, and method-specific
   //timeout hint
   return port->methodTimeout;
}


/**
 * @brief Determine the code, identifier value, and type of the current response
 * @param[in] port Pointer to the port context
 **/

void eapParseResp(AuthenticatorPort *port)
{
   const EapPacket *packet;
   const EapResponse *response;

   //Debug message
   TRACE_DEBUG("parseEapResp() procedure...\r\n");

   //In the case of a parsing error, rxResp will be set to FALSE. The values of
   //respId and respMethod may be undefined as a result (refer to RFC 4137,
   //section 5.4)
   port->rxResp = 0;

   //Point to the EAP packet
   packet = (EapPacket *) port->eapRespData;

   //Save the identifier from the current EAP response
   port->respId = packet->identifier;

   //Check code field
   if(packet->code == EAP_CODE_RESPONSE)
   {
      //Valid EAP response?
      if(port->eapRespDataLen >= sizeof(EapResponse))
      {
         //The current received packet is an EAP response
         port->rxResp = TRUE;

         //Point to the EAP response
         response = (EapResponse *) port->eapRespData;
         //Determine the type of the current response
         port->respMethod = (EapMethodType) response->type;

         //Update statistics
         if(response->type == EAP_METHOD_TYPE_IDENTITY)
         {
            //Number of EAP Resp/Id frames that have been received
            port->stats.eapolRespIdFramesRx++;
         }
         else
         {
            //Number of valid EAP Response frames (other than Resp/Id frames)
            //that have been received
            port->stats.eapolRespFramesRx++;
         }
      }
   }
   else
   {
      //Unknown code
   }
}


/**
 * @brief Create an EAP success packet
 * @param[in] port Pointer to the port context
 **/

void eapBuildSuccess(AuthenticatorPort *port)
{
   size_t n;
   EapPacket *packet;

   //Debug message
   TRACE_DEBUG("buildSuccess() procedure...\r\n");

   //Point to the buffer where to format the EAP packet
   packet = (EapPacket *) port->eapReqData;

   //Total length of the EAP packet
   n = sizeof(EapPacket);

   //Format EAP success packet
   packet->code = EAP_CODE_SUCCESS;
   packet->identifier = port->currentId;
   packet->length = htons(n);

   //Debug message
   TRACE_DEBUG("Port %" PRIu8 ": Sending EAP packet (%" PRIuSIZE " bytes)...\r\n",
      port->portIndex, n);

   //Dump EAP packet for debugging purpose
   eapDumpPacket(packet, n);

   //Save the length of the EAP packet
   port->eapReqDataLen = n;
}


/**
 * @brief Create an EAP failure packet
 * @param[in] port Pointer to the port context
 **/

void eapBuildFailure(AuthenticatorPort *port)
{
   size_t n;
   EapPacket *packet;

   //Debug message
   TRACE_DEBUG("buildFailure() procedure...\r\n");

   //Point to the buffer where to format the EAP packet
   packet = (EapPacket *) port->eapReqData;

   //Total length of the EAP packet
   n = sizeof(EapPacket);

   //Format EAP failure packet
   packet->code = EAP_CODE_FAILURE;
   packet->identifier = port->currentId;
   packet->length = htons(n);

   //Debug message
   TRACE_DEBUG("Port %" PRIu8 ": Sending EAP packet (%" PRIuSIZE " bytes)...\r\n",
      port->portIndex, n);

   //Dump EAP packet for debugging purpose
   eapDumpPacket(packet, n);

   //Save the length of the EAP packet
   port->eapReqDataLen = n;
}


/**
 * @brief Determine the next identifier value to use
 * @param[in] id Current identifier value
 * @return Next identifier value to use
 **/

uint_t eapNextId(uint_t id)
{
   //Debug message
   TRACE_DEBUG("nextId() procedure...\r\n");

   //Increment identifier value
   if(id == EAP_CURRENT_ID_NONE)
   {
      id = 0;
   }
   else
   {
      id = (id + 1) % 256;
   }

   //Return the next identifier value to use
   return id;
}


/**
 * @brief Update all variables related to internal policy state
 * @param[in] port Pointer to the port context
 **/

void eapPolicyUpdate(AuthenticatorPort *port)
{
   //Debug message
   TRACE_DEBUG("Policy.update() procedure...\r\n");
}


/**
 * @brief Determine the method that should be used at this point in the conversation
 * @param[in] port Pointer to the port context
 * @return Next method to use
 **/

EapMethodType eapPolicyGetNextMethod(AuthenticatorPort *port)
{
   //Debug message
   TRACE_DEBUG("Policy.getNextMethod() procedure...\r\n");

   //The NAS initiates the conversation by sending an EAP-Request/Identity
   return EAP_METHOD_TYPE_IDENTITY;
}


/**
 * @brief Determine if the policy will allow SUCCESS, FAIL, or is yet to determine
 * @param[in] port Pointer to the port context
 * @return Decision enumeration
 **/

EapDecision eapPolicyGetDecision(AuthenticatorPort *port)
{
   EapDecision decision;

   //Debug message
   TRACE_DEBUG("Policy.getDecision() procedure...\r\n");

   //Determine policy decision
   if(port->currentMethod == EAP_METHOD_TYPE_NONE)
   {
      //The NAS should send an initial EAP-Request message to the authenticating
      //peer (refer to RFC 3579, section 2.1)
      decision = EAP_DECISION_CONTINUE;
   }
   else
   {
      //The NAS acts as a pass-through for subsequent messages
      decision = EAP_DECISION_PASSTHROUGH;
   }

   //Return policy decision
   return decision;
}


/**
 * @brief Test for the validity of a message
 * @param[in] port Pointer to the port context
 * @return TRUE if the message is invalid and must be ignored, else FALSE
 **/

bool_t eapCheckResp(AuthenticatorPort *port)
{
   bool_t ignore;

   //Debug message
   TRACE_DEBUG("m.check() procedure...\r\n");

   //Identity method?
   if(port->currentMethod == EAP_METHOD_TYPE_IDENTITY)
   {
      ignore = FALSE;
   }
   else
   {
      ignore = TRUE;
   }

   //Return TRUE if the message is invalid and must be ignored
   return ignore;
}


/**
 * @brief Parse and process a response
 * @param[in] port Pointer to the port context
 **/

void eapProcessResp(AuthenticatorPort *port)
{
   //Debug message
   TRACE_DEBUG("m.process() procedure...\r\n");
}


/**
 * @brief Method procedure to initialize state just before use
 * @param[in] port Pointer to the port context
 **/

void eapInit(AuthenticatorPort *port)
{
   //Debug message
   TRACE_DEBUG("m.init() procedure...\r\n");
}


/**
 * @brief The method is ending in the middle of or before completion
 * @param[in] port Pointer to the port context
 **/

void eapReset(AuthenticatorPort *port)
{
   //Debug message
   TRACE_DEBUG("m.reset() procedure...\r\n");
}


/**
 * @brief Check for method completion
 * @param[in] port Pointer to the port context
 * @return Boolean
 **/

bool_t eapIsDone(AuthenticatorPort *port)
{
   //Debug message
   TRACE_DEBUG("m.isDone() procedure...\r\n");

   //This method returns a boolean
   return TRUE;
}


/**
 * @brief Determine an appropriate timeout hint for the method
 * @param[in] port Pointer to the port context
 * @return Timeout value
 **/

uint_t eapGetTimeout(AuthenticatorPort *port)
{
   //Debug message
   TRACE_DEBUG("m.getTimeout() procedure...\r\n");

   //Return default timeout
   return AUTHENTICATOR_DEFAULT_METHOD_TIMEOUT;
}


/**
 * @brief Obtain key material for use by EAP or lower layers
 * @param[in] port Pointer to the port context
 * @return EAP key
 **/

uint8_t *eapAuthGetKey(AuthenticatorPort *port)
{
   //Debug message
   TRACE_DEBUG("m.getKey() procedure...\r\n");

   //Not implemented
   return NULL;
}


/**
 * @brief Produce the next request
 * @param[in] port Pointer to the port context
 **/

void eapBuildReq(AuthenticatorPort *port)
{
   size_t n;
   EapRequest *request;

   //Debug message
   TRACE_DEBUG("m.buildReq() procedure...\r\n");

   //Identity method?
   if(port->currentMethod == EAP_METHOD_TYPE_IDENTITY)
   {
      //Point to the buffer where to format the EAP packet
      request = (EapRequest *) port->eapReqData;

      //Format EAP packet
      request->code = EAP_CODE_REQUEST;
      request->identifier = port->currentId;
      request->type = EAP_METHOD_TYPE_IDENTITY;

      //Retrieve the length of the user name
      n = osStrlen("User name:");
      //Copy user name
      osMemcpy(request->data, "User name:", n);

      //Total length of the EAP packet
      n += sizeof(EapRequest);
      //Convert the length field to network byte order
      request->length = htons(n);

      //Debug message
      TRACE_DEBUG("Port %" PRIu8 ": Sending EAP packet (%" PRIuSIZE " bytes)...\r\n",
         port->portIndex, n);

      //Dump EAP packet for debugging purpose
      eapDumpPacket((EapPacket *) request, n);

      //Save the length of the EAP request
      port->eapReqDataLen = n;
   }
   else
   {
      //Unknown EAP method
      port->eapReqDataLen = 0;
   }
}


/**
 * @brief Determine the identifier value for the current EAP request
 * @param[in] eapReqData Pointer to the EAP request
 * @param[in] eapReqDataLen Length of the EAP request, in bytes
 * @return Identifier value
 **/

uint_t eapGetId(const uint8_t *eapReqData, size_t eapReqDataLen)
{
   uint_t id;
   const EapPacket *packet;

   //Debug message
   TRACE_DEBUG("getId() procedure...\r\n");

   //Check the length of the EAP packet
   if(eapReqDataLen >= sizeof(EapPacket))
   {
      //Point to the EAP packet
      packet = (EapPacket *) eapReqData;
      //The Identifier field is one octet
      id = packet->identifier;
   }
   else
   {
      //Malformed EAP packet
      id = EAP_CURRENT_ID_NONE;
   }

   //Return identifier value
   return id;
}

#endif
