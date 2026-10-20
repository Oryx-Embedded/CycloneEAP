/**
 * @file authenticator_procedures.c
 * @brief Authenticator state machine procedures
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
#define TRACE_LEVEL AUTHENTICATOR_TRACE_LEVEL

//Dependencies
#include "authenticator/authenticator.h"
#include "authenticator/authenticator_procedures.h"
#include "authenticator/authenticator_misc.h"
#include "eap/eap_auth_procedures.h"
#include "eap/eap_debug.h"
#include "debug.h"

//Check EAP library configuration
#if (AUTHENTICATOR_SUPPORT == ENABLED)


/**
 * @brief Set authorization state for a given port
 * @param[in] port Pointer to the port context
 * @param[in] status Authorization state (authorized or unauthorized)
 **/

void authenticatorSetAuthPortStatus(AuthenticatorPort *port,
   AuthenticatorPortStatus status)
{
   NetInterface *interface;
   AuthenticatorContext *context;
   SwitchPortState portState;

   //Point to the 802.1X authenticator context
   context = port->context;
   //Point to the underlying network interface
   interface = context->interface;

   //Check authorization state
   if(status == AUTHENTICATOR_PORT_STATUS_AUTH)
   {
      //Debug message
      TRACE_INFO("Port %" PRIu8 ": Set port status to Authorized\r\n",
         port->portIndex);

      //A port in the authorized state effectively means that the supplicant has
      //been successfully authenticated
      portState = SWITCH_PORT_STATE_FORWARDING;
   }
   else
   {
      //Debug message
      TRACE_INFO("Port %" PRIu8 ": Set port status to Unauthorized\r\n",
         port->portIndex);

      //If the port is in the unauthorized state, then the client is not granted
      //access to the network
      portState = SWITCH_PORT_STATE_BLOCKING;
   }

   //Valid switch driver?
   if(interface->switchDriver != NULL &&
      interface->switchDriver->setPortState != NULL)
   {
      //Get exclusive access
      netLock(context->netContext);

      //Update the state of the specified port
      interface->switchDriver->setPortState(interface, port->portIndex,
         portState);

      //Release exclusive access
      netUnlock(context->netContext);
   }

   //Save authorization state
   port->authPortStatus = status;
}


/**
 * @brief Transmit an EAPOL frame containing an EAP failure (8.2.4.1.3 a)
 * @param[in] port Pointer to the port context
 **/

void authenticatorTxCannedFail(AuthenticatorPort *port)
{
   size_t n;
   EapolPdu *pdu;
   EapPacket *packet;

   //Debug message
   TRACE_DEBUG("txCannedFail() procedure...\r\n");

   //In the case that no EAP communication was taking place on the port, then
   //any value of ID may be used in the Identifier field of the EAP frame. In
   //the case that there was an EAP communication taking place on the port,
   //then the value of the Identifier field in the EAP packet is set to a value
   //that is different from the last delivered EAPOL frame of type EAP-Packet
   //(refer to IEEE Std 802.1X-2004, section 8.2.4.1.3)
   port->currentId = eapNextId(port->currentId);

   //Point to the buffer where to format the EAPOL packet
   pdu = (EapolPdu *) port->eapTxBuffer;
   //Point to the buffer where to format the EAP packet
   packet = (EapPacket *) pdu->packetBody;

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

   //Format EAPOL packet
   pdu->protocolVersion = EAPOL_VERSION_2;
   pdu->packetType = EAPOL_TYPE_EAP;
   pdu->packetBodyLen = htons(n);

   //Total length of the EAPOL packet
   n += sizeof(EapolPdu);

   //Debug message
   TRACE_INFO("Port %" PRIu8 ": Sending EAPOL packet (%" PRIuSIZE " bytes)...\r\n",
      port->portIndex, n);

   //Dump EAPOL header contents for debugging purpose
   eapolDumpHeader(pdu);

   //Send EAPOL PDU
   authenticatorSendEapolPdu(port, port->eapTxBuffer, n);
}


/**
 * @brief Transmit an EAPOL frame containing an EAP success (8.2.4.1.3 b)
 * @param[in] port Pointer to the port context
 **/

void authenticatorTxCannedSuccess(AuthenticatorPort *port)
{
   size_t n;
   EapolPdu *pdu;
   EapPacket *packet;

   //Debug message
   TRACE_DEBUG("txCannedSuccess() procedure...\r\n");

   //In the case that no EAP communication was taking place on the port, then
   //any value of ID may be used in the Identifier field of the EAP frame. In
   //the case that there was an EAP communication taking place on the port,
   //then the value of the Identifier field in the EAP packet is set to a value
   //that is different from the last delivered EAPOL frame of type EAP-Packet
   //(refer to IEEE Std 802.1X-2004, section 8.2.4.1.3)
   port->currentId = eapNextId(port->currentId);

   //Point to the buffer where to format the EAPOL packet
   pdu = (EapolPdu *) port->eapTxBuffer;
   //Point to the buffer where to format the EAP packet
   packet = (EapPacket *) pdu->packetBody;

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

   //Format EAPOL packet
   pdu->protocolVersion = EAPOL_VERSION_2;
   pdu->packetType = EAPOL_TYPE_EAP;
   pdu->packetBodyLen = htons(n);

   //Total length of the EAPOL packet
   n += sizeof(EapolPdu);

   //Debug message
   TRACE_INFO("Port %" PRIu8 ": Sending EAPOL packet (%" PRIuSIZE " bytes)...\r\n",
      port->portIndex, n);

   //Dump EAPOL header contents for debugging purpose
   eapolDumpHeader(pdu);

   //Send EAPOL PDU
   authenticatorSendEapolPdu(port, port->eapTxBuffer, n);
}


/**
 * @brief Transmit an EAPOL frame of type EAP-Packet (8.2.9.1.3 a)
 * @param[in] port Pointer to the port context
 **/

void authenticatorTxReq(AuthenticatorPort *port)
{
   size_t length;
   EapolPdu *pdu;
   EapRequest *request;

   //Debug message
   TRACE_DEBUG("txReq() procedure...\r\n");

   //Point to the buffer where to format the EAPOL packet
   pdu = (EapolPdu *) port->eapTxBuffer;
   //Retrieve the length of the EAP request
   length = port->eapReqDataLen;

   //Valid EAP packet?
   if(length >= sizeof(EapPacket))
   {
      //EAP request?
      if(port->eapReqData[0] == EAP_CODE_REQUEST &&
         length >= sizeof(EapRequest))
      {
         //Point to the EAP request
         request = (EapRequest *) port->eapReqData;

         //Update statistics
         if(request->type == EAP_METHOD_TYPE_IDENTITY)
         {
            //Number of EAP Req/Id frames that have been transmitted
            port->stats.eapolReqIdFramesTx++;
         }
         else
         {
            //Number of EAP Request frames (other than Rq/Id frames) that have
            //been transmitted
            port->stats.eapolReqFramesTx++;
         }
      }

      //Format EAPOL packet
      pdu->protocolVersion = EAPOL_VERSION_2;
      pdu->packetType = EAPOL_TYPE_EAP;
      pdu->packetBodyLen = htons(length);

      //Total length of the EAPOL packet
      length += sizeof(EapolPdu);

      //Debug message
      TRACE_INFO("Port %" PRIu8 ": Sending EAPOL packet (%" PRIuSIZE " bytes)...\r\n",
         port->portIndex, length);

      //Dump EAPOL header contents for debugging purpose
      eapolDumpHeader(pdu);

      //Send EAPOL PDU
      authenticatorSendEapolPdu(port, port->eapTxBuffer, length);
   }
}


/**
 * @brief Deliver the received EAP frame to EAP for processing (8.2.9.1.3 b)
 * @param[in] port Pointer to the port context
 **/

void authenticatorSendRespToServer(AuthenticatorPort *port)
{
   //Debug message
   TRACE_DEBUG("sendRespToServer() procedure...\r\n");
}


/**
 * @brief Release any system resources (8.2.9.1.3 c)
 * @param[in] port Pointer to the port context
 **/

void authenticatorAbortAuth(AuthenticatorPort *port)
{
}


/**
 * @brief Decrement timer value
 * @param[in,out] x Actual timer value
 **/

void authenticatorDecrementTimer(uint_t *x)
{
   //If the variable has a non-zero value, this procedure decrements the value
   //of the variable by 1
   if(*x > 0)
   {
      *x -= 1;
   }
}

#endif
