/**
 * @file supplicant_procedures.c
 * @brief Supplicant state machine procedures
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
#include "supplicant/supplicant_misc.h"
#include "eap/eap_debug.h"
#include "debug.h"

//Check EAP library configuration
#if (SUPPLICANT_SUPPORT == ENABLED)


/**
 * @brief Transmit an EAPOL-Start packet (8.2.11.1.3 a)
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void supplicantTxStart(SupplicantContext *context)
{
   size_t n;
   EapolPdu *pdu;

   //Debug message
   TRACE_DEBUG("txStart() procedure...\r\n");

   //Point to the buffer where to format the EAPOL packet
   pdu = (EapolPdu *) context->txBuffer;

   //EAPOL-Start PDUs are transmitted with no Packet Body
   pdu->protocolVersion = EAPOL_VERSION_2;
   pdu->packetType = EAPOL_TYPE_START;
   pdu->packetBodyLen = ntohs(0);

   //Total length of the EAPOL packet
   n = sizeof(EapolPdu);

   //Debug message
   TRACE_INFO("Sending EAPOL packet (%" PRIuSIZE " bytes)\r\n", n);
   //Dump EAPOL header contents for debugging purpose
   eapolDumpHeader(pdu);

   //Send EAPOL PDU
   supplicantSendEapolPdu(context, context->txBuffer, n);
}


/**
 * @brief Transmit an EAPOL-Logoff packet (8.2.11.1.3 b)
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void supplicantTxLogoff(SupplicantContext *context)
{
   size_t n;
   EapolPdu *pdu;

   //Debug message
   TRACE_DEBUG("txLogoff() procedure...\r\n");

   //Point to the buffer where to format the EAPOL packet
   pdu = (EapolPdu *) context->txBuffer;

   //EAPOL-Start PDUs are transmitted with no Packet Body
   pdu->protocolVersion = EAPOL_VERSION_2;
   pdu->packetType = EAPOL_TYPE_LOGOFF;
   pdu->packetBodyLen = ntohs(0);

   //Total length of the EAPOL packet
   n = sizeof(EapolPdu);

   //Debug message
   TRACE_INFO("Sending EAPOL packet (%" PRIuSIZE " bytes)\r\n", n);
   //Dump EAPOL header contents for debugging purpose
   eapolDumpHeader(pdu);

   //Send EAPOL PDU
   supplicantSendEapolPdu(context, context->txBuffer, n);
}


/**
 * @brief Release any system resources (8.2.12.1.3 a)
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void supplicantAbortSupp(SupplicantContext *context)
{
}


/**
 * @brief Get the information required in order to respond to the EAP request (8.2.12.1.3 b)
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void supplicantGetSuppRsp(SupplicantContext *context)
{
   //Debug message
   TRACE_DEBUG("getSuppRsp() procedure...\r\n");
}


/**
 * @brief Transmit an EAPOL-Packet packet (8.2.12.1.3 c)
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void supplicantTxSuppRsp(SupplicantContext *context)
{
   size_t length;
   EapolPdu *pdu;

   //Debug message
   TRACE_DEBUG("txSuppRsp() procedure...\r\n");

   //Point to the buffer where to format the EAPOL packet
   pdu = (EapolPdu *) context->txBuffer;
   //Retrieve the length of the EAP response
   length = context->eapRespDataLen;

   //Valid EAP packet?
   if(length >= sizeof(EapPacket))
   {
      //Format EAPOL packet
      pdu->protocolVersion = EAPOL_VERSION_2;
      pdu->packetType = EAPOL_TYPE_EAP;
      pdu->packetBodyLen = ntohs(length);

      //Total length of the EAPOL packet
      length += sizeof(EapolPdu);

      //Debug message
      TRACE_INFO("Sending EAPOL packet (%" PRIuSIZE " bytes)\r\n", length);
      //Dump EAPOL header contents for debugging purpose
      eapolDumpHeader(pdu);

      //Send EAPOL PDU
      supplicantSendEapolPdu(context, context->txBuffer, length);
   }
}


/**
 * @brief Decrement timer value
 * @param[in,out] x Actual timer value
 **/

void supplicantDecrementTimer(uint_t *x)
{
   //If the variable has a non-zero value, this procedure decrements the value
   //of the variable by 1
   if(*x > 0)
   {
      *x -= 1;
   }
}

#endif
