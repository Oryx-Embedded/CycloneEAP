/**
 * @file supplicant_misc.c
 * @brief Helper functions for 802.1X supplicant
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

//Switch to the appropriate trace level
#define TRACE_LEVEL SUPPLICANT_TRACE_LEVEL

//Dependencies
#include "supplicant/supplicant.h"
#include "supplicant/supplicant_fsm.h"
#include "supplicant/supplicant_procedures.h"
#include "supplicant/supplicant_misc.h"
#include "eap/eap_debug.h"
#include "debug.h"

//Check EAP library configuration
#if (SUPPLICANT_SUPPORT == ENABLED)

//PAE group address (refer to IEEE Std 802.1X-2010, section 11.1.1)
static const MacAddr PAE_GROUP_ADDR = {{{0x01, 0x80, 0xC2, 0x00, 0x00, 0x03}}};


/**
 * @brief Handle periodic operations
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void supplicantTick(SupplicantContext *context)
{
   //The portEnabled variable is externally controlled. Its value reflects
   //the operational state of the MAC service supporting the port
   context->portEnabled = supplicantGetLinkState(context);

   //Timers are decremented once per second
   supplicantDecrementTimer(&context->startWhen);
   supplicantDecrementTimer(&context->heldWhile);
   supplicantDecrementTimer(&context->authWhile);
   supplicantDecrementTimer(&context->idleWhile);

   //Update supplicant state machines
   supplicantFsm(context);

   //Any registered callback?
   if(context->tickCallback != NULL)
   {
      //Invoke user callback function
      context->tickCallback(context);
   }
}


/**
 * @brief Get link state
 * @param[in] context Pointer to the 802.1X supplicant context
 * @return Error code
 **/

bool_t supplicantGetLinkState(SupplicantContext *context)
{
   bool_t linkState;
   NetInterface *interface;

   //Point to the underlying network interface
   interface = context->interface;

   //Valid switch driver?
   if(context->portIndex != 0 && interface != NULL &&
      interface->switchDriver != NULL &&
      interface->switchDriver->getLinkState != NULL)
   {
      //Get exclusive access
      netLock(context->netContext);

      //Retrieve the link state of the specified port
      linkState = interface->switchDriver->getLinkState(interface,
         context->portIndex);

      //Release exclusive access
      netUnlock(context->netContext);
   }
   else
   {
      //Retrieve the link state of the network interface
      linkState = netGetLinkState(interface);
   }

   //Return link state
   return linkState;
}


/**
 * @brief Add the PAE group address to the static MAC table
 * @param[in] context Pointer to the 802.1X supplicant context
 * @return Error code
 **/

error_t supplicantAcceptPaeGroupAddr(SupplicantContext *context)
{
   error_t error;
   SwitchFdbEntry entry;
   NetInterface *physicalInterface;

   //Initialize status code
   error = NO_ERROR;

   //Valid interface?
   if(context->interface != NULL)
   {
      //Get exclusive access
      netLock(context->netContext);

      //Point to the physical interface
      physicalInterface = nicGetPhysicalInterface(context->interface);

      //Valid switch driver?
      if(context->portIndex != 0 &&
         physicalInterface->switchDriver != NULL &&
         physicalInterface->switchDriver->addStaticFdbEntry != NULL)
      {
         //Format forwarding database entry
         entry.macAddr = PAE_GROUP_ADDR;
         entry.srcPort = 0;
         entry.destPorts = SWITCH_CPU_PORT_MASK;
         entry.override = TRUE;

         //Update the static MAC table of the switch
         error = physicalInterface->switchDriver->addStaticFdbEntry(
            physicalInterface, &entry);
      }

      //Check status code
      if(!error)
      {
         //Add the PAE group address to the MAC filter table
         error = ethAcceptMacAddr(context->interface, &PAE_GROUP_ADDR);
      }

      //Check status code
      if(!error)
      {
         //Virtual interface?
         if(context->interface != physicalInterface)
         {
            //Configure the physical interface to accept the MAC address
            error = ethAcceptMacAddr(physicalInterface, &PAE_GROUP_ADDR);

            //Any error to report?
            if(error)
            {
               //Clean up side effects
               ethDropMacAddr(context->interface, &PAE_GROUP_ADDR);
            }
         }
      }

      //Release exclusive access
      netUnlock(context->netContext);
   }

   //Return status code
   return error;
}


/**
 * @brief Remove the PAE group address from the static MAC table
 * @param[in] context Pointer to the 802.1X supplicant context
 * @return Error code
 **/

error_t supplicantDropPaeGroupAddr(SupplicantContext *context)
{
   error_t error;
   SwitchFdbEntry entry;
   NetInterface *physicalInterface;

   //Initialize status code
   error = NO_ERROR;

   //Valid interface?
   if(context->interface != NULL)
   {
      //Get exclusive access
      netLock(context->netContext);

      //Point to the physical interface
      physicalInterface = nicGetPhysicalInterface(context->interface);

      //Valid switch driver?
      if(context->portIndex != 0 &&
         physicalInterface->switchDriver != NULL &&
         physicalInterface->switchDriver->deleteStaticFdbEntry != NULL)
      {
         //Format forwarding database entry
         entry.macAddr = PAE_GROUP_ADDR;
         entry.srcPort = 0;
         entry.destPorts = 0;
         entry.override = FALSE;

         //Update the static MAC table of the switch
         error = physicalInterface->switchDriver->deleteStaticFdbEntry(
            physicalInterface, &entry);
      }

      //Check status code
      if(!error)
      {
         //Remove the PAE group address to the MAC filter table
         ethDropMacAddr(context->interface, &PAE_GROUP_ADDR);

         //Virtual interface?
         if(context->interface != physicalInterface)
         {
            //Drop the corresponding address from the MAC filter table of the
            //physical interface
            ethDropMacAddr(physicalInterface, &PAE_GROUP_ADDR);
         }
      }

      //Release exclusive access
      netUnlock(context->netContext);
   }

   //Return status code
   return error;
}


/**
 * @brief Send EAPOL PDU
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] pdu Pointer to the PDU to be transmitted
 * @param[in] length Length of the PDU, in bytes
 * @return Error code
 **/

error_t supplicantSendEapolPdu(SupplicantContext *context, const uint8_t *pdu,
   size_t length)
{
   error_t error;
   SocketMsg msg;

   //Point to the PDU to be transmitted
   msg = SOCKET_DEFAULT_MSG;
   msg.data = (uint8_t *) pdu;
   msg.length = length;

   //All EAPOL MPDUs shall be identified using the PAE EtherType (refer to
   //IEEE Std 802.1X-2010, section 11.1.4)
   msg.ethType = ETH_TYPE_EAPOL;

#if (ETH_PORT_TAGGING_SUPPORT == ENABLED)
   //Specify the egress port
   msg.switchPort = context->portIndex;
#endif

   //The PAE group address is assigned specifically for use by EAPOL clients
   //designed to maximize plug-and-play interoperability, and should be the
   //default for those clients (refer to IEEE Std 802.1X-2010, section 11.1.1)
   msg.destMacAddr = PAE_GROUP_ADDR;

   //The source address for each MAC service request used to transmit an EAPOL
   //MPDU shall be an individual address associated with the service access
   //point at which the request is made (refer to IEEE Std 802.1X-2010,
   //section 11.1.2)
   error = netGetMacAddr(context->interface, &msg.srcMacAddr);

   //Check status code
   if(!error)
   {
      //Send EAPOL MPDU
      error = socketSendMsg(context->socket, &msg, 0);
   }

   //Return status code
   return error;
}


/**
 * @brief Process incoming EAPOL PDU
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void supplicantProcessEapolPdu(SupplicantContext *context)
{
   error_t error;
   size_t length;
   SocketMsg msg;
   MacAddr macAddr;
   EapolPdu *pdu;

   //Point to the receive buffer
   msg = SOCKET_DEFAULT_MSG;
   msg.data = context->rxBuffer;
   msg.size = SUPPLICANT_RX_BUFFER_SIZE;

   //Receive EAPOL MPDU
   error = socketReceiveMsg(context->socket, &msg, 0);
   //Any error to report?
   if(error)
      return;

#if (ETH_PORT_TAGGING_SUPPORT == ENABLED)
   //Check the port number on which the EAPOL PDU was received
   if(msg.switchPort != context->portIndex && context->portIndex != 0)
      return;
#endif

   //Get the MAC address assigned to the interface
   error = netGetMacAddr(context->interface, &macAddr);
   //Any error to report?
   if(error)
      return;

   //The destination MAC address field contains the PAE group address, or
   //the specific MAC address of the PAE (refer to IEEE Std 802.1X-2004,
   //section 7.5.7)
   if(!macCompAddr(&msg.destMacAddr, &PAE_GROUP_ADDR) &&
      !macCompAddr(&msg.destMacAddr, &macAddr))
   {
      return;
   }

   //The received MPDU must contain the PAE EtherType
   if(msg.ethType != ETH_TYPE_EAPOL)
      return;

   //Malformed EAPOL packet?
   if(msg.length < sizeof(EapolPdu))
      return;

   //Point to the EAPOL packet
   pdu = (EapolPdu *) context->rxBuffer;

   //Debug message
   TRACE_INFO("EAPOL packet received (%" PRIuSIZE " bytes)\r\n", msg.length);
   //Dump EAPOL header contents for debugging purpose
   eapolDumpHeader(pdu);

   //Any octets following the Packet Body field in the frame conveying the
   //EAPOL PDU shall be ignored (refer to IEEE Std 802.1X-2004, section 11.4)
   length = ntohs(pdu->packetBodyLen);

   //Malformed EAPOL packet?
   if(msg.length < (sizeof(EapolPdu) + length))
      return;

   //Check packet type
   if(pdu->packetType == EAPOL_TYPE_EAP)
   {
      //Process incoming EAP packet
      supplicantProcessEapPacket(context, (EapPacket *) pdu->packetBody,
         length);
   }
}


/**
 * @brief Process incoming EAP packet
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] packet Pointer to the received EAP packet
 * @param[in] length Length of the packet, in bytes
 **/

void supplicantProcessEapPacket(SupplicantContext *context,
   const EapPacket *packet, size_t length)
{
   //Malformed EAP packet?
   if(length < sizeof(EapPacket))
      return;

   //Debug message
   TRACE_DEBUG("EAP packet received (%" PRIuSIZE " bytes)\r\n", length);
   //Dump EAP packet for debugging purpose
   eapDumpPacket(packet, length);

   //The Length field is two octets and indicates the length, in octets, of the
   //EAP packet including the Code, Identifier, Length, and Data fields
   if(ntohs(packet->length) < sizeof(EapPacket))
      return;

   //A message with the Length field set to a value larger than the number of
   //received octets must be silently discarded (refer to RFC 3748, section 4.0)
   if(ntohs(packet->length) > length)
      return;

   //Octets outside the range of the Length field should be treated as data
   //link layer padding and must be ignored upon reception
   length = ntohs(packet->length);

   //Based on the Code field, the EAP layer demultiplexes incoming EAP packets
   //to the EAP peer and authenticator layers
   if(packet->code != EAP_CODE_RESPONSE)
   {
      //Point to the EAP request
      context->eapReqData = (uint8_t *) packet;
      context->eapReqDataLen = length;

      //The eapolEap variable is set TRUE by an external entity if an EAPOL
      //PDU carrying a Packet Type of EAP-Packet is received
      context->eapolEap = TRUE;

      //Invoke EAP to perform whatever processing is needed
      supplicantFsm(context);
   }
}

#endif
