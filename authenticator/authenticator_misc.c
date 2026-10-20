/**
 * @file authenticator_misc.c
 * @brief Helper functions for 802.1X authenticator
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
#define TRACE_LEVEL AUTHENTICATOR_TRACE_LEVEL

//Dependencies
#include "authenticator/authenticator.h"
#include "authenticator/authenticator_fsm.h"
#include "authenticator/authenticator_procedures.h"
#include "authenticator/authenticator_misc.h"
#include "radius/radius.h"
#include "radius/radius_attributes.h"
#include "radius/radius_debug.h"
#include "eap/eap_debug.h"
#include "debug.h"

//Check EAP library configuration
#if (AUTHENTICATOR_SUPPORT == ENABLED)

//PAE group address (refer to IEEE Std 802.1X-2010, section 11.1.1)
static const MacAddr PAE_GROUP_ADDR = {{{0x01, 0x80, 0xC2, 0x00, 0x00, 0x03}}};


/**
 * @brief Handle periodic operations
 * @param[in] context Pointer to the 802.1X authenticator context
 **/

void authenticatorTick(AuthenticatorContext *context)
{
   uint_t i;
   bool_t macOpState;
   AuthenticatorPort *port;

   //Loop through the ports
   for(i = 0; i < context->numPorts; i++)
   {
      //Point to the current port
      port = &context->ports[i];

      //Poll link state
      macOpState = authenticatorGetLinkState(port);

      //Link state change detected?
      if(macOpState && !port->portEnabled)
      {
         //Session statistics for a port can be retained by the system until a
         //new session begins on that port
         port->sessionStats.sessionOctetsRx = 0;
         port->sessionStats.sessionOctetsTx = 0;
         port->sessionStats.sessionFramesRx = 0;
         port->sessionStats.sessionFramesTx = 0;
         port->sessionStats.sessionTime = 0;

         //The port is up
         port->sessionStats.sessionTerminateCause =
            AUTHENTICATOR_TERMINATE_CAUSE_NOT_TERMINATED_YET;
      }
      else if(!macOpState && port->portEnabled)
      {
         //The port is down
         port->sessionStats.sessionTerminateCause =
            AUTHENTICATOR_TERMINATE_CAUSE_PORT_FAILURE;
      }
      else if(macOpState)
      {
         //Duration of the session in seconds
         port->sessionStats.sessionTime++;
      }
      else
      {
         //No link state change
      }

      //The portEnabled variable is externally controlled. Its value reflects
      //the operational state of the MAC service supporting the port
      port->portEnabled = macOpState;

      //Timers are decremented once per second
      authenticatorDecrementTimer(&port->aWhile);
      authenticatorDecrementTimer(&port->quietWhile);
      authenticatorDecrementTimer(&port->reAuthWhen);
      authenticatorDecrementTimer(&port->retransWhile);
      authenticatorDecrementTimer(&port->aaaRetransTimer);
   }

   //Update authenticator state machines
   authenticatorFsm(context);

   //Any registered callback?
   if(context->tickCallback != NULL)
   {
      //Invoke user callback function
      context->tickCallback(context);
   }
}


/**
 * @brief Port's MAC address generation
 * @param[in] port Pointer to the port context
 **/

void authenticatorGeneratePortAddr(AuthenticatorPort *port)
{
   int_t i;
   uint8_t c;
   MacAddr *macAddr;
   AuthenticatorContext *context;

   //Point to the 802.1X authenticator context
   context = port->context;

   //Get the MAC address of the underlying network interface
   macAddr = &context->interface->macAddr;

   //Retrieve port index
   c = port->portIndex;

   //Generate a unique MAC address for the port
   for(i = 5; i >= 0; i--)
   {
      //Generate current byte
      port->macAddr.b[i] = macAddr->b[i] + c;

      //Propagate the carry if necessary
      if(port->macAddr.b[i] < macAddr->b[i])
      {
         c = 1;
      }
      else
      {
         c = 0;
      }
   }
}


/**
 * @brief Get link state
 * @param[in] port Pointer to the port context
 * @return Error code
 **/

bool_t authenticatorGetLinkState(AuthenticatorPort *port)
{
   bool_t linkState;
   NetInterface *interface;
   AuthenticatorContext *context;

   //Point to the 802.1X authenticator context
   context = port->context;
   //Point to the underlying network interface
   interface = context->interface;

   //Valid switch driver?
   if(interface->switchDriver != NULL &&
      interface->switchDriver->getLinkState != NULL)
   {
      //Get exclusive access
      netLock(context->netContext);

      //Retrieve the link state of the specified port
      linkState = interface->switchDriver->getLinkState(interface,
         port->portIndex);

      //Release exclusive access
      netUnlock(context->netContext);
   }
   else
   {
      //Retrieve the link state of the network interface
      linkState = interface->linkState;
   }

   //Return link state
   return linkState;
}


/**
 * @brief Add the PAE group address to the static MAC table
 * @param[in] context Pointer to the 802.1X authenticator context
 * @return Error code
 **/

error_t authenticatorAcceptPaeGroupAddr(AuthenticatorContext *context)
{
   error_t error;
   SwitchFdbEntry entry;
   NetInterface *interface;

   //Initialize status code
   error = NO_ERROR;

   //Point to the underlying network interface
   interface = context->interface;

   //Get exclusive access
   netLock(context->netContext);

   //Valid switch driver?
   if(interface->switchDriver != NULL &&
      interface->switchDriver->addStaticFdbEntry != NULL)
   {
      //Format forwarding database entry
      entry.macAddr = PAE_GROUP_ADDR;
      entry.srcPort = 0;
      entry.destPorts = SWITCH_CPU_PORT_MASK;
      entry.override = TRUE;

      //Update the static MAC table of the switch
      error = interface->switchDriver->addStaticFdbEntry(interface, &entry);
   }

   //Check status code
   if(!error)
   {
      //Add the PAE group address to the MAC filter table
      error = ethAcceptMacAddr(interface, &PAE_GROUP_ADDR);
   }

   //Release exclusive access
   netUnlock(context->netContext);

   //Return status code
   return error;
}


/**
 * @brief Remove the PAE group address from the static MAC table
 * @param[in] context Pointer to the 802.1X authenticator context
 * @return Error code
 **/

error_t authenticatorDropPaeGroupAddr(AuthenticatorContext *context)
{
   error_t error;
   SwitchFdbEntry entry;
   NetInterface *interface;

   //Initialize status code
   error = NO_ERROR;

   //Point to the underlying network interface
   interface = context->interface;

   //Get exclusive access
   netLock(context->netContext);

   //Valid switch driver?
   if(interface->switchDriver != NULL &&
      interface->switchDriver->deleteStaticFdbEntry != NULL)
   {
      //Format forwarding database entry
      entry.macAddr = PAE_GROUP_ADDR;
      entry.srcPort = 0;
      entry.destPorts = 0;
      entry.override = FALSE;

      //Update the static MAC table of the switch
      error = interface->switchDriver->deleteStaticFdbEntry(interface, &entry);
   }

   //Check status code
   if(!error)
   {
      //Remove the PAE group address to the MAC filter table
      ethDropMacAddr(interface, &PAE_GROUP_ADDR);
   }

   //Release exclusive access
   netUnlock(context->netContext);

   //Return status code
   return error;
}


/**
 * @brief Send EAPOL PDU
 * @param[in] port Pointer to the port context
 * @param[in] pdu Pointer to the PDU to be transmitted
 * @param[in] length Length of the PDU, in bytes
 * @return Error code
 **/

error_t authenticatorSendEapolPdu(AuthenticatorPort *port, const uint8_t *pdu,
   size_t length)
{
   SocketMsg msg;

   //Point to the PDU to be transmitted
   msg = SOCKET_DEFAULT_MSG;
   msg.data = (uint8_t *) pdu;
   msg.length = length;

   //The PAE group address is assigned specifically for use by EAPOL clients
   //designed to maximize plug-and-play interoperability, and should be the
   //default for those clients (refer to IEEE Std 802.1X-2010, section 11.1.1)
   msg.destMacAddr = PAE_GROUP_ADDR;

   //The source address for each MAC service request used to transmit an EAPOL
   //MPDU shall be an individual address associated with the service access
   //point at which the request is made (refer to IEEE Std 802.1X-2010,
   //section 11.1.2)
   msg.srcMacAddr = port->macAddr;

   //All EAPOL MPDUs shall be identified using the PAE EtherType (refer to
   //IEEE Std 802.1X-2010, section 11.1.4)
   msg.ethType = ETH_TYPE_EAPOL;

#if (ETH_PORT_TAGGING_SUPPORT == ENABLED)
   //Specify the egress port
   msg.switchPort = port->portIndex;
#endif

   //Number of EAPOL frames of any type that have been transmitted
   port->stats.eapolFramesTx++;

   //Send EAPOL MPDU
   return socketSendMsg(port->context->peerSocket, &msg, 0);
}


/**
 * @brief Process incoming EAPOL PDU
 * @param[in] context Pointer to the 802.1X authenticator context
 **/

void authenticatorProcessEapolPdu(AuthenticatorContext *context)
{
   error_t error;
   size_t length;
   uint_t portIndex;
   SocketMsg msg;
   EapolPdu *pdu;
   AuthenticatorPort *port;

   //Point to the receive buffer
   msg = SOCKET_DEFAULT_MSG;
   msg.data = context->rxBuffer;
   msg.size = AUTHENTICATOR_RX_BUFFER_SIZE;

   //Receive EAPOL MPDU
   error = socketReceiveMsg(context->peerSocket, &msg, 0);
   //Failed to receive packet
   if(error)
      return;

#if (ETH_PORT_TAGGING_SUPPORT == ENABLED)
   //Save the port number on which the EAPOL PDU was received
   portIndex = MAX(msg.switchPort, 1);
#else
   //The station has a single port
   portIndex = 1;
#endif

   //The destination MAC address field must contain the PAE group address
   if(!macCompAddr(&msg.destMacAddr, &PAE_GROUP_ADDR))
      return;

   //The received MPDU must contain the PAE EtherType
   if(msg.ethType != ETH_TYPE_EAPOL)
      return;

   //Malformed EAPOL packet?
   if(msg.length < sizeof(EapolPdu))
      return;

   //Point to the EAPOL packet
   pdu = (EapolPdu *) context->rxBuffer;

   //Debug message
   TRACE_INFO("Port %" PRIu8 ": EAPOL packet received (%" PRIuSIZE " bytes)...\r\n",
      portIndex, msg.length);

   //Dump EAPOL header contents for debugging purpose
   eapolDumpHeader(pdu);

   //Sanity check
   if(portIndex > context->numPorts)
      return;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Any octets following the Packet Body field in the frame conveying the
   //EAPOL PDU shall be ignored (refer to IEEE Std 802.1X-2004, section 11.4)
   length = ntohs(pdu->packetBodyLen);

   //Malformed EAPOL packet?
   if(msg.length < (sizeof(EapolPdu) + length))
   {
      //Number of EAPOL frames that have been received by this authenticator
      //in which the Packet Body Length field is invalid
      port->stats.eapLengthErrorFramesRx++;

      //Exit immediately
      return;
   }

   //Number of valid EAPOL frames of any type that have been received
   port->stats.eapolFramesRx++;
   //Protocol version number carried in the most recently received EAPOL frame
   port->stats.lastEapolFrameVersion = pdu->protocolVersion;

   //Save the MAC address of the supplicant
   port->supplicantMacAddr = msg.srcMacAddr;

   //Check packet type
   if(pdu->packetType == EAPOL_TYPE_EAP)
   {
      //Process incoming EAP packet
      authenticatorProcessEapPacket(port, (EapPacket *) pdu->packetBody,
         length);
   }
   else if(pdu->packetType == EAPOL_TYPE_START)
   {
      //Number of EAPOL Start frames that have been received
      port->stats.eapolStartFramesRx++;

      //The eapolStart variable is set TRUE if an EAPOL PDU carrying a packet
      //type of EAPOL-Start is received
      port->eapolStart = TRUE;
   }
   else if(pdu->packetType == EAPOL_TYPE_LOGOFF)
   {
      //Number of EAPOL Logoff frames that have been received
      port->stats.eapolLogoffFramesRx++;

      //The Logoff variable is set TRUE if an EAPOL PDU carrying a packet type
      //of EAPOL-Logoff is received
      port->eapolLogoff = TRUE;
   }
   else
   {
      //Number of EAPOL frames that have been received by this authenticator
      //in which the frame type is not recognized
      port->stats.invalidEapolFramesRx++;
   }
}


/**
 * @brief Process incoming EAP packet
 * @param[in] port Pointer to the port context
 * @param[in] packet Pointer to the received EAP packet
 * @param[in] length Length of the packet, in bytes
 **/

void authenticatorProcessEapPacket(AuthenticatorPort *port,
   const EapPacket *packet, size_t length)
{
   //Malformed EAP packet?
   if(length < sizeof(EapPacket))
      return;

   //Debug message
   TRACE_DEBUG("Port %" PRIu8 ": EAP packet received (%" PRIuSIZE " bytes)...\r\n",
      port->portIndex, length);

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
   if(packet->code == EAP_CODE_RESPONSE)
   {
      //Point to the EAP response
      port->eapRespData = (uint8_t *) packet;
      port->eapRespDataLen = length;

      //The eapolEap variable is set TRUE by an external entity if an EAPOL
      //PDU carrying a Packet Type of EAP-Packet is received
      port->eapolEap = TRUE;

      //Invoke EAP to perform whatever processing is needed
      authenticatorFsm(port->context);
   }
   else
   {
      //Unless a host implements an EAP peer layer, EAP Request, Success and
      //Failure packets will be silently discarded (refer to RFC 3748,
      //section 2.3)
   }
}


/**
 * @brief Build RADIUS Access-Request packet
 * @param[in] port Pointer to the port context
 **/

error_t authenticatorBuildRadiusRequest(AuthenticatorPort *port)
{
   error_t error;
   size_t i;
   size_t n;
   IpAddr ipAddr;
   MacAddr macAddr;
   RadiusPacket *packet;
   AuthenticatorContext *context;
   uint8_t buffer[32];

   //Point to the 802.1X authenticator context
   context = port->context;

   //Total length of the RADIUS packet
   port->aaaReqDataLen = 0;

   //The Request Authenticator value must be changed each time a new
   //Identifier is used (refer to RFC 2865, section 4.1)
   error = context->prngAlgo->generate(context->prngContext,
      port->reqAuthenticator, 16);
   //Any error to report?
   if(error)
      return error;

   //Generate a new RADIUS packet identifier
   port->aaaReqId = authenticatorGetNextRadiusId(context);

   //Point to the buffer where to format the RADIUS packet
   packet = (RadiusPacket *) port->aaaReqData;

   //The Length field indicates the length of the packet including the Code,
   //Identifier, Length, Authenticator and Attribute fields
   n = sizeof(RadiusPacket);

   //Format RADIUS packet
   packet->code = RADIUS_CODE_ACCESS_REQUEST;
   packet->identifier = port->aaaReqId;
   packet->length = htons(n);

   //The Authenticator field is 16 octets. This value is used to authenticate
   //the reply from the RADIUS server (refer to RFC 2865, section 3)
   osMemcpy(packet->authenticator, port->reqAuthenticator, 16);

   //The NAS must include the Type-Data field of the EAP-Response/Identity
   //in the User-Name attribute in every subsequent Access-Request (refer to
   //RFC 3579, section 2.1)
   radiusAddAttribute(packet, RADIUS_ATTR_USER_NAME, port->aaaIdentity,
      osStrlen(port->aaaIdentity));

   //The Service-Type attribute indicates the type of service the user has
   //requested, or the type of service to be provided (refer to RFC 2865,
   //section 5.6)
   STORE32BE(RADIUS_SERVICE_TYPE_FRAMED, buffer);

   //Add Service-Type attribute
   radiusAddAttribute(packet, RADIUS_ATTR_SERVICE_TYPE, buffer,
      sizeof(uint32_t));

   //The Framed-MTU attribute indicates the Maximum Transmission Unit to be
   //configured for the user (refer to RFC 2865, section 5.12)
   STORE32BE(EAP_MAX_FRAG_SIZE, buffer);

   //Add Framed-MTU attribute
   radiusAddAttribute(packet, RADIUS_ATTR_FRAMED_MTU, buffer,
      sizeof(uint32_t));

   //Get exclusive access
   netLock(context->netContext);

   //Retrieve the IP address of the NAS
   error = ipSelectSourceAddr(context->netContext, &context->serverInterface,
      &context->serverIpAddr, &ipAddr);

   //Release exclusive access
   netUnlock(context->netContext);

   //Any error to report?
   if(error)
      return error;

   //Either NAS-Identifier, NAS-IP-Address or NAS-IPv6-Address attributes
   //must be included (refer to RFC 3579, section 3)
   if(ipAddr.length == sizeof(Ipv4Addr))
   {
      radiusAddAttribute(packet, RADIUS_ATTR_NAS_IP_ADDR, &ipAddr.addr,
         ipAddr.length);
   }
   else if(ipAddr.length == sizeof(Ipv6Addr))
   {
      radiusAddAttribute(packet, RADIUS_ATTR_NAS_IPV6_ADDR, &ipAddr.addr,
         ipAddr.length);
   }
   else
   {
      return ERROR_INVALID_ADDRESS;
   }

   //The NAS-Port attribute indicates the physical port number of the NAS which
   //is authenticating the user (refer to RFC 2865, section 5.5)
   STORE32BE(port->portIndex, buffer);

   //Add NAS-Port attribute
   radiusAddAttribute(packet, RADIUS_ATTR_NAS_PORT, buffer, sizeof(uint32_t));

   //The NAS-Port-Type attribute indicates the type of the physical port of
   //the NAS which is authenticating the user. It can be used instead of or in
   //addition to the NAS-Port attribute (refer to RFC 2865, section 5.41)
   STORE32BE(RADIUS_PORT_TYPE_ETHERNET, buffer);

   //Add NAS-Port-Type attribute
   radiusAddAttribute(packet, RADIUS_ATTR_NAS_PORT_TYPE, buffer,
      sizeof(uint32_t));

   //The NAS-Port-Id attribute contains a text string which identifies the
   //port of the NAS which is authenticating the user (refer to RFC 2869,
   //section 5.17)
   osSprintf((char_t *) buffer, "%s_%" PRIu8, context->interface->name,
      port->portIndex);

   radiusAddAttribute(packet, RADIUS_ATTR_NAS_PORT_ID, buffer,
      osStrlen((char_t *) buffer));

   //Retrieve the MAC address of the bridge
   netGetMacAddr(context->serverInterface, &macAddr);
   macAddrToString(&macAddr, (char_t *) buffer);

   //The Called-Station-Id attribute is used to store the bridge or access
   //point MAC address in ASCII format (refer to RFC 3580, section 3.20)
   radiusAddAttribute(packet, RADIUS_ATTR_CALLED_STATION_ID, buffer,
      osStrlen((char_t *) buffer));

   //Retrieve the MAC address of the supplicant
   macAddrToString(&port->supplicantMacAddr, (char_t *) buffer);

   //The Calling-Station-Id attribute is used to store the supplicant MAC
   //address in ASCII format (refer to RFC 3580, section 3.21)
   radiusAddAttribute(packet, RADIUS_ATTR_CALLING_STATION_ID, buffer,
      osStrlen((char_t *) buffer));

   //Any State attribute received from previous Access-Challenge?
   if(port->serverStateLen > 0)
   {
      //The NAS must include the State attribute unchanged in that
      //Access-Request (refer to RFC 2865, section 5.24)
      radiusAddAttribute(packet, RADIUS_ATTR_STATE, port->serverState,
         port->serverStateLen);
   }

   //The NAS places EAP messages received from the authenticating peer into
   //one or more EAP-Message attributes and forwards them to the RADIUS server
   //within an Access-Request message (refer to RFC 3579, section 3.1)
   for(i = 0; i < port->eapRespDataLen; i += n)
   {
      //Each attribute can contain up to 253 octets of binary data
      n = MIN(port->eapRespDataLen - i, RADIUS_MAX_ATTR_VALUE_LEN);

      //Make sure the buffer is large enough to hold the EAP-Message attribute
      if((htons(packet->length) + sizeof(RadiusAttribute) + n) >
         AUTHENTICATOR_TX_BUFFER_SIZE)
      {
         return ERROR_BUFFER_OVERFLOW;
      }

      //If multiple EAP-Message attributes are contained within an Access-
      //Request, they must be in order and they must be consecutive attributes
      radiusAddAttribute(packet, RADIUS_ATTR_EAP_MESSAGE,
         port->eapRespData + i, n);
   }

   //When the checksum is calculated the signature string should be considered
   //to be sixteen octets of zero (refer to RFC 2869, section 5.14)
   osMemset(buffer, 0, MD5_DIGEST_SIZE);

   //Make sure the buffer is large enough to hold the Message-Authenticator
   //attribute
   if((htons(packet->length) + sizeof(RadiusAttribute) + MD5_DIGEST_SIZE) >
      AUTHENTICATOR_TX_BUFFER_SIZE)
   {
      return ERROR_BUFFER_OVERFLOW;
   }

   //Add Message-Authenticator attribute
   radiusAddAttribute(packet, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, buffer,
      MD5_DIGEST_SIZE);

   //Retrieve the total length of the RADIUS packet
   n = htons(packet->length);

   //Transactions between the client and RADIUS server are authenticated through
   //the use of a shared secret (refer to RFC 2865, section 1)
   error = hmacInit(&context->hmacContext, MD5_HASH_ALGO, context->serverKey,
      context->serverKeyLen);
   //Any error to report?
   if(error)
      return error;

   //When present in an Access-Request packet, Message-Authenticator is an
   //HMAC-MD5 hash of the entire Access-Request packet, including Type, ID,
   //Length and Authenticator, using the shared secret as the key (refer to
   //RFC 3579, section 3.2)
   hmacUpdate(&context->hmacContext, port->aaaReqData, n);
   hmacFinal(&context->hmacContext, buffer);

   //Copy the resulting HMAC-MD5 hash
   osMemcpy(port->aaaReqData + n - MD5_DIGEST_SIZE, buffer, MD5_DIGEST_SIZE);

   //Save the total length of the RADIUS packet
   port->aaaReqDataLen = n;
   //Initialize retransmission counter
   port->aaaRetransCount = 0;

   //Sucessful processing
   return NO_ERROR;
}


/**
 * @brief Send RADIUS Access-Request packet
 * @param[in] port Pointer to the port context
 **/

error_t authenticatorSendRadiusRequest(AuthenticatorPort *port)
{
   error_t error;
   SocketMsg msg;
   AuthenticatorContext *context;

   //Initialize status code
   error = NO_ERROR;

   //Point to the 802.1X authenticator context
   context = port->context;

   //Valid RADIUS packet?
   if(port->aaaReqDataLen > 0)
   {
      //Exactly one RADIUS packet is encapsulated in the UDP data field,
      //where the UDP destination Port field indicates 1812 (refer to
      //RFC 2865, section 3)
      msg = SOCKET_DEFAULT_MSG;
      msg.data = port->aaaReqData;
      msg.length = port->aaaReqDataLen;
      msg.destIpAddr = context->serverIpAddr;
      msg.destPort = context->serverPort;

#if (ETH_PORT_TAGGING_SUPPORT == ENABLED)
      //Specify the egress port
      msg.switchPort = context->serverPortIndex;
#endif

      //Debug message
      TRACE_INFO("Sending RADIUS packet (%" PRIuSIZE " bytes)...\r\n",
         port->aaaReqDataLen);

      //Dump RADIUS header contents for debugging purpose
      radiusDumpPacket((RadiusPacket *) port->aaaReqData, port->aaaReqDataLen);

      //Send UDP datagram
      error = socketSendMsg(context->serverSocket, &msg, 0);

      //Increment retransmission counter
      port->aaaRetransCount++;
      //Set retransmission timeout
      port->aaaRetransTimer = AUTHENTICATOR_RADIUS_TIMEOUT;
   }

   //Return status code
   return error;
}


/**
 * @brief Process incoming RADIUS packet
 * @param[in] context Pointer to the 802.1X authenticator context
 **/

void authenticatorProcessRadiusPacket(AuthenticatorContext *context)
{
   error_t error;
   uint_t i;
   size_t n;
   size_t length;
   SocketMsg msg;
   AuthenticatorPort *port;
   EapPacket *eapPacket;
   const RadiusPacket *packet;
   const RadiusAttribute *attribute;
   Md5Context *md5Context;
   HmacContext *hmacContext;
   uint8_t digest[MD5_DIGEST_SIZE];

   //Point to the receive buffer
   msg = SOCKET_DEFAULT_MSG;
   msg.data = context->rxBuffer;
   msg.size = AUTHENTICATOR_RX_BUFFER_SIZE;

   //Receive EAPOL MPDU
   error = socketReceiveMsg(context->serverSocket, &msg, 0);
   //Failed to receive packet
   if(error)
      return;

   //Debug message
   TRACE_INFO("RADIUS packet received (%" PRIuSIZE " bytes)...\r\n",
      msg.length);

#if (ETH_PORT_TAGGING_SUPPORT == ENABLED)
   //Check the port number on which the EAPOL PDU was received
   if(msg.switchPort != context->serverPortIndex && context->serverPortIndex != 0)
      return;
#endif

   //Ensure the source IP address matches the RADIUS server's IP address
   if(!ipCompAddr(&msg.srcIpAddr, &context->serverIpAddr))
      return;

   //The officially assigned port number for RADIUS is 1812 (refer to RFC 2865,
   //section 3)
   if(msg.srcPort != context->serverPort)
      return;

   //Malformed RADIUS packet?
   if(msg.length < sizeof(RadiusPacket))
      return;

   //Point to the RADIUS packet
   packet = (RadiusPacket *) context->rxBuffer;

   //Octets outside the range of the Length field must be treated as padding
   //and ignored on reception (refer to RFC 2865, section 3)
   length = ntohs(packet->length);

   //If the packet is shorter than the Length field indicates, it must be
   //silently discarded
   if(msg.length < length)
      return;

   //The minimum length is 20 and maximum length is 4096
   if(length < sizeof(RadiusPacket) || length > RADIUS_MAX_PACKET_SIZE)
      return;

   //Dump RADIUS header contents for debugging purpose
   radiusDumpPacket(packet, length);

   //Calculate the length of the RADIUS attributes
   length -= sizeof(RadiusPacket);

   //The RADIUS packet type is determined by the Code field
   if(packet->code != RADIUS_CODE_ACCESS_ACCEPT &&
      packet->code != RADIUS_CODE_ACCESS_REJECT &&
      packet->code != RADIUS_CODE_ACCESS_CHALLENGE)
   {
      return;
   }

   //The Identifier field aids in matching requests and replies
   for(i = 0; i < context->numPorts; i++)
   {
      //Point to the current port
      port = &context->ports[i];

      //The Identifier field is matched with a pending Access-Request
      if(port->eapFullAuthState == EAP_FULL_AUTH_STATE_AAA_IDLE &&
         !port->aaaEapResp)
      {
         //Matching identifier?
         if(port->aaaReqId == packet->identifier)
         {
            break;
         }
      }
   }

   //No matching request found?
   if(i >= context->numPorts)
      return;

   //Point to the MD5 context
   md5Context = &context->hmacContext.hashContext.md5Context;
   //Initialize MD5 calculation
   md5Init(md5Context);

   //The Response Authenticator contains a one-way MD5 hash calculated over the
   //RADIUS packet, beginning with the Code field, including the Identifier, the
   //Length, the Request Authenticator field from the Access-Request packet, and
   //the response Attributes, followed by the shared secret (refer to RFC 2865,
   //section 3)
   md5Update(md5Context, packet, 4);
   md5Update(md5Context, port->reqAuthenticator, 16);
   md5Update(md5Context, packet->attributes, length);
   md5Update(md5Context, context->serverKey, context->serverKeyLen);
   md5Final(md5Context, digest);

   //Debug message
   TRACE_DEBUG("Calculated Response Authenticator:\r\n");
   TRACE_DEBUG_ARRAY("  ", digest, MD5_DIGEST_SIZE);

   //The Response Authenticator field must contain the correct response for the
   //pending Access-Request. Invalid packets are silently discarded
   if(osMemcmp(digest, packet->authenticator, MD5_DIGEST_SIZE) != 0)
   {
      //Debug message
      TRACE_WARNING("Invalid Response Authenticator value!\r\n");
      //Exit immediately
      return;
   }

   //The Message-Authenticator attribute must be used to protect all
   //Access-Request, Access-Challenge, Access-Accept, and Access-Reject
   //packets containing an EAP-Message attribute (refer to RFC 3579,
   //section 3.2)
   attribute = radiusGetAttribute(packet, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 0);

   //Access-Challenge, Access-Accept, or Access-Reject packets including
   //EAP-Message attribute(s) without a Message-Authenticator attribute should
   //be silently discarded by the NAS (refer to RFC 3579, section 3.1)
   if(attribute == NULL)
      return;

   //Malformed Message-Authenticator attribute?
   if(attribute->length != (sizeof(RadiusAttribute) + MD5_DIGEST_SIZE))
      return;

   //Save the offset to the Message-Authenticator value
   n = attribute->value - packet->attributes;

   //When the checksum is calculated the signature string should be considered
   //to be sixteen octets of zero (refer to RFC 2869, section 5.14)
   osMemset(digest, 0, MD5_DIGEST_SIZE);

   //Point to the HMAC context
   hmacContext = &context->hmacContext;

   //Initialize HMAC-MD5 calculation
   error = hmacInit(hmacContext, MD5_HASH_ALGO, context->serverKey,
      context->serverKeyLen);
   //Any error to report?
   if(error)
      return;

   //For Access-Challenge, Access-Accept, and Access-Reject packets, the
   //Message-Authenticator is calculated as follows, using the Request-
   //Authenticator from the Access-Request this packet is in reply to (refer
   //to RFC 3579, section 3.2)
   hmacUpdate(hmacContext, packet, 4);
   hmacUpdate(hmacContext, port->reqAuthenticator, 16);
   hmacUpdate(hmacContext, packet->attributes, n);
   hmacUpdate(hmacContext, digest, 16);
   hmacUpdate(hmacContext, packet->attributes + n + 16, length - n - 16);
   hmacFinal(hmacContext, digest);

   //Debug message
   TRACE_DEBUG("Calculated Message Authenticator:\r\n");
   TRACE_DEBUG_ARRAY("  ", digest, MD5_DIGEST_SIZE);

   //A NAS supporting the EAP-Message attribute must calculate the correct
   //value of the Message-Authenticator and must silently discard the packet
   //if it does not match the value sent (refer to RFC 3579, section 3.1)
   if(osMemcmp(digest, attribute->value, MD5_DIGEST_SIZE) != 0)
   {
      //Debug message
      TRACE_WARNING("Invalid Message Authenticator value!\r\n");
      //Exit immediately
      return;
   }

   //Search the RADIUS packet for the State attribute
   attribute = radiusGetAttribute(packet, RADIUS_ATTR_STATE, 0);

   //State attribute found?
   if(attribute != NULL)
   {
      //Retrieve the length of the attribute value
      n = attribute->length - sizeof(RadiusAttribute);

      //Check the length of the attribute
      if(n >= 1 && n <= AUTHENTICATOR_MAX_STATE_SIZE)
      {
         //The actual format of the information is site or application
         //specific, and a robust implementation should support the field
         //as undistinguished octets (refer to RFC 2865, section 5.24)
         osMemcpy(port->serverState, attribute->value, n);
         port->serverStateLen = n;
      }
   }

   //EAP-Message attribute(s) encapsulate a single EAP packet which the NAS
   //decapsulates and passes on to the authenticating peer
   port->aaaEapReqDataLen = 0;

   //Decapsulate the EAP packet
   for(i = 0; ; i++)
   {
      //Point to the next EAP-Message attribute
      attribute = radiusGetAttribute(packet, RADIUS_ATTR_EAP_MESSAGE, i);

      //EAP-Message attribute found?
      if(attribute != NULL)
      {
         //Retrieve the length of the fragment
         n = attribute->length - sizeof(RadiusAttribute);

         //Make sure the buffer is large enough to hold the reconstructed EAP
         //packet
         if((port->aaaEapReqDataLen + n) <= AUTHENTICATOR_TX_BUFFER_SIZE)
         {
            //Copy the current fragment
            osMemcpy(context->txBuffer + port->aaaEapReqDataLen,
               attribute->value, n);

            //Adjust the length of the reconstructed EAP packet
            port->aaaEapReqDataLen += n;
         }
         else
         {
            //The reassembly process failed
            port->aaaEapReqDataLen = 0;
            break;
         }
      }
      else
      {
         //The reassembly process is now complete
         break;
      }
   }

   //Malformed EAP packet?
   if(port->aaaEapReqDataLen < sizeof(EapPacket))
      return;

   //Point to the EAP packet
   eapPacket = (EapPacket *) context->txBuffer;

   //Check Code field
   if(eapPacket->code == EAP_CODE_REQUEST ||
      eapPacket->code == EAP_CODE_SUCCESS ||
      eapPacket->code == EAP_CODE_FAILURE)
   {
      //The corresponding request (or success/failure) packet is stored in
      //aaaEapReqData
      osMemcpy(port->aaaEapReqData, context->txBuffer, port->aaaEapReqDataLen);

      //Debug message
      TRACE_DEBUG("Port %" PRIu8 ": Sending EAP packet (%" PRIuSIZE " bytes)...\r\n",
         port->portIndex, port->aaaEapReqDataLen);

      //Dump EAP packet for debugging purpose
      eapDumpPacket(eapPacket, port->aaaEapReqDataLen);

      //When the authenticator has finished processing the message, it sets one
      //of the signals aaaEapReq, aaaSuccess, and aaaFail
      if(eapPacket->code == EAP_CODE_REQUEST)
      {
         port->aaaEapReq = TRUE;
      }
      else if(eapPacket->code == EAP_CODE_SUCCESS)
      {
         port->aaaSuccess = TRUE;
      }
      else
      {
         port->aaaFail = TRUE;
      }

   }
   else
   {
      //The aaaEapNoReq flag indicates that the most recent response has been
      //processed, but that there is no new request to send
      port->aaaEapNoReq = TRUE;
   }

   //Invoke EAP to perform whatever processing is needed
   authenticatorFsm(port->context);
}


/**
 * @brief Generate a new RADIUS packet identifier
 * @param[in] context Pointer to the 802.1X authenticator context
 **/

uint8_t authenticatorGetNextRadiusId(AuthenticatorContext *context)
{
   uint_t i;
   bool_t acceptable;
   AuthenticatorPort *port;

   //Generate a new RADIUS packet identifier
   do
   {
      //Increment identifier value
      context->radiusId++;

      //Loop through the ports
      for(acceptable = TRUE, i = 0; i < context->numPorts; i++)
      {
         //Point to the current port
         port = &context->ports[i];

         //Pending Access-Request?
         if(port->eapFullAuthState == EAP_FULL_AUTH_STATE_AAA_IDLE &&
            !port->aaaEapResp)
         {
            //Check whether the identifier is a duplicate
            if(port->aaaReqId == context->radiusId)
            {
               acceptable = FALSE;
            }
         }
      }

      //Repeat as necessary until a unique identifier value is generated
   } while(!acceptable);

   //Return the identifier value
   return context->radiusId;
}

#endif
