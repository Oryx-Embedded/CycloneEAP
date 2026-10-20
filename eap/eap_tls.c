/**
 * @file eap_tls.c
 * @brief EAP-TLS authentication method
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
#include "eap/eap_tls.h"
#include "eap/eap_debug.h"
#include "debug.h"

//Check EAP library configuration
#if (EAP_TLS_SUPPORT == ENABLED)


/**
 * @brief Check incoming EAP-TLS request
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] request Pointer to the received request
 * @param[in] length Length of the request, in bytes
 **/

error_t eapTlsCheckRequest(SupplicantContext *context,
   const EapTlsPacket *request, size_t length)
{
   //Check the length of the EAP request
   if(length < sizeof(EapTlsPacket))
   {
      return ERROR_INVALID_LENGTH;
   }

   //The L flag is set to indicate the presence of the four-octet TLS Message
   //Length field (refer to RFC 5216, section 2.1.5)
   if((request->flags & EAP_TLS_FLAGS_L) != 0)
   {
      //Malformed request?
      if(length < (sizeof(EapTlsPacket) + sizeof(uint32_t)))
      {
         return ERROR_INVALID_LENGTH;
      }
   }

   //The request is valid
   return NO_ERROR;
}


/**
 * @brief Process incoming EAP-TLS request
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] request Pointer to the received request
 * @param[in] length Length of the request, in bytes
 **/

void eapTlsProcessRequest(SupplicantContext *context,
   const EapTlsPacket *request, size_t length)
{
   error_t error;
   size_t n;
   uint8_t data;

   //Check method state
   if(context->methodState == EAP_METHOD_STATE_INIT)
   {
      //The method starts by initializing its own method-specific state
      context->txBufferWritePos = EAP_TLS_TX_BUFFER_START_POS;
      context->txBufferReadPos = EAP_TLS_TX_BUFFER_START_POS;
      context->txBufferLen = 0;
      context->rxBufferPos = 0;
      context->rxBufferLen = 0;

      //Abort previous TLS session, if any
      eapCloseTls(context, ERROR_CONNECTION_RESET);

      //The S flag is set only within the EAP-TLS start message sent from the
      //EAP server to the peer (refer to RFC 5216, section 2.1.5)
      if((request->flags & EAP_TLS_FLAGS_S) != 0)
      {
         //Initialize TLS context
         error = eapOpenTls(context);

         //Check status code
         if(!error)
         {
            //Restore TLS session
            error = tlsRestoreSessionState(context->tlsContext,
               &context->tlsSession);
         }

         //Check status code
         if(!error)
         {
            //The EAP-TLS conversation will then begin with the peer sending an
            //EAP-Response containing a TLS ClientHello handshake message
            error = tlsConnect(context->tlsContext);
         }
      }
      else
      {
         //The S flag is not set
         error = ERROR_INVALID_REQUEST;
      }
   }
   else if(context->methodState == EAP_METHOD_STATE_CONT ||
      context->methodState == EAP_METHOD_STATE_MAY_CONT)
   {
      //The data consists of the encapsulated TLS packet in TLS record format
      //(refer to RFC 5216, section 3.2)
      context->rxBufferPos = request->data - context->rxBuffer;
      context->rxBufferLen = length - sizeof(EapTlsPacket);

      //The L flag is set to indicate the presence of the four-octet TLS
      //Message Length field (refer to RFC 5216, section 2.1.5)
      if((request->flags & EAP_TLS_FLAGS_L) != 0)
      {
         //The TLS Message Length field provides the total length of the TLS
         //message or set of messages that is being fragmented
         n = LOAD32BE(request->data);

         //Point to the next field
         context->rxBufferPos += sizeof(uint32_t);
         context->rxBufferLen -= sizeof(uint32_t);
      }

      //Perform TLS handshake
      error = tlsConnect(context->tlsContext);

      //Check status code
      if(!error)
      {
         //EAP-TLS with TLS 1.3?
         if(context->tlsContext->version == TLS_VERSION_1_3)
         {
            //When an EAP-TLS server has successfully processed the TLS client
            //Finished and sent its last handshake message (Finished or a
            //post-handshake message), it sends an encrypted TLS record with
            //application data 0x00 (refer to RFC 9190, section 2.5)
            error = tlsRead(context->tlsContext, &data, sizeof(data), &n, 0);

            //Check status code
            if(!error)
            {
               //The 0x00 byte serves as protected success indication
               if(n != sizeof(data) || data != 0x00)
               {
                  //Report an error
                  error = ERROR_UNEXPECTED_VALUE;
               }
            }
         }
      }

      //Check status code
      if(!error)
      {
         //Save TLS session
         error = tlsSaveSessionState(context->tlsContext,
            &context->tlsSession);
      }
   }
   else
   {
      //Invalid method state
      error = ERROR_WRONG_STATE;
   }

   //Next, the method must update methodState and decision (refer to RFC 4137,
   //section 4.2)
   if(error == ERROR_WOULD_BLOCK)
   {
      //The authenticator can decide either to continue the method or to end
      //the conversation
      context->methodState = EAP_METHOD_STATE_MAY_CONT;

      //The decision variable is always set to FAIL
      context->decision = EAP_DECISION_FAIL;
   }
   else
   {
      //The method never continues at this point
      context->methodState = EAP_METHOD_STATE_DONE;

      //Check whether the EAP-TLS mutual authentication is successful
      if(error == NO_ERROR)
      {
         //If both the server has informed us that it will allow access, and
         //the next packet will be EAP Success, and we're willing to use this
         //access, set decision to UNCOND_SUCC
         context->decision = EAP_DECISION_UNCOND_SUCC;
      }
      else
      {
         //If either the authenticator has informed us that it will not allow
         //access, or we're not willing to talk to this authenticator, set
         //decision to FAIL
         context->decision = EAP_DECISION_FAIL;
      }

      //Close TLS session
      eapCloseTls(context, error);
   }
}


/**
 * @brief Build EAP-TLS response
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void eapTlsBuildResponse(SupplicantContext *context)
{
   size_t n;
   size_t fragLen;
   uint8_t *p;
   EapTlsPacket *response;

   //Point to the buffer where to format the EAP packet
   response = (EapTlsPacket *) context->eapRespData;

   //Format EAP packet
   response->code = EAP_CODE_RESPONSE;
   response->identifier = context->reqId;
   response->type = EAP_METHOD_TYPE_TLS;
   response->flags = 0;

   //Point to the next field
   p = response->data;
   n = sizeof(EapTlsPacket);

   //Check the length of the TLS handshake message
   if(context->txBufferLen <= EAP_TLS_MAX_FRAG_SIZE)
   {
      //TLS handshake messages should not be fragmented into multiple TLS
      //records if they fit within a single TLS record (refer to RFC 5216,
      //section 2.1.5)
      fragLen = context->txBufferLen;
   }
   else
   {
      //The M bit is set on all but the last fragment (refer to RFC 5216,
      //section 3.2)
      response->flags |= EAP_TLS_FLAGS_M;

      //First fragment?
      if(context->txBufferReadPos == EAP_TLS_TX_BUFFER_START_POS)
      {
         //The L bit is set to indicate the presence of the four-octet TLS
         //Message Length field, and must be set for the first fragment of a
         //fragmented TLS message or set of messages
         response->flags |= EAP_TLS_FLAGS_L;

         //The TLS Message Length field provides the total length of the TLS
         //message or set of messages that is being fragmented
         STORE32BE(context->txBufferLen, p);

         //Point to the next field
         p += sizeof(uint32_t);
         n += sizeof(uint32_t);

         //Calculate the length of the first fragment
         fragLen = MIN(context->txBufferLen, EAP_TLS_MAX_INIT_FRAG_SIZE);
      }
      else
      {
         //Calculate the length of subsequent fragments
         fragLen = MIN(context->txBufferLen, EAP_TLS_MAX_FRAG_SIZE);
      }
   }

   //The data consists of the encapsulated TLS packet in TLS record format
   //(refer to RFC 5216, section 3.1)
   osMemmove(p, context->txBuffer + context->txBufferReadPos, fragLen);

   //Total length of the EAP packet
   n += fragLen;
   //Convert the length field to network byte order
   response->length = htons(n);

   //Debug message
   TRACE_DEBUG("Sending EAP packet (%" PRIuSIZE " bytes)\r\n", n);
   //Dump EAP packet for debugging purpose
   eapDumpPacket((EapPacket *) response, n);

   //Save the length of the EAP response
   context->eapRespDataLen = n;

   //Point to the next fragment
   context->txBufferReadPos += fragLen;
   context->txBufferLen -= fragLen;

   //Last fragment?
   if(context->txBufferLen == 0)
   {
      //Flush transmit buffer
      context->txBufferWritePos = EAP_TLS_TX_BUFFER_START_POS;
      context->txBufferReadPos = EAP_TLS_TX_BUFFER_START_POS;
      context->txBufferLen = 0;
   }
}


/**
 * @brief Open TLS session
 * @param[in] context Pointer to the 802.1X supplicant context
 * @return Error code
 **/

error_t eapOpenTls(SupplicantContext *context)
{
   error_t error;

   //Initialize TLS context
   context->tlsContext = tlsInit();
   //Initialization failed?
   if(context->tlsContext == NULL)
   {
      return ERROR_OUT_OF_MEMORY;
   }

   //Set the transport protocol to be used (EAP)
   error = tlsSetTransportProtocol(context->tlsContext,
      TLS_TRANSPORT_PROTOCOL_EAP);
   //Any error to report?
   if(error)
   {
      return error;
   }

   //Set send and receive callbacks (I/O abstraction layer)
   error = tlsSetSocketCallbacks(context->tlsContext, eapTlsSendCallback,
      eapTlsReceiveCallback, (TlsSocketHandle) context);
   //Any error to report?
   if(error)
   {
      return error;
   }

   //Select client operation mode
   error = tlsSetConnectionEnd(context->tlsContext, TLS_CONNECTION_END_CLIENT);
   //Any error to report?
   if(error)
   {
      return error;
   }

   //Invoke user-defined callback, if any
   if(context->tlsInitCallback != NULL)
   {
      //Perform TLS related initialization
      error = context->tlsInitCallback(context, context->tlsContext);
      //Any error to report?
      if(error)
      {
         return error;
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Close TLS session
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] error Status code describing the reason for closing the TLS
 *   session
 **/

void eapCloseTls(SupplicantContext *context, error_t error)
{
   //Valid TLS context?
   if(context->tlsContext != NULL)
   {
      //Invoke user-defined callback, if any
      if(context->tlsCompleteCallback != NULL)
      {
         context->tlsCompleteCallback(context, context->tlsContext, error);
      }

      //Release TLS context
      tlsFree(context->tlsContext);
      context->tlsContext = NULL;
   }
}


/**
 * @brief TLS send callback (I/O abstraction layer)
 * @param[in] handle Pointer the 802.1X supplicant context
 * @param[in] data Pointer to a buffer containing the data to be transmitted
 * @param[in] length Number of data bytes to send
 * @param[out] written Number of bytes that have been transmitted
 * @param[in] flags Unused parameter
 * @return Error code
 **/

error_t eapTlsSendCallback(void *handle, const void *data, size_t length,
   size_t *written, uint_t flags)
{
   error_t error;
   SupplicantContext *context;

   //Point to the 802.1X supplicant context
   context = (SupplicantContext *) handle;

   //Make sure the datagram is large enough to hold the TLS message
   if((context->txBufferWritePos + length) <= SUPPLICANT_TX_BUFFER_SIZE)
   {
      //The data consists of the encapsulated TLS packet in TLS record format
      //(refer to RFC 5216, section 3.1)
      osMemcpy(context->txBuffer + context->txBufferWritePos, data, length);

      //Adjust the total length of the data
      context->txBufferWritePos += length;
      context->txBufferLen += length;

      //Total number of data that have been written
      *written = length;

      //Successful processing
      error = NO_ERROR;

   }
   else
   {
      //Report an error
      error = ERROR_BUFFER_OVERFLOW;
   }

   //Return status code
   return error;
}


/**
 * @brief TLS receive callback (I/O abstraction layer)
 * @param[in] handle Pointer the 802.1X supplicant context
 * @param[out] data Buffer where to store the incoming data
 * @param[in] size Maximum number of bytes that can be received
 * @param[out] received Number of bytes that have been received
 * @param[in] flags Unused parameter
 * @return Error code
 **/

error_t eapTlsReceiveCallback(void *handle, void *data, size_t size,
   size_t *received, uint_t flags)
{
   error_t error;
   size_t n;
   SupplicantContext *context;

   //Point to the 802.1X supplicant context
   context = (SupplicantContext *) handle;

   //Any data pending in the receive buffer?
   if(context->rxBufferLen > 0)
   {
      //Limit the number of bytes to copy
      n = MIN(context->rxBufferLen, size);

      //The data consists of the encapsulated TLS packet in TLS record format
      //(refer to RFC 5216, section 3.2)
      osMemcpy(data, context->rxBuffer + context->rxBufferPos, n);

      //Number of bytes left to process
      context->rxBufferPos += n;
      context->rxBufferLen -= n;

      //Total number of data that have been received
      *received = n;

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //Report an error
      error = ERROR_WOULD_BLOCK;
   }

   //Return status code
   return error;
}

#endif
