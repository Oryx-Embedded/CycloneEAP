/**
 * @file eap_debug.c
 * @brief Data logging functions for debugging purpose (EAP)
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
#include "eap/eap_debug.h"
#include "debug.h"

//Check EAP library configuration
#if (EAP_SUPPORT == ENABLED)

#if(EAP_TRACE_LEVEL >= TRACE_LEVEL_DEBUG)

//EAPOL packet types
static const EapParamName eapolPacketTypeList[] =
{
   {EAPOL_TYPE_EAP,                    "EAPOL-EAP"},
   {EAPOL_TYPE_START,                  "EAPOL-Start"},
   {EAPOL_TYPE_LOGOFF,                 "EAPOL-Logoff"},
   {EAPOL_TYPE_KEY,                    "EAPOL-Key"},
   {EAPOL_TYPE_ENCAPSULATED_ASF_ALERT, "EAPOL-Encapsulated-ASF-Alert"}
};

//EAP codes
static const EapParamName eapCodeList[] =
{
   {EAP_CODE_REQUEST,  "Request"},
   {EAP_CODE_RESPONSE, "Response"},
   {EAP_CODE_SUCCESS,  "Success"},
   {EAP_CODE_FAILURE,  "Failure"}
};

//EAP method types
static const EapParamName methodTypeList[] =
{
   {EAP_METHOD_TYPE_IDENTITY,      "Identity"},
   {EAP_METHOD_TYPE_NOTIFICATION,  "Notification"},
   {EAP_METHOD_TYPE_NAK,           "Nak"},
   {EAP_METHOD_TYPE_MD5_CHALLENGE, "MD5-Challenge"},
   {EAP_METHOD_TYPE_OTP,           "One-Time Password"},
   {EAP_METHOD_TYPE_GTC,           "Generic Token Card"},
   {EAP_METHOD_TYPE_TLS,           "EAP-TLS"},
   {EAP_METHOD_TYPE_TTLS,          "EAP-TTLS"},
   {EAP_METHOD_TYPE_PEAP,          "PEAP"},
   {EAP_METHOD_TYPE_MSCHAPV2,      "MS-CHAP-V2"},
   {EAP_METHOD_TYPE_EXPANDED_NAK,  "Expanded NAK"}
};

//MS-CHAP-V2 opcodes
static const EapParamName mschapv2OpcodeList[] =
{
   {EAP_MSCHAPV2_CODE_CHALLENGE, "Challenge"},
   {EAP_MSCHAPV2_CODE_RESPONSE,  "Response"},
   {EAP_MSCHAPV2_CODE_SUCCESS,   "Success"},
   {EAP_MSCHAPV2_CODE_FAILURE,   "Failure"}
};


/**
 * @brief Dump EAPOL header
 * @param[in] header Pointer to the EAPOL header
 **/

void eapolDumpHeader(const EapolPdu *header)
{
   const char_t *packetTypeName;

   //Convert the Packet Type field to string representation
   packetTypeName = eapGetParamName(header->packetType, eapolPacketTypeList,
      arraysize(eapolPacketTypeList));

   //Dump EAPOL header contents
   TRACE_DEBUG("  Protocol Version = %" PRIu8 "\r\n", header->protocolVersion);
   TRACE_DEBUG("  Packet Type = %" PRIu8 " (%s)\r\n", header->packetType, packetTypeName);
   TRACE_DEBUG("  Packet Body Length = %" PRIu16 "\r\n", ntohs(header->packetBodyLen));
}


/**
 * @brief Dump EAP packet
 * @param[in] packet Pointer to the EAP header
 * @param[in] length Length of the EAP packet, in bytes
 **/

void eapDumpPacket(const EapPacket *packet, size_t length)
{
   //Check the length of the EAP packet
   if(length < sizeof(EapPacket))
   {
      return;
   }

   //Dump EAP header
   eapDumpHeader(packet);

   //Check Code field
   if(packet->code == EAP_CODE_REQUEST)
   {
      //Dump EAP request
      eapDumpRequest((EapRequest *) packet, length);
   }
   else if(packet->code == EAP_CODE_RESPONSE)
   {
      //Dump EAP response
      eapDumpResponse((EapResponse *) packet, length);
   }
   else
   {
      //Unknown Code value
   }
}


/**
 * @brief Dump EAP header
 * @param[in] header Pointer to the EAP header
 **/

void eapDumpHeader(const EapPacket *header)
{
   const char_t *codeName;

   //Convert the Code field to string representation
   codeName = eapGetParamName(header->code, eapCodeList,
      arraysize(eapCodeList));

   //Dump EAP header contents
   TRACE_DEBUG("  Code = %" PRIu8 " (%s)\r\n", header->code, codeName);
   TRACE_DEBUG("  Identifier = %" PRIu8 "\r\n", header->identifier);
   TRACE_DEBUG("  Length = %" PRIu16 "\r\n", ntohs(header->length));
}


/**
 * @brief Dump EAP request
 * @param[in] request Pointer to the EAP request
 * @param[in] length Length of the EAP request, in bytes
 **/

void eapDumpRequest(const EapRequest *request, size_t length)
{
   const char_t *methodTypeName;

   //Malformed EAP request?
   if(length < sizeof(EapRequest))
   {
      return;
   }

   //Convert the Method Type field to string representation
   methodTypeName = eapGetParamName(request->type, methodTypeList,
      arraysize(methodTypeList));

   //Dump Method Type field
   TRACE_DEBUG("  Method Type = %" PRIu8 " (%s)\r\n", request->type,
      methodTypeName);

   //Check Method Type value
   if(request->type == EAP_METHOD_TYPE_IDENTITY)
   {
      //Dump Identity request
      eapDumpIdentityRequest(request, length);
   }
   else if(request->type == EAP_METHOD_TYPE_MD5_CHALLENGE)
   {
      //Dump EAP-MD5 request
      eapMd5DumpPacket((EapMd5Packet *) request, length);
   }
   else if(request->type == EAP_METHOD_TYPE_MSCHAPV2)
   {
      //Dump EAP MS-CHAP-V2 request
      eapMschapv2DumpPacket((EapMschapv2Packet *) request, length);
   }
   else if(request->type == EAP_METHOD_TYPE_TLS)
   {
      //Dump EAP-TLS request
      eapTlsDumpPacket((EapTlsPacket *) request, length);
   }
   else
   {
      //Unknown Method Type value
   }
}


/**
 * @brief Dump EAP response
 * @param[in] response Pointer to the EAP response
 * @param[in] length Length of the EAP request, in bytes
 **/

void eapDumpResponse(const EapResponse *response, size_t length)
{
   const char_t *methodTypeName;

   //Malformed EAP response?
   if(length < sizeof(EapResponse))
   {
      return;
   }

   //Convert the Method Type field to string representation
   methodTypeName = eapGetParamName(response->type, methodTypeList,
      arraysize(methodTypeList));

   //Dump Method Type field
   TRACE_DEBUG("  Method Type = %" PRIu8 " (%s)\r\n", response->type,
      methodTypeName);

   //Check Method Type value
   if(response->type == EAP_METHOD_TYPE_IDENTITY)
   {
      //Dump Identity response
      eapDumpIdentityResponse(response, length);
   }
   else if(response->type == EAP_METHOD_TYPE_NAK)
   {
      //Dump Nak response
      eapDumpNakResponse(response, length);
   }
   else if(response->type == EAP_METHOD_TYPE_MD5_CHALLENGE)
   {
      //Dump EAP-MD5 response
      eapMd5DumpPacket((EapMd5Packet *) response, length);
   }
   else if(response->type == EAP_METHOD_TYPE_MSCHAPV2)
   {
      //Dump EAP MS-CHAP-V2 response
      eapMschapv2DumpPacket((EapMschapv2Packet *) response, length);
   }
   else if(response->type == EAP_METHOD_TYPE_TLS)
   {
      //Dump EAP-TLS response
      eapTlsDumpPacket((EapTlsPacket *) response, length);
   }
   else
   {
      //Unknown EAP method
   }
}


/**
 * @brief Dump Identity request
 * @param[in] request Pointer to the Identity request
 * @param[in] length Length of the Identity request, in bytes
 **/

void eapDumpIdentityRequest(const EapRequest *request, size_t length)
{
   //Retrieve the length of the message
   length -= sizeof(EapRequest);

   //Dump message
   TRACE_DEBUG("  Message (%" PRIuSIZE " bytes)\r\n", length);
   eapDumpString(request->data, length);
}


/**
 * @brief Dump Identity response
 * @param[in] response Pointer to the Identity response
 * @param[in] length Length of the Identity response, in bytes
 **/

void eapDumpIdentityResponse(const EapResponse *response, size_t length)
{
   //Retrieve the length of the identity
   length -= sizeof(EapResponse);

   //Dump identity
   TRACE_DEBUG("  Identity (%" PRIuSIZE " bytes)\r\n", length);
   eapDumpString(response->data, length);
}


/**
 * @brief Dump Nak response
 * @param[in] response Pointer to the Nak response
 * @param[in] length Length of the Nak response, in bytes
 **/

void eapDumpNakResponse(const EapResponse *response, size_t length)
{
   size_t i;
   const char_t *name;

   //The response contains one or more authentication types desired by the peer
   length -= sizeof(EapResponse);

   //Debug message
   TRACE_DEBUG("  Authentication Types (%" PRIuSIZE " bytes)\r\n", length);

   //Dump authentication types
   for(i = 0; i < length; i++)
   {
      //Convert the authentication type to string representation
      name = eapGetParamName(response->data[i], methodTypeList,
         arraysize(methodTypeList));

      //Dump authentication type
      TRACE_DEBUG("    %" PRIu8 " (%s)\r\n", response->data[i], name);
   }
}


/**
 * @brief Dump EAP-MD5 packet
 * @param[in] packet Pointer to the EAP-MD5 packet
 * @param[in] length Length of the EAP-MD5 packet, in bytes
 **/

void eapMd5DumpPacket(const EapMd5Packet *packet, size_t length)
{
   //Malformed EAP-MD5 packet?
   if(length < sizeof(EapMd5Packet))
   {
      return;
   }

   //Check the length of the challenge value
   if(length < (sizeof(EapMd5Packet) + packet->valueSize))
   {
      return;
   }

   //Dump Value-Size field
   TRACE_DEBUG("  Value-Size = %" PRIu8 "\r\n", packet->valueSize);

   //Dump Value field
   TRACE_DEBUG("  Value (%" PRIu8 " bytes)\r\n", packet->valueSize);
   TRACE_DEBUG_ARRAY("    ", packet->value, packet->valueSize);
}


/**
 * @brief Dump EAP MS-CHAP-V2 packet
 * @param[in] request Pointer to the EAP MS-CHAP-V2 request
 * @param[in] length Length of the EAP MS-CHAP-V2 request, in bytes
 **/

void eapMschapv2DumpPacket(const EapMschapv2Packet *packet, size_t length)
{
   const char_t *opcodeName;

   //Malformed MS-CHAP-V2 packet?
   if(length < sizeof(EapMschapv2Packet))
   {
      return;
   }

   //Convert the OpCode field to string representation
   opcodeName = eapGetParamName(packet->opcode, mschapv2OpcodeList,
      arraysize(mschapv2OpcodeList));

   //Dump OpCode field
   TRACE_DEBUG("  OpCode = %" PRIu8 " (%s)\r\n", packet->opcode, opcodeName);

   //Check Code field
   if(packet->code == EAP_CODE_REQUEST)
   {
      //The OpCode field identifies the type of MS-CHAP-V2 packet
      if(packet->opcode == EAP_MSCHAPV2_CODE_CHALLENGE)
      {
         //Dump MS-CHAP-V2 Challenge packet
         eapMschapv2DumpChallenge((EapMschapv2Challenge *) packet,
            length);
      }
      else if(packet->opcode == EAP_MSCHAPV2_CODE_SUCCESS)
      {
         //Dump MS-CHAP-V2 Success Request packet
         eapMschapv2DumpSuccessRequest((EapMschapv2SuccessRequest *) packet,
            length);
      }
      else if(packet->opcode == EAP_MSCHAPV2_CODE_FAILURE)
      {
         //Dump MS-CHAP-V2 Failure Request packet
         eapMschapv2DumpFailureRequest((EapMschapv2FailureRequest *) packet,
            length);
      }
      else
      {
         //Unknown OpCode value
      }
   }
   else if(packet->code == EAP_CODE_RESPONSE)
   {
      //The OpCode field identifies the type of MS-CHAP-V2 packet
      if(packet->opcode == EAP_MSCHAPV2_CODE_RESPONSE)
      {
         //Dump MS-CHAP-V2 Response packet
         eapMschapv2DumpResponse((EapMschapv2Response *) packet,
            length);
      }
      else if(packet->opcode == EAP_MSCHAPV2_CODE_SUCCESS)
      {
         //Dump MS-CHAP-V2 Success Response packet
         eapMschapv2DumpSuccessResponse((EapMschapv2SuccessResponse *) packet,
            length);
      }
      else if(packet->opcode == EAP_MSCHAPV2_CODE_FAILURE)
      {
         //Dump MS-CHAP-V2 Failure Response packet
         eapMschapv2DumpFailureResponse((EapMschapv2FailureResponse *) packet,
            length);
      }
      else
      {
         //Unknown OpCode value
      }
   }
   else
   {
      //Unknown Code value
   }
}


/**
 * @brief Dump EAP MS-CHAP-V2 Challenge packet
 * @param[in] response Pointer to the EAP MS-CHAP-V2 Challenge packet
 * @param[in] length Length of the EAP MS-CHAP-V2 Challenge packet, in bytes
 **/

void eapMschapv2DumpChallenge(const EapMschapv2Challenge *challenge,
   size_t length)
{
   //Malformed MS-CHAP-V2 Challenge packet?
   if(length < sizeof(EapMschapv2Challenge))
   {
      return;
   }

   //Dump MS-CHAPv2-ID field
   TRACE_DEBUG("  MS-CHAPv2-ID = %" PRIu8 "\r\n", challenge->mschapv2Id);
   //Dumpe MS-Length field
   TRACE_DEBUG("  MS-Length = %" PRIu16 "\r\n", ntohs(challenge->msLength));
   //Dump Value-Size field
   TRACE_DEBUG("  Value-Size = %" PRIu8 "\r\n", challenge->valueSize);

   //Dump Challenge field
   TRACE_DEBUG("  Challenge (%" PRIuSIZE " bytes)\r\n", 16);
   TRACE_DEBUG_ARRAY("    ", challenge->challenge, 16);

   //Retrieve the length of the name
   length -= sizeof(EapMschapv2Challenge);

   //Dump Name field
   TRACE_DEBUG("  Name (%" PRIuSIZE " bytes)\r\n", length);
   eapDumpString(challenge->name, length);
}


/**
 * @brief Dump EAP MS-CHAP-V2 Response packet
 * @param[in] response Pointer to the EAP MS-CHAP-V2 Response packet
 * @param[in] length Length of the EAP MS-CHAP-V2 Response packet, in bytes
 **/

void eapMschapv2DumpResponse(const EapMschapv2Response *response,
   size_t length)
{
   //Malformed MS-CHAP-V2 Response packet?
   if(length < sizeof(EapMschapv2Response))
   {
      return;
   }

   //Dump MS-CHAPv2-ID field
   TRACE_DEBUG("  MS-CHAPv2-ID = %" PRIu8 "\r\n", response->mschapv2Id);
   //Dumpe MS-Length field
   TRACE_DEBUG("  MS-Length = %" PRIu16 "\r\n", ntohs(response->msLength));
   //Dump Value-Size field
   TRACE_DEBUG("  Value-Size = %" PRIu8 "\r\n", response->valueSize);

   //Dump Peer-Challenge field
   TRACE_DEBUG("  Peer-Challenge (%" PRIuSIZE " bytes)\r\n", 16);
   TRACE_DEBUG_ARRAY("    ", response->peerChallenge, 16);

   //Dump Reserved field
   TRACE_DEBUG("  Reserved (%" PRIuSIZE " bytes)\r\n", 8);
   TRACE_DEBUG_ARRAY("    ", response->reserved, 8);

   //Dump NT-Response field
   TRACE_DEBUG("  NT-Response (%" PRIuSIZE " bytes)\r\n", 24);
   TRACE_DEBUG_ARRAY("    ", response->ntResponse, 24);

   //Retrieve the length of the name
   length -= sizeof(EapMschapv2Response);

   //Dump Name field
   TRACE_DEBUG("  Name (%" PRIuSIZE " bytes)\r\n", length);
   eapDumpString(response->name, length);
}


/**
 * @brief Dump EAP MS-CHAP-V2 Success Request packet
 * @param[in] response Pointer to the EAP MS-CHAP-V2 Success Request packet
 * @param[in] length Length of the EAP MS-CHAP-V2 Success Request packet, in bytes
 **/

void eapMschapv2DumpSuccessRequest(const EapMschapv2SuccessRequest *request,
   size_t length)
{
   //Malformed MS-CHAP-V2 Success Request packet?
   if(length < sizeof(EapMschapv2SuccessRequest))
   {
      return;
   }

   //Dump MS-CHAPv2-ID field
   TRACE_DEBUG("  MS-CHAPv2-ID = %" PRIu8 "\r\n", request->mschapv2Id);
   //Dumpe MS-Length field
   TRACE_DEBUG("  MS-Length = %" PRIu16 "\r\n", ntohs(request->msLength));

   //Retrieve the length of the message
   length -= sizeof(EapMschapv2SuccessRequest);

   //Dump Message field
   TRACE_DEBUG("  Message (%" PRIuSIZE " bytes)\r\n", length);
   eapDumpString(request->message, length);
}


/**
 * @brief Dump EAP MS-CHAP-V2 Success Response packet
 * @param[in] response Pointer to the EAP MS-CHAP-V2 Success Response packet
 * @param[in] length Length of the EAP MS-CHAP-V2 Success Response packet, in bytes
 **/

void eapMschapv2DumpSuccessResponse(const EapMschapv2SuccessResponse *response,
   size_t length)
{
}


/**
 * @brief Dump EAP MS-CHAP-V2 Failure Request packet
 * @param[in] response Pointer to the EAP MS-CHAP-V2 Failure Request packet
 * @param[in] length Length of the EAP MS-CHAP-V2 Failure Request packet, in bytes
 **/

void eapMschapv2DumpFailureRequest(const EapMschapv2FailureRequest *request,
   size_t length)
{
   //Malformed MS-CHAP-V2 Failure Request packet?
   if(length < sizeof(EapMschapv2FailureRequest))
   {
      return;
   }

   //Dump MS-CHAPv2-ID field
   TRACE_DEBUG("  MS-CHAPv2-ID = %" PRIu8 "\r\n", request->mschapv2Id);
   //Dumpe MS-Length field
   TRACE_DEBUG("  MS-Length = %" PRIu16 "\r\n", ntohs(request->msLength));

   //Retrieve the length of the message
   length -= sizeof(EapMschapv2FailureRequest);

   //Dump Message field
   TRACE_DEBUG("  Message (%" PRIuSIZE " bytes)\r\n", length);
   eapDumpString(request->message, length);
}


/**
 * @brief Dump EAP MS-CHAP-V2 Failure Response packet
 * @param[in] response Pointer to the EAP MS-CHAP-V2 Failure Response packet
 * @param[in] length Length of the EAP MS-CHAP-V2 Failure Response packet, in bytes
 **/

void eapMschapv2DumpFailureResponse(const EapMschapv2FailureResponse *response,
   size_t length)
{
}


/**
 * @brief Dump EAP-TLS packet
 * @param[in] packet Pointer to the EAP-TLS packet
 * @param[in] length Length of the EAP-TLS packet, in bytes
 **/

void eapTlsDumpPacket(const EapTlsPacket *packet, size_t length)
{
   //Malformed EAP-TLS packet?
   if(length < sizeof(EapTlsPacket))
   {
      return;
   }

   //Dump Flags field
   eapTlsDumpFlags(packet->flags);
}


/**
 * @brief Dump EAP-TLS flags
 * @param[in] flags EAP-TLS specific options
 **/

void eapTlsDumpFlags(uint8_t flags)
{
   uint8_t l;
   uint8_t m;
   uint8_t s;

   //The L flag (length included) is set to indicate the presence of the
   //four-octet TLS Message Length field
   l = (flags & EAP_TLS_FLAGS_L) ? 1 : 0;

   //The M flag (more fragments) is set on all but the last fragment
   m = (flags & EAP_TLS_FLAGS_M) ? 1 : 0;

   //The S flag (EAP-TLS start) is set only within the EAP-TLS start message
   s = (flags & EAP_TLS_FLAGS_S) ? 1 : 0;

   //Check whether any flag is set
   if(l != 0 || m != 0 || s != 0)
   {
      //Dump the value of the Flags field
      TRACE_DEBUG("  Flags = 0x%02" PRIX8 " (", flags);

      //Dump flags
      while(1)
      {
         if(l != 0)
         {
            TRACE_DEBUG("Length");
            l = FALSE;
         }
         else if(m != 0)
         {
            TRACE_DEBUG("More");
            m = FALSE;
         }
         else if(s != 0)
         {
            TRACE_DEBUG("Start");
            s = FALSE;
         }
         else
         {
         }

         if(l != 0 || m != 0 || s != 0)
         {
            TRACE_DEBUG(", ");
         }
         else
         {
            TRACE_DEBUG(")\r\n");
            break;
         }
      }
   }
   else
   {
      //Dump the value of the Flags field
      TRACE_DEBUG("  Flags = 0x%02" PRIX8 "\r\n", flags);
   }
}


/**
 * @brief Dump string
 * @param[in] s Pointer to the string to dump
 * @param[in] length Length of the string, in characters
 **/

void eapDumpString(const uint8_t *s, size_t length)
{
   size_t i;

   //Display prefix
   TRACE_DEBUG("    \"");

   //Dump string
   for(i = 0; i < length; i++)
   {
      TRACE_DEBUG("%c", s[i]);
   }

   //Display suffix
   TRACE_DEBUG("\"\r\n");
}

#endif


/**
 * @brief Convert a parameter to string representation
 * @param[in] value Parameter value
 * @param[in] paramList List of acceptable parameters
 * @param[in] paramListLen Number of entries in the list
 * @return NULL-terminated string describing the parameter
 **/

const char_t *eapGetParamName(uint_t value, const EapParamName *paramList,
   size_t paramListLen)
{
   uint_t i;

   //Default name for unknown values
   static const char_t defaultName[] = "Unknown";

   //Loop through the list of acceptable parameters
   for(i = 0; i < paramListLen; i++)
   {
      if(paramList[i].value == value)
      {
         return paramList[i].name;
      }
   }

   //Unknown value
   return defaultName;
}

#endif
