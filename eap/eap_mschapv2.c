/**
 * @file eap_mschapv2.c
 * @brief EAP MS-CHAP-V2 authentication method
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
#define TRACE_LEVEL EAP_TRACE_LEVEL

//Dependencies
#include "eap/eap.h"
#include "eap/eap_mschapv2.h"
#include "eap/eap_debug.h"
#include "hash/md4.h"
#include "hash/sha1.h"
#include "cipher/des.h"
#include "debug.h"

//Check EAP library configuration
#if (EAP_MSCHAPV2_SUPPORT == ENABLED)

//Magic1 constant
static const uint8_t magic1[39] =
{
   0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x74, 0x6F, 0x20,
   0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x63,
   0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74
};

//Magic2 constant
static const uint8_t magic2[41] =
{
   0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B, 0x65, 0x20, 0x69, 0x74, 0x20, 0x64,
   0x6F, 0x20, 0x6D, 0x6F, 0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E, 0x65, 0x20,
   0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E
};

//Hex conversion table
static const char_t hexDigit[16] =
{
   '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};


/**
 * @brief Check incoming EAP MS-CHAP-V2 request
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] request Pointer to the received request
 * @param[in] length Length of the request, in bytes
 **/

error_t eapMschapv2CheckRequest(SupplicantContext *context,
   const EapMschapv2Packet *request, size_t length)
{
   //Check the length of the EAP request
   if(length < sizeof(EapMschapv2Packet))
      return ERROR_INVALID_LENGTH;

   //The OpCode field identifies the type of MS-CHAP-V2 packet
   if(request->opcode == EAP_MSCHAPV2_CODE_CHALLENGE)
   {
      const EapMschapv2Challenge *challenge;

      //Point to the MS-CHAP-V2 Challenge packet
      challenge = (EapMschapv2Challenge *) request;

      //Malformed MS-CHAP-V2 packet?
      if(length < sizeof(EapMschapv2Challenge))
         return ERROR_INVALID_LENGTH;

      //The MS-Length field is two octets and must be set to the value of the
      //Length field minus 5
      if(ntohs(challenge->msLength) != (length - sizeof(EapRequest)))
         return ERROR_INVALID_LENGTH;

      //The Value-Size field is one octet and indicates the length of the
      //Challenge field. Since EAP MS-CHAP-V2 utilizes a 16 octet Challenge
      //field, it is set to 16
      if(challenge->valueSize != 16)
         return ERROR_INVALID_LENGTH;
   }
   else if(request->opcode == EAP_MSCHAPV2_CODE_SUCCESS)
   {
      const EapMschapv2SuccessRequest *successReq;

      //Point to the MS-CHAP-V2 Challenge packet
      successReq = (EapMschapv2SuccessRequest *) request;

      //Malformed MS-CHAP-V2 packet?
      if(length < sizeof(EapMschapv2SuccessRequest))
         return ERROR_INVALID_LENGTH;

      //The MS-Length field is two octets and must be set to the value of the
      //Length field minus 5
      if(ntohs(successReq->msLength) != (length - sizeof(EapRequest)))
         return ERROR_INVALID_LENGTH;

      //The Message field contains a 42-octet authenticator response string and
      //a printable message (refer to RFC 2759, section 5)
      if(length < (sizeof(EapMschapv2SuccessRequest) + 42))
         return ERROR_INVALID_LENGTH;
   }
   else if(request->opcode == EAP_MSCHAPV2_CODE_FAILURE)
   {
      const EapMschapv2FailureRequest *failureReq;

      //Point to the MS-CHAP-V2 Failure Request packet
      failureReq = (EapMschapv2FailureRequest *) request;

      //Malformed MS-CHAP-V2 packet?
      if(length < sizeof(EapMschapv2FailureRequest))
         return ERROR_INVALID_LENGTH;

      //The MS-Length field is two octets and must be set to the value of the
      //Length field minus 5
      if(ntohs(failureReq->msLength) != (length - sizeof(EapRequest)))
         return ERROR_INVALID_LENGTH;
   }
   else
   {
      //Invalid opcode
      return ERROR_INVALID_TYPE;
   }

   //The request is valid
   return NO_ERROR;
}


/**
 * @brief Process incoming EAP MS-CHAP-V2 request
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] request Pointer to the received request
 * @param[in] length Length of the request, in bytes
 **/

void eapMschapv2ProcessRequest(SupplicantContext *context,
   const EapMschapv2Packet *request, size_t length)
{
   //Initialize MS-CHAP-V2 packet type
   context->opcode = EAP_MSCHAPV2_CODE_INVALID;

   //Check method state
   if(context->methodState == EAP_METHOD_STATE_INIT)
   {
      //The OpCode field identifies the type of MS-CHAP-V2 packet
      if(request->opcode == EAP_MSCHAPV2_CODE_CHALLENGE)
      {
         const EapMschapv2Challenge *challenge;

         //Point to the EAP MS-CHAP-V2 Challenge packet
         challenge = (EapMschapv2Challenge *) request;

         //The MS-CHAPv2-ID field is one octet and aids in matching MS-CHAP-V2
         //responses with requests
         context->mschapv2Id = challenge->mschapv2Id;

         //The Challenge field is 16 octets
         osMemcpy(context->authChallenge, challenge->challenge, 16);

         //The Peer-Challenge field is generated by the peer and is used in the
         //calculation of the NT-Response field
         context->prngAlgo->generate(context->prngContext,
            context->peerChallenge, 16);

         //The NT-Response field is an encoded function of the password, the
         //user name, the contents of the Peer-Challenge field and the received
         //challenge as output by the routine GenerateNTResponse()
         eapMschapv2GenerateNtResponse(context->authChallenge,
            context->peerChallenge, context->username, context->password,
            context->ntResponse);

         //The authenticator can decide either to continue the method or to end
         //the conversation
         context->methodState = EAP_METHOD_STATE_MAY_CONT;

         //The decision variable is always set to FAIL
         context->decision = EAP_DECISION_FAIL;

         //Send a EAP MS-CHAP-V2 Response packet
         context->opcode = EAP_MSCHAPV2_CODE_RESPONSE;
      }
      else
      {
         //The method never continues at this point
         context->methodState = EAP_METHOD_STATE_DONE;
         //The decision variable is always set to FAIL
         context->decision = EAP_DECISION_FAIL;
      }
   }
   else
   {
      //The OpCode field identifies the type of MS-CHAP-V2 packet
      if(request->opcode == EAP_MSCHAPV2_CODE_SUCCESS)
      {
         bool_t valid;
         const EapMschapv2SuccessRequest *successReq;

         //Point to the EAP MS-CHAP-V2 Success Request packet
         successReq = (EapMschapv2SuccessRequest *) request;

         //The authenticating peer must verify the authenticator response when
         //a Success packet is received (refer to RFC 2759, section 5)
         valid = eapMschapv2CheckAuthResponse(context->password,
            context->ntResponse, context->peerChallenge,
            context->authChallenge, context->username, successReq->message);

         //The method never continues at this point
         context->methodState = EAP_METHOD_STATE_DONE;

         //Valid authenticator response?
         if(valid)
         {
            //If both the server has informed us that it will allow access, and
            //the next packet will be EAP Success, and we're willing to use
            //this access, set decision to UNCOND_SUCC
            context->decision = EAP_DECISION_UNCOND_SUCC;

            //If the peer successfully validates the EAP MS-CHAP-V2 Success
            //Request packet sent by the authenticator, then it must respond
            //with an EAP MS-CHAP-V2 Success Response packet
            context->opcode = EAP_MSCHAPV2_CODE_SUCCESS;
         }
         else
         {
            //If the authenticator response is either missing or incorrect, the
            //peer must end the session (refer to RFC 2759, section 5)
            context->decision = EAP_DECISION_FAIL;
         }
      }
      else if(request->opcode == EAP_MSCHAPV2_CODE_FAILURE)
      {
         //The peer has received a Failure Request packet
         context->methodState = EAP_METHOD_STATE_DONE;
         //The decision variable is always set to FAIL
         context->decision = EAP_DECISION_FAIL;
      }
      else
      {
         //The method never continues at this point
         context->methodState = EAP_METHOD_STATE_DONE;
         //The decision variable is always set to FAIL
         context->decision = EAP_DECISION_FAIL;
      }
   }
}


/**
 * @brief Build EAP MS-CHAP-V2 response
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void eapMschapv2BuildResponse(SupplicantContext *context)
{
   size_t n;
   EapMschapv2Packet *packet;

   //Point to the buffer where to format the EAP packet
   packet = (EapMschapv2Packet *) context->eapRespData;

   //Format EAP packet
   packet->code = EAP_CODE_RESPONSE;
   packet->identifier = context->reqId;
   packet->type = EAP_METHOD_TYPE_MSCHAPV2;

   //The OpCode field is one octet and identifies the type of MS-CHAP-V2 packet
   packet->opcode = context->opcode;

   //Check MS-CHAP-V2 packet type
   if(context->opcode == EAP_MSCHAPV2_CODE_RESPONSE)
   {
      EapMschapv2Response *response;

      //Point to the EAP MS-CHAP-V2 Response packet
      response = (EapMschapv2Response *) context->eapRespData;

      //The MS-CHAPv2-ID field is one octet and aids in matching MS-CHAP-V2
      //responses with requests
      response->mschapv2Id = context->mschapv2Id;

      //The Value-Size field is one octet and indicates the length of the
      //Response field. It is set to 49
      response->valueSize = 49;

      //The Peer-Challenge field is a 16-octet random number
      osMemcpy(response->peerChallenge, context->peerChallenge, 16);

      //The Reserved field must be zero
      osMemset(response->reserved, 0, 8);

      //The NT-Response field is an encoded function of the password, the user
      //name, the contents of the Peer-Challenge field and the received
      //challenge as output by the routine GenerateNTResponse()
      osMemcpy(response->ntResponse, context->ntResponse, 24);

      //The Flags field is reserved for future use and must be zero
      response->flags = 0;

      //Determine the length of the user name
      n = osStrlen(context->username);

      //The Name field is a string of 0 to (theoretically) 256 case-sensitive
      //ASCII characters which identifies the peer's user account name
      osMemcpy(response->name, context->username, n);

      //Length of the EAP MS-CHAP-V2 Response packet
      n += sizeof(EapMschapv2Response);

      //The MS-Length field is two octets and must be set to the value of the
      //Length field minus 5
      response->msLength = htons(n - sizeof(EapResponse));
   }
   else if(context->opcode == EAP_MSCHAPV2_CODE_SUCCESS)
   {
      //Length of the EAP MS-CHAP-V2 Success Response packet
      n = sizeof(EapMschapv2SuccessResponse);
   }
   else if(context->opcode == EAP_MSCHAPV2_CODE_FAILURE)
   {
      //Length of the EAP MS-CHAP-V2 Failure Response packet
      n = sizeof(EapMschapv2FailureResponse);
   }
   else
   {
      //Invalid method state
      n = 0;
   }

   //Valid reponse?
   if(n > 0)
   {
      //The Length field is two octets and indicates the length of the EAP
      //packet including the Code, Identifier, Length, Type, OpCode,
      //MS-CHAPv2-ID, MS-Length, Value-Size, Challenge, and Name fields
      packet->length = htons(n);

      //Debug message
      TRACE_DEBUG("Sending EAP packet (%" PRIuSIZE " bytes)\r\n", n);
      //Dump EAP packet for debugging purpose
      eapDumpPacket((EapPacket *) packet, n);
   }

   //Save the length of the EAP response
   context->eapRespDataLen = n;
}


/**
 * @brief GenerateNTResponse routine
 * @param[in] authChallenge Authenticator challenge (16 bytes)
 * @param[in] peerChallenge Peer challenge (16 bytes)
 * @param[in] username NULL-terminated string containing the user name
 * @param[in] password NULL-terminated string containing the password
 * @param[out] response Resulting NT-Response field (24 bytes)
 **/

void eapMschapv2GenerateNtResponse(const uint8_t *authChallenge,
   const uint8_t *peerChallenge, const char_t *username,
   const char_t *password, uint8_t *response)
{
   uint8_t challenge[8];
   uint8_t passwordHash[16];

   //Compute ChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName)
   eapMschapv2ChallengeHash(peerChallenge, authChallenge, username, challenge);

   //Compute NtPasswordHash(Password)
   eapMschapv2NtPasswordHash(password, passwordHash);

   //Compute ChallengeResponse(Challenge, PasswordHash)
   eapMschapv2ChallengeResponse(challenge, passwordHash, response);

   //Erase working state
   cryptoZeroizeMem(passwordHash, sizeof(passwordHash));
}


/**
 * @brief ChallengeHash routine
 * @param[in] peerChallenge Peer challenge (16 bytes)
 * @param[in] authChallenge Authenticator challenge (16 bytes)
 * @param[in] username NULL-terminated string containing the user name
 * @param[out] challenge Resulting challenge (8 bytes)
 **/

void eapMschapv2ChallengeHash(const uint8_t *peerChallenge,
   const uint8_t *authChallenge, const char_t *username, uint8_t *challenge)
{
   Sha1Context sha1Context;
   uint8_t digest[SHA1_DIGEST_SIZE];

   //Compute ChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName)
   sha1Init(&sha1Context);
   sha1Update(&sha1Context, peerChallenge, 16);
   sha1Update(&sha1Context, authChallenge, 16);
   sha1Update(&sha1Context, username, osStrlen(username));
   sha1Final(&sha1Context, digest);
   sha1Deinit(&sha1Context);

   //Return the first 8 bytes of the SHA-1 digest
   osMemcpy(challenge, digest, 8);
}


/**
 * @brief NtPasswordHash routine
 * @param[in] password NULL-terminated string containing the password
 * @param[out] passwordHash Password hash (16 bytes)
 **/

void eapMschapv2NtPasswordHash(const char_t *password, uint8_t *passwordHash)
{
   size_t i;
   size_t n;
   char_t zero;
   Md4Context md4Context;

   //Initialize variable
   zero = 0;

   //Determine the length of the password
   n = osStrlen(password);

   //Use the MD4 algorithm to irreversibly hash Password into PasswordHash
   md4Init(&md4Context);

   //Only the password is hashed without including any terminating 0
   for(i = 0; i < n; i++)
   {
      //The password is a string of Unicode characters (refer to RFC 2759,
      //section 8.3)
      md4Update(&md4Context, &password[i], sizeof(char_t));
      md4Update(&md4Context, &zero, sizeof(char_t));
   }

   //Finalize MD4 computation
   md4Final(&md4Context, passwordHash);
   md4Deinit(&md4Context);
}


/**
 * @brief HashNtPasswordHash routine
 * @param[in] passwordHash Password hash (16 bytes)
 * @param[out] passwordHashHash Resulting hash (16 bytes)
 **/

void eapMschapv2HashNtPasswordHash(const uint8_t *passwordHash,
   uint8_t *passwordHashHash)
{
   Md4Context md4Context;

   //Use the MD4 algorithm to irreversibly hash PasswordHash into
   //PasswordHashHash
   md4Init(&md4Context);
   md4Update(&md4Context, passwordHash, 16);
   md4Final(&md4Context, passwordHashHash);
   md4Deinit(&md4Context);
}


/**
 * @brief ChallengeResponse routine
 * @param[in] challenge Challenge (8 bytes)
 * @param[in] passwordHash Password hash (16 bytes)
 * @param[out] response Resulting response (24 bytes)
 **/

void eapMschapv2ChallengeResponse(const uint8_t *challenge,
   const uint8_t *passwordHash, uint8_t *response)
{
   DesContext desContext;
   uint8_t zPasswordHash[21];
   uint8_t key[8];

   //Set ZPasswordHash to PasswordHash zero-padded to 21 octets (refer to
   //RFC 2759, section 8.5)
   osMemcpy(zPasswordHash, passwordHash, 16);
   osMemset(zPasswordHash + 16, 0, 5);

   //Compute DesEncrypt(Challenge, 1st 7-octets of ZPasswordHash)
   desComputeKeyParity(zPasswordHash, key);
   desInit(&desContext, key, 8);
   desEncryptBlock(&desContext, challenge, response);

   //Compute DesEncrypt(Challenge, 2nd 7-octets of ZPasswordHash)
   desComputeKeyParity(zPasswordHash + 7, key);
   desInit(&desContext, key, 8);
   desEncryptBlock(&desContext, challenge, response + 8);

   //Compute DesEncrypt(Challenge, 3rd 7-octets of ZPasswordHash)
   desComputeKeyParity(zPasswordHash + 14, key);
   desInit(&desContext, key, 8);
   desEncryptBlock(&desContext, challenge, response + 16);
   desDeinit(&desContext);

   //Erase working state
   cryptoZeroizeMem(zPasswordHash, sizeof(zPasswordHash));
   cryptoZeroizeMem(key, sizeof(key));
}


/**
 * @brief GenerateAuthenticatorResponse routine
 * @param[in] password NULL-terminated string containing the password
 * @param[out] ntResponse NT-Response field (24 bytes)
 * @param[in] peerChallenge Peer challenge (16 bytes)
 * @param[in] authChallenge Authenticator challenge (16 bytes)
 * @param[in] username NULL-terminated string containing the user name
 * @param[out] authResponse Resulting authenticator response (42 bytes)
 **/

void eapMschapv2GenerateAuthResponse(const char_t *password,
   const uint8_t *ntResponse, const uint8_t *peerChallenge,
   const uint8_t *authChallenge, const char_t *username, uint8_t *authResponse)
{
   uint_t i;
   Sha1Context sha1Context;
   uint8_t challenge[8];
   uint8_t passwordHash[16];
   uint8_t passwordHashHash[16];
   uint8_t digest[SHA1_DIGEST_SIZE];

   //Hash the password with MD4
   eapMschapv2NtPasswordHash(password, passwordHash);

   //Use the MD4 algorithm to irreversibly hash PasswordHash into
   //PasswordHashHash
   eapMschapv2HashNtPasswordHash(passwordHash, passwordHashHash);

   //Compute SHA1(PasswordHashHash || NT-Response || Magic1)
   sha1Init(&sha1Context);
   sha1Update(&sha1Context, passwordHashHash, 16);
   sha1Update(&sha1Context, ntResponse, 24);
   sha1Update(&sha1Context, magic1, 39);
   sha1Final(&sha1Context, digest);
   sha1Deinit(&sha1Context);

   //Compute ChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName)
   eapMschapv2ChallengeHash(peerChallenge, authChallenge, username, challenge);

   //Compute SHA1(Digest || Challenge || Magic2)
   sha1Init(&sha1Context);
   sha1Update(&sha1Context, digest, 20);
   sha1Update(&sha1Context, challenge, 8);
   sha1Update(&sha1Context, magic2, 41);
   sha1Final(&sha1Context, digest);
   sha1Deinit(&sha1Context);

   //Encode the value of Digest as "S=" followed by the auth_string
   authResponse[0] = 'S';
   authResponse[1] = '=';

   //The auth_string quantity is a 20 octet number encoded in ASCII as 40
   //hexadecimal digits. The hexadecimal digits A-F (if present) must be
   //uppercase (refer to RFC 2759, section 5)
   for(i = 0; i < SHA1_DIGEST_SIZE; i++)
   {
      //Convert upper nibble
      authResponse[i * 2 + 2] = hexDigit[(digest[i] >> 4) & 0x0F];
      //Then convert lower nibble
      authResponse[i * 2 + 3] = hexDigit[digest[i] & 0x0F];
   }

   //Erase working state
   cryptoZeroizeMem(passwordHash, sizeof(passwordHash));
   cryptoZeroizeMem(passwordHashHash, sizeof(passwordHashHash));
   cryptoZeroizeMem(digest, sizeof(digest));
}


/**
 * @brief CheckAuthenticatorResponse routine
 * @param[in] password NULL-terminated string containing the password
 * @param[out] ntResponse NT-Response field (24 bytes)
 * @param[in] peerChallenge Peer challenge (16 bytes)
 * @param[in] authChallenge Authenticator challenge (16 bytes)
 * @param[in] username NULL-terminated string containing the user name
 * @param[in] receivedResponse Received response (42 bytes)
 * @return TRUE if the authenticator response is correct, else FASE
 **/

bool_t eapMschapv2CheckAuthResponse(const char_t *password,
   const uint8_t *ntResponse, const uint8_t *peerChallenge,
   const uint8_t *authChallenge, const char_t *username,
   const uint8_t *receivedResponse)
{
   bool_t valid;
   uint8_t calcResponse[42];

   //Compute GenerateAuthenticatorResponse(Password, NtResponse, PeerChallenge,
   //AuthenticatorChallenge, UserName)
   eapMschapv2GenerateAuthResponse(password, ntResponse, peerChallenge,
      authChallenge, username, calcResponse);

   //Verify the authenticator response
   if(osMemcmp(receivedResponse, calcResponse, sizeof(calcResponse)) == 0)
   {
      valid = TRUE;
   }
   else
   {
      valid = FALSE;
   }

   //Erase working state
   cryptoZeroizeMem(calcResponse, sizeof(calcResponse));

   //Return TRUE if the authenticator response is correct
   return valid;
}

#endif
