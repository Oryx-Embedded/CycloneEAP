/**
 * @file eap_full_auth_fsm.c
 * @brief EAP full authenticator state machine
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
#include "authenticator/authenticator_fsm.h"
#include "authenticator/authenticator_misc.h"
#include "eap/eap_full_auth_fsm.h"
#include "eap/eap_auth_procedures.h"
#include "eap/eap_debug.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (AUTHENTICATOR_SUPPORT == ENABLED)

//EAP full authenticator states
const EapParamName eapFullAuthStates[] =
{
   {EAP_FULL_AUTH_STATE_DISABLED,               "DISABLED"},
   {EAP_FULL_AUTH_STATE_INITIALIZE,             "INITIALIZE"},
   {EAP_FULL_AUTH_STATE_IDLE,                   "IDLE"},
   {EAP_FULL_AUTH_STATE_RETRANSMIT,             "RETRANSMIT"},
   {EAP_FULL_AUTH_STATE_RECEIVED,               "RECEIVED"},
   {EAP_FULL_AUTH_STATE_NAK,                    "NAK"},
   {EAP_FULL_AUTH_STATE_SELECT_ACTION,          "SELECT_ACTION"},
   {EAP_FULL_AUTH_STATE_INTEGRITY_CHECK,        "INTEGRITY_CHECK"},
   {EAP_FULL_AUTH_STATE_METHOD_RESPONSE,        "METHOD_RESPONSE"},
   {EAP_FULL_AUTH_STATE_PROPOSE_METHOD,         "PROPOSE_METHOD"},
   {EAP_FULL_AUTH_STATE_METHOD_REQUEST,         "METHOD_REQUEST"},
   {EAP_FULL_AUTH_STATE_DISCARD,                "DISCARD"},
   {EAP_FULL_AUTH_STATE_SEND_REQUEST,           "SEND_REQUEST"},
   {EAP_FULL_AUTH_STATE_TIMEOUT_FAILURE,        "TIMEOUT_FAILURE"},
   {EAP_FULL_AUTH_STATE_FAILURE,                "FAILURE"},
   {EAP_FULL_AUTH_STATE_SUCCESS,                "SUCCESS"},
   {EAP_FULL_AUTH_STATE_INITIALIZE_PASSTHROUGH, "INITIALIZE_PASSTHROUGH"},
   {EAP_FULL_AUTH_STATE_IDLE2,                  "IDLE2"},
   {EAP_FULL_AUTH_STATE_RETRANSMIT2,            "RETRANSMIT2"},
   {EAP_FULL_AUTH_STATE_RECEIVED2,              "RECEIVED2"},
   {EAP_FULL_AUTH_STATE_AAA_REQUEST,            "AAA_REQUEST"},
   {EAP_FULL_AUTH_STATE_AAA_IDLE,               "AAA_IDLE"},
   {EAP_FULL_AUTH_STATE_AAA_RESPONSE,           "AAA_RESPONSE"},
   {EAP_FULL_AUTH_STATE_DISCARD2,               "DISCARD2"},
   {EAP_FULL_AUTH_STATE_SEND_REQUEST2,          "SEND_REQUEST2"},
   {EAP_FULL_AUTH_STATE_TIMEOUT_FAILURE2,       "TIMEOUT_FAILURE2"},
   {EAP_FULL_AUTH_STATE_FAILURE2,               "FAILURE2"},
   {EAP_FULL_AUTH_STATE_SUCCESS2,               "SUCCESS2"}
};


/**
 * @brief EAP full authenticator state machine initialization
 * @param[in] port Pointer to the port context
 **/

void eapFullAuthInitFsm(AuthenticatorPort *port)
{
   //Enter initial state
   eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_DISABLED);
}


/**
 * @brief EAP full authenticator state machine implementation
 * @param[in] port Pointer to the port context
 **/

void eapFullAuthFsm(AuthenticatorPort *port)
{
   //A global transition can occur from any of the possible states. When the
   //condition associated with a global transition is met, it supersedes all
   //other exit conditions
   if(!port->portEnabled)
   {
      //Switch to the DISABLED state
      eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_DISABLED);
   }
   else if(port->eapRestart && port->portEnabled)
   {
      //Switch to the INITIALIZE state
      eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_INITIALIZE);
   }
   //Errata
   else if(port->portControl != AUTHENTICATOR_PORT_MODE_AUTO)
   {
      //Switch to the INITIALIZE state
      eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_INITIALIZE);
   }
   else
   {
      //All exit conditions for the state are evaluated continuously until one
      //of the conditions is met (refer to RFC 4137, section 3.1)
      switch(port->eapFullAuthState)
      {
      //DISABLED state?
      case EAP_FULL_AUTH_STATE_DISABLED:
         //Evaluate conditions for the current state
         if(port->portEnabled)
         {
            //Switch to the INITIALIZE state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_INITIALIZE);
         }

         break;

      //INITIALIZE state?
      case EAP_FULL_AUTH_STATE_INITIALIZE:
         //Unconditional transition (UCT) to SELECT_ACTION state
         eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_SELECT_ACTION);
         break;

      //IDLE state?
      case EAP_FULL_AUTH_STATE_IDLE:
         //The state machine spends most of its time here, waiting for
         //something to happen
         if(port->retransWhile == 0)
         {
            //Switch to the RETRANSMIT state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_RETRANSMIT);
         }
         else if(port->eapResp)
         {
            //Switch to the RECEIVED state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_RECEIVED);
         }
         else
         {
            //Just for sanity
         }

         break;

      //RETRANSMIT state?
      case EAP_FULL_AUTH_STATE_RETRANSMIT:
         //Evaluate conditions for the current state
         if(port->retransCount > port->maxRetrans)
         {
            //Switch to the TIMEOUT_FAILURE state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_TIMEOUT_FAILURE);
         }
         else
         {
            //Switch to the IDLE state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_IDLE);
         }

         break;

      //RECEIVED state?
      case EAP_FULL_AUTH_STATE_RECEIVED:
         //Evaluate conditions for the current state
         if(port->rxResp && port->respId == port->currentId &&
            (port->respMethod == EAP_METHOD_TYPE_NAK ||
            port->respMethod == EAP_METHOD_TYPE_EXPANDED_NAK) &&
            port->methodState == EAP_METHOD_STATE_PROPOSED)
         {
            //Switch to the NAK state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_NAK);
         }
         else if(port->rxResp && port->respId == port->currentId &&
            port->respMethod == port->currentMethod)
         {
            //Switch to the INTEGRITY_CHECK state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_INTEGRITY_CHECK);
         }
         else
         {
            //Switch to the DISCARD state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_DISCARD);
         }

         break;

      //NAK state?
      case EAP_FULL_AUTH_STATE_NAK:
         //Unconditional transition (UCT) to SELECT_ACTION state
         eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_SELECT_ACTION);
         break;

      //SELECT_ACTION state?
      case EAP_FULL_AUTH_STATE_SELECT_ACTION:
         //Evaluate conditions for the current state
         if(port->decision == EAP_DECISION_FAILURE)
         {
            //Switch to the FAILURE state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_FAILURE);
         }
         else if(port->decision == EAP_DECISION_SUCCESS)
         {
            //Switch to the SUCCESS state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_SUCCESS);
         }
         else if(port->decision == EAP_DECISION_PASSTHROUGH)
         {
            //Switch to the INITIALIZE_PASSTHROUGH state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_INITIALIZE_PASSTHROUGH);
         }
         else
         {
            //Switch to the PROPOSE_METHOD state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_PROPOSE_METHOD);
         }

         break;

      //INTEGRITY_CHECK state?
      case EAP_FULL_AUTH_STATE_INTEGRITY_CHECK:
         //Evaluate conditions for the current state
         if(port->ignore)
         {
            //Switch to the DISCARD state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_DISCARD);
         }
         else
         {
            //Switch to the METHOD_RESPONSE state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_METHOD_RESPONSE);
         }

         break;

      //METHOD_RESPONSE state?
      case EAP_FULL_AUTH_STATE_METHOD_RESPONSE:
         //Evaluate conditions for the current state
         if(port->methodState == EAP_METHOD_STATE_END)
         {
            //Switch to the SELECT_ACTION state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_SELECT_ACTION);
         }
         else
         {
            //Switch to the METHOD_REQUEST state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_METHOD_REQUEST);
         }

         break;

      //PROPOSE_METHOD state?
      case EAP_FULL_AUTH_STATE_PROPOSE_METHOD:
         //Unconditional transition (UCT) to METHOD_REQUEST state
         eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_METHOD_REQUEST);
         break;

      //METHOD_REQUEST state?
      case EAP_FULL_AUTH_STATE_METHOD_REQUEST:
         //Unconditional transition (UCT) to SEND_REQUEST state
         eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_SEND_REQUEST);
         break;

      //DISCARD state?
      case EAP_FULL_AUTH_STATE_DISCARD:
         //Unconditional transition (UCT) to IDLE state
         eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_IDLE);
         break;

      //SEND_REQUEST state?
      case EAP_FULL_AUTH_STATE_SEND_REQUEST:
         //Unconditional transition (UCT) to IDLE state
         eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_IDLE);
         break;

      //TIMEOUT_FAILURE state?
      case EAP_FULL_AUTH_STATE_TIMEOUT_FAILURE:
         //Final state indicating failure because no response has been received
         break;

      //FAILURE state?
      case EAP_FULL_AUTH_STATE_FAILURE:
         //Final state indicating failure
         break;

      //SUCCESS state?
      case EAP_FULL_AUTH_STATE_SUCCESS:
         //Final state indicating success
         break;

      //INITIALIZE_PASSTHROUGH state?
      case EAP_FULL_AUTH_STATE_INITIALIZE_PASSTHROUGH:
         //Evaluate conditions for the current state
         if(port->currentId != EAP_CURRENT_ID_NONE)
         {
            //Switch to the AAA_REQUEST state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_AAA_REQUEST);
         }
         else
         {
            //Switch to the AAA_IDLE state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_AAA_IDLE);
         }

         break;

      //IDLE2 state?
      case EAP_FULL_AUTH_STATE_IDLE2:
         //The state machine waits for a response from the primary lower layer,
         //which transports EAP traffic from the peer
         if(port->retransWhile == 0)
         {
            //Switch to the RETRANSMIT2 state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_RETRANSMIT2);
         }
         else if(port->eapResp)
         {
            //Switch to the RECEIVED2 state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_RECEIVED2);
         }
         else
         {
            //Just for sanity
         }

         break;

      //RETRANSMIT2 state?
      case EAP_FULL_AUTH_STATE_RETRANSMIT2:
         //Evaluate conditions for the current state
         if(port->retransCount > port->maxRetrans)
         {
            //Switch to the TIMEOUT_FAILURE2 state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_TIMEOUT_FAILURE2);
         }
         else
         {
            //Switch to the IDLE2 state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_IDLE2);
         }

         break;

      //RECEIVED2 state?
      case EAP_FULL_AUTH_STATE_RECEIVED2:
         //Evaluate conditions for the current state
         if(port->rxResp && port->respId == port->currentId)
         {
            //Switch to the AAA_REQUEST state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_AAA_REQUEST);
         }
         else
         {
            //Switch to the DISCARD2 state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_DISCARD2);
         }

         break;

      //AAA_REQUEST state?
      case EAP_FULL_AUTH_STATE_AAA_REQUEST:
         //Unconditional transition (UCT) to AAA_IDLE state
         eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_AAA_IDLE);
         break;

      //AAA_IDLE state?
      case EAP_FULL_AUTH_STATE_AAA_IDLE:
         //Evaluate conditions for the current state
         if(port->aaaEapNoReq)
         {
            //Switch to the DISCARD2 state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_DISCARD2);
         }
         else if(port->aaaEapReq)
         {
            //Switch to the AAA_RESPONSE state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_AAA_RESPONSE);
         }
         else if(port->aaaTimeout)
         {
            //Switch to the TIMEOUT_FAILURE2 state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_TIMEOUT_FAILURE2);
         }
         else if(port->aaaFail)
         {
            //Switch to the FAILURE2 state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_FAILURE2);
         }
         else if(port->aaaSuccess)
         {
            //Switch to the SUCCESS2 state
            eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_SUCCESS2);
         }
         else
         {
            //Just for sanity
         }

         break;

      //AAA_RESPONSE state?
      case EAP_FULL_AUTH_STATE_AAA_RESPONSE:
         //Unconditional transition (UCT) to SEND_REQUEST2 state
         eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_SEND_REQUEST2);
         break;

      //DISCARD2 state?
      case EAP_FULL_AUTH_STATE_DISCARD2:
         //Unconditional transition (UCT) to IDLE2 state
         eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_IDLE2);
         break;

      //SEND_REQUEST2 state?
      case EAP_FULL_AUTH_STATE_SEND_REQUEST2:
         //Unconditional transition (UCT) to IDLE2 state
         eapFullAuthChangeState(port, EAP_FULL_AUTH_STATE_IDLE2);
         break;

      //TIMEOUT_FAILURE2 state?
      case EAP_FULL_AUTH_STATE_TIMEOUT_FAILURE2:
         //Final state indicating failure because no response has been received
         break;

      //FAILURE2 state?
      case EAP_FULL_AUTH_STATE_FAILURE2:
         //Final state indicating failure
         break;

      //SUCCESS2 state?
      case EAP_FULL_AUTH_STATE_SUCCESS2:
         //Final state indicating success
         break;

      //Invalid state?
      default:
         //Just for sanity
         authenticatorFsmError(port->context);
         break;
      }
   }
}


/**
 * @brief Update EAP full authenticator state
 * @param[in] port Pointer to the port context
 * @param[in] newState New state to switch to
 **/

void eapFullAuthChangeState(AuthenticatorPort *port,
   EapFullAuthState newState)
{
   size_t n;
   EapFullAuthState oldState;

   //Retrieve current state
   oldState = port->eapFullAuthState;

   //Any state change?
   if(newState != oldState)
   {
      //Dump the state transition
      TRACE_DEBUG("Port %" PRIu8 ": EAP full authenticator state machine %s -> %s\r\n",
         port->portIndex,
         eapGetParamName(oldState, eapFullAuthStates,
         arraysize(eapFullAuthStates)),
         eapGetParamName(newState, eapFullAuthStates,
         arraysize(eapFullAuthStates)));
   }

   //Switch to the new state
   port->eapFullAuthState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to RFC 4137, section 3.1)
   switch(newState)
   {
   //DISABLED state?
   case EAP_FULL_AUTH_STATE_DISABLED:
      //No action
      break;

   //INITIALIZE state?
   case EAP_FULL_AUTH_STATE_INITIALIZE:
      //Initialize variables
      port->currentId = EAP_CURRENT_ID_NONE;
      port->eapSuccess = FALSE;
      port->eapFail = FALSE;
      port->eapTimeout = FALSE;
      port->eapKeyData = NULL;
      port->eapKeyAvailable = FALSE;
      port->eapRestart = FALSE;

      //Errata
      port->currentMethod = EAP_METHOD_TYPE_NONE;
      port->serverStateLen = 0;
      break;

   //IDLE state?
   case EAP_FULL_AUTH_STATE_IDLE:
      //Calculate the retransmission timeout, taking into account the
      //retransmission count, round-trip time measurements, and method-specific
      //timeout hint
      port->retransWhile = eapCalculateTimeout(port);
      break;

   //RETRANSMIT state?
   case EAP_FULL_AUTH_STATE_RETRANSMIT:
      //Increment retransmission counter
      port->retransCount++;

      //Check retransmission counter
      if(port->retransCount <= port->maxRetrans)
      {
         //Retransmitted requests must be sent with the same identifier value
         port->eapReqData = port->lastReqData;
         port->eapReqDataLen = port->lastReqDataLen;
         port->eapReq = TRUE;
      }

      break;

   //RECEIVED state?
   case EAP_FULL_AUTH_STATE_RECEIVED:
      //This state is entered when an EAP packet is received. The packet
      //header is parsed here
      eapParseResp(port);
      break;

   //NAK state?
   case EAP_FULL_AUTH_STATE_NAK:
      //This state processes Nak responses from the peer
      eapReset(port);
      eapPolicyUpdate(port);
      break;

   //SELECT_ACTION state?
   case EAP_FULL_AUTH_STATE_SELECT_ACTION:
      //Between methods, the state machine re-evaluates whether its policy is
      //satisfied and succeeds, fails, or remains undecided
      port->decision = eapPolicyGetDecision(port);
      break;

   //INTEGRITY_CHECK state?
   case EAP_FULL_AUTH_STATE_INTEGRITY_CHECK:
      //The integrity of the incoming packet from the peer is verified by
      //the method
      port->ignore = eapCheckResp(port);
      break;

   //METHOD_RESPONSE state?
   case EAP_FULL_AUTH_STATE_METHOD_RESPONSE:
      //Incoming packet is processed
      eapProcessResp(port);

      //Check for method completion
      if(eapIsDone(port))
      {
         eapPolicyUpdate(port);
         port->eapKeyData = eapAuthGetKey(port);
         port->methodState = EAP_METHOD_STATE_END;
      }
      else
      {
         port->methodState = EAP_METHOD_STATE_CONTINUE;
      }

      break;

   //PROPOSE_METHOD state?
   case EAP_FULL_AUTH_STATE_PROPOSE_METHOD:
      //The authenticator decides which method to try next in the authentication
      port->currentMethod = eapPolicyGetNextMethod(port);
      //Initialize state
      eapInit(port);

      //Identity or Notification method?
      if(port->currentMethod == EAP_METHOD_TYPE_IDENTITY ||
         port->currentMethod == EAP_METHOD_TYPE_NOTIFICATION)
      {
         port->methodState = EAP_METHOD_STATE_CONTINUE;
      }
      else
      {
         port->methodState = EAP_METHOD_STATE_PROPOSED;
      }

      break;

   //METHOD_REQUEST state?
   case EAP_FULL_AUTH_STATE_METHOD_REQUEST:
      //A new request is formulated if necessary
      port->currentId = eapNextId(port->currentId);
      eapBuildReq(port);
      port->methodTimeout = eapGetTimeout(port);
      break;

   //DISCARD state?
   case EAP_FULL_AUTH_STATE_DISCARD:
      //This state signals the lower layer that the response was discarded,
      //and no new request packet will be sent at this time
      port->eapResp = FALSE;
      port->eapNoReq = TRUE;
      break;

   //SEND_REQUEST state?
   case EAP_FULL_AUTH_STATE_SEND_REQUEST:
      //This state signals the lower layer that a request packet is ready
      //to be sent
      port->retransCount = 0;
      port->lastReqData = port->eapReqData;
      port->lastReqDataLen = port->eapReqDataLen;
      port->eapResp = FALSE;
      port->eapReq = TRUE;
      break;

   //TIMEOUT_FAILURE state?
   case EAP_FULL_AUTH_STATE_TIMEOUT_FAILURE:
      //Final state indicating failure because no response has been received
      port->eapTimeout = TRUE;
      break;

   //FAILURE state?
   case EAP_FULL_AUTH_STATE_FAILURE:
      //Create an EAP failure packet
      eapBuildFailure(port);
      //The state machine has reached the FAILURE state
      port->eapFail = TRUE;
      break;

   //SUCCESS state?
   case EAP_FULL_AUTH_STATE_SUCCESS:
      //Create an EAP success packet
      eapBuildSuccess(port);

      //Valid EAP key?
      if(port->eapKeyData != NULL)
      {
         port->eapKeyAvailable = TRUE;
      }

      //The state machine has reached the SUCCESS state
      port->eapSuccess = TRUE;
      break;

   //INITIALIZE_PASSTHROUGH state?
   case EAP_FULL_AUTH_STATE_INITIALIZE_PASSTHROUGH:
      //Initialize variables when the pass-through portion of the state machine
      //is activated
      port->aaaEapRespData = NULL;
      port->aaaEapRespDataLen = 0;
      break;

   //IDLE2 state?
   case EAP_FULL_AUTH_STATE_IDLE2:
      //Calculate the retransmission timeout, taking into account the
      //retransmission count, round-trip time measurements, and method-specific
      //timeout hint
      port->retransWhile = eapCalculateTimeout(port);
      break;

   //RETRANSMIT2 state?
   case EAP_FULL_AUTH_STATE_RETRANSMIT2:
      //Increment retransmission counter
      port->retransCount++;

      //Check retransmission counter
      if(port->retransCount <= port->maxRetrans)
      {
         //Retransmitted requests must be sent with the same identifier value
         port->eapReqData = port->lastReqData;
         port->eapReqDataLen = port->lastReqDataLen;
         port->eapReq = TRUE;
      }

      break;

   //RECEIVED2 state?
   case EAP_FULL_AUTH_STATE_RECEIVED2:
      //This state is entered when an EAP packet is received and the
      //authenticator is in PASSTHROUGH mode. The packet header is parsed
      //here
      eapParseResp(port);
      break;

   //AAA_REQUEST state?
   case EAP_FULL_AUTH_STATE_AAA_REQUEST:
      //Identity response received?
      if(port->respMethod == EAP_METHOD_TYPE_IDENTITY)
      {
         //Determine the length of the identity
         n = port->eapRespDataLen - sizeof(EapResponse);
         //Limit the length of the string
         n = MIN(n, AUTHENTICATOR_MAX_ID_LEN);

         //The NAS must copy the contents of the Type-Data field of the
         //EAP-Response/Identity received from the peer (refer to RFC 3579,
         //section 2.1)
         osMemcpy(port->aaaIdentity, port->eapRespData + sizeof(EapResponse), n);
         port->aaaIdentity[n] = '\0';
      }

      //The incoming EAP packet is parsed for sending to the AAA server
      port->aaaEapRespData = port->eapRespData;
      port->aaaEapRespDataLen = port->eapRespDataLen;
      break;

   //AAA_IDLE state?
   case EAP_FULL_AUTH_STATE_AAA_IDLE:
      //Idle state that tells the AAA layer that it has a response and then
      //waits for a new request, a no-request signal, or success/failure
      port->aaaFail = FALSE;
      port->aaaSuccess = FALSE;
      port->aaaEapReq = FALSE;
      port->aaaEapNoReq = FALSE;
      port->aaaEapResp = TRUE;
      break;

   //AAA_RESPONSE state?
   case EAP_FULL_AUTH_STATE_AAA_RESPONSE:
      //The request from the AAA interface is processed into an EAP request
      port->eapReqData = port->aaaEapReqData;
      port->eapReqDataLen = port->aaaEapReqDataLen;
      port->currentId = eapGetId(port->eapReqData, port->eapReqDataLen);
      port->methodTimeout = port->aaaMethodTimeout;
      break;

   //DISCARD2 state?
   case EAP_FULL_AUTH_STATE_DISCARD2:
      //This state signals the lower layer that the response was discarded,
      //and that no new request packet will be sent at this time
      port->eapResp = FALSE;
      port->eapNoReq = TRUE;
      break;

   //SEND_REQUEST2 state?
   case EAP_FULL_AUTH_STATE_SEND_REQUEST2:
      //This state signals the lower layer that a request packet is ready
      //to be sent
      port->retransCount = 0;
      port->lastReqData = port->eapReqData;
      port->lastReqDataLen = port->eapReqDataLen;
      port->eapResp = FALSE;
      port->eapReq = TRUE;
      break;

   //TIMEOUT_FAILURE2 state?
   case EAP_FULL_AUTH_STATE_TIMEOUT_FAILURE2:
      //The authenticator has reached its maximum number of retransmissions
      //without receiving a response
      port->eapTimeout = TRUE;
      //Errata
      port->eapNoReq = TRUE;
      break;

   //FAILURE2 state?
   case EAP_FULL_AUTH_STATE_FAILURE2:
      //Final state indicating failure
      port->eapReqData = port->aaaEapReqData;
      port->eapReqDataLen = port->aaaEapReqDataLen;
      port->eapFail = TRUE;
      break;

   //SUCCESS2 state?
   case EAP_FULL_AUTH_STATE_SUCCESS2:
      //Final state indicating success
      port->eapReqData = port->aaaEapReqData;
      port->eapReqDataLen = port->aaaEapReqDataLen;
      port->eapKeyData = port->aaaEapKeyData;
      port->eapKeyAvailable = port->aaaEapKeyAvailable;
      port->eapSuccess = TRUE;
      break;

   //Invalid state?
   default:
      //Just for sanity
      break;
   }

   //Any state change?
   if(newState != oldState)
   {
      //Any registered callback?
      if(port->context->eapFullAuthStateChangeCallback != NULL)
      {
         //Invoke user callback function
         port->context->eapFullAuthStateChangeCallback(port, newState);
      }
   }

   //Check whether the port is enabled
   if(port->portControl == AUTHENTICATOR_PORT_MODE_AUTO &&
      !port->initialize && port->portEnabled)
   {
      //The EAP full authenticator state machine is busy
      port->context->busy = TRUE;
   }
}

#endif
