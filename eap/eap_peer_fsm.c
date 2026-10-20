/**
 * @file eap_peer_fsm.c
 * @brief EAP peer state machine
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
#include "supplicant/supplicant_fsm.h"
#include "supplicant/supplicant_misc.h"
#include "eap/eap_peer_fsm.h"
#include "eap/eap_peer_procedures.h"
#include "eap/eap_debug.h"
#include "debug.h"

//Check EAP library configuration
#if (EAP_SUPPORT == ENABLED)

//EAP peer states
const EapParamName eapPeerStates[] =
{
   {EAP_PEER_STATE_DISABLED,      "DISABLED"},
   {EAP_PEER_STATE_INITIALIZE,    "INITIALIZE"},
   {EAP_PEER_STATE_IDLE,          "IDLE"},
   {EAP_PEER_STATE_RECEIVED,      "RECEIVED"},
   {EAP_PEER_STATE_METHOD,        "METHOD"},
   {EAP_PEER_STATE_GET_METHOD,    "GET_METHOD"},
   {EAP_PEER_STATE_IDENTITY,      "IDENTITY"},
   {EAP_PEER_STATE_NOTIFICATION,  "NOTIFICATION"},
   {EAP_PEER_STATE_RETRANSMIT,    "RETRANSMIT"},
   {EAP_PEER_STATE_DISCARD,       "DISCARD"},
   {EAP_PEER_STATE_SEND_RESPONSE, "SEND_RESPONSE"},
   {EAP_PEER_STATE_SUCCESS,       "SUCCESS"},
   {EAP_PEER_STATE_FAILURE,       "FAILURE"}
};


/**
 * @brief EAP peer state machine initialization
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void eapPeerInitFsm(SupplicantContext *context)
{
   //Enter initial state
   eapPeerChangeState(context, EAP_PEER_STATE_INITIALIZE);
}


/**
 * @brief EAP peer state machine implementation
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void eapPeerFsm(SupplicantContext *context)
{
   //A global transition can occur from any of the possible states
   if(!context->portEnabled)
   {
      //Switch to the DISABLED state
      eapPeerChangeState(context, EAP_PEER_STATE_DISABLED);
   }
   else if(context->eapRestart && context->portEnabled)
   {
      //Switch to the INITIALIZE state
      eapPeerChangeState(context, EAP_PEER_STATE_INITIALIZE);
   }
   else
   {
      //All exit conditions for the state are evaluated continuously until one
      //of the conditions is met (refer to RFC 4137, section 3.1)
      switch(context->eapPeerState)
      {
      //DISABLED state?
      case EAP_PEER_STATE_DISABLED:
         //Immediate transition to INITIALIZE occurs when the port becomes
         //enabled
         if(context->portEnabled)
         {
            //Switch to the INITIALIZE state
            eapPeerChangeState(context, EAP_PEER_STATE_INITIALIZE);
         }

         break;

      //INITIALIZE state?
      case EAP_PEER_STATE_INITIALIZE:
         //Unconditional transition (UCT) to IDLE state
         eapPeerChangeState(context, EAP_PEER_STATE_IDLE);
         break;

      //IDLE state?
      case EAP_PEER_STATE_IDLE:
         //The state machine spends most of its time here, waiting for something
         //to happen
         if(context->eapReq)
         {
            //Switch to the RECEIVED state
            eapPeerChangeState(context, EAP_PEER_STATE_RECEIVED);
         }
         else if((context->altAccept && context->decision != EAP_DECISION_FAIL) ||
            (context->idleWhile == 0 && context->decision == EAP_DECISION_UNCOND_SUCC))
         {
            //Switch to the SUCCESS state
            eapPeerChangeState(context, EAP_PEER_STATE_SUCCESS);
         }
         else if(context->altReject ||
            (context->idleWhile == 0 && context->decision != EAP_DECISION_UNCOND_SUCC) ||
            (context->altAccept && context->methodState != EAP_METHOD_STATE_CONT &&
            context->decision == EAP_DECISION_FAIL))
         {
            //Switch to the FAILURE state
            eapPeerChangeState(context, EAP_PEER_STATE_FAILURE);
         }
         else
         {
            //Just for sanity
         }

         break;

      //RECEIVED state?
      case EAP_PEER_STATE_RECEIVED:
         //Evaluate conditions for the current state
         if(context->rxReq && context->reqId != context->lastId &&
            context->reqMethod == context->selectedMethod &&
            context->methodState != EAP_METHOD_STATE_DONE)
         {
            //Switch to the METHOD state
            eapPeerChangeState(context, EAP_PEER_STATE_METHOD);
         }
         else if(context->rxReq && context->reqId != context->lastId &&
            context->selectedMethod == EAP_METHOD_TYPE_NONE &&
            context->reqMethod != EAP_METHOD_TYPE_IDENTITY &&
            context->reqMethod != EAP_METHOD_TYPE_NOTIFICATION)
         {
            //Switch to the GET_METHOD state
            eapPeerChangeState(context, EAP_PEER_STATE_GET_METHOD);
         }
         else if(context->rxReq && context->reqId != context->lastId &&
            context->selectedMethod == EAP_METHOD_TYPE_NONE &&
            context->reqMethod == EAP_METHOD_TYPE_IDENTITY)
         {
            //Switch to the IDENTITY state
            eapPeerChangeState(context, EAP_PEER_STATE_IDENTITY);
         }
         else if(context->rxReq && context->reqId != context->lastId &&
            context->reqMethod == EAP_METHOD_TYPE_NOTIFICATION &&
            context->allowNotifications)
         {
            //Switch to the NOTIFICATION state
            eapPeerChangeState(context, EAP_PEER_STATE_NOTIFICATION);
         }
         else if(context->rxReq && context->reqId == context->lastId)
         {
            //Switch to the RETRANSMIT state
            eapPeerChangeState(context, EAP_PEER_STATE_RETRANSMIT);
         }
         else if(context->rxSuccess && context->reqId == context->lastId &&
            context->decision != EAP_DECISION_FAIL)
         {
            //Switch to the SUCCESS state
            eapPeerChangeState(context, EAP_PEER_STATE_SUCCESS);
         }
         //Errata
         else if(context->rxSuccess && context->lastId != EAP_LAST_ID_NONE &&
            context->reqId == ((context->lastId + 1) % 256) &&
            context->decision != EAP_DECISION_FAIL)
         {
            //Switch to the SUCCESS state
            eapPeerChangeState(context, EAP_PEER_STATE_SUCCESS);
         }
         //Errata
         else if(context->rxSuccess && context->lastId == EAP_LAST_ID_NONE &&
            context->allowCanned)
         {
            //Switch to the SUCCESS state
            eapPeerChangeState(context, EAP_PEER_STATE_SUCCESS);
         }
         else if(context->methodState != EAP_METHOD_STATE_CONT &&
            ((context->rxFailure && context->decision != EAP_DECISION_UNCOND_SUCC) ||
            (context->rxSuccess && context->decision == EAP_DECISION_FAIL)) &&
            context->reqId == context->lastId)
         {
            //Switch to the FAILURE state
            eapPeerChangeState(context, EAP_PEER_STATE_FAILURE);
         }
         //Errata
         else if(context->methodState != EAP_METHOD_STATE_CONT &&
            ((context->rxFailure && context->decision != EAP_DECISION_UNCOND_SUCC) ||
            (context->rxSuccess && context->decision == EAP_DECISION_FAIL)) &&
            context->lastId != EAP_LAST_ID_NONE &&
            context->reqId == ((context->lastId + 1) % 256))
         {
            //Switch to the FAILURE state
            eapPeerChangeState(context, EAP_PEER_STATE_FAILURE);
         }
         //Errata
         else if(context->methodState != EAP_METHOD_STATE_CONT &&
            context->rxFailure && context->lastId == EAP_LAST_ID_NONE &&
            context->allowCanned)
         {
            //Switch to the FAILURE state
            eapPeerChangeState(context, EAP_PEER_STATE_FAILURE);
         }
         else
         {
            //Switch to the DISCARD state
            eapPeerChangeState(context, EAP_PEER_STATE_DISCARD);
         }

         break;

      //METHOD state?
      case EAP_PEER_STATE_METHOD:
         //Evaluate conditions for the current state
         if(context->ignore)
         {
            //Switch to the DISCARD state
            eapPeerChangeState(context, EAP_PEER_STATE_DISCARD);
         }
         else if(context->methodState == EAP_METHOD_STATE_DONE &&
            context->decision == EAP_DECISION_FAIL)
         {
            //Switch to the FAILURE state
            eapPeerChangeState(context, EAP_PEER_STATE_FAILURE);
         }
         else
         {
            //Switch to the SEND_RESPONSE state
            eapPeerChangeState(context, EAP_PEER_STATE_SEND_RESPONSE);
         }

         break;

      //GET_METHOD state?
      case EAP_PEER_STATE_GET_METHOD:
         //Evaluate conditions for the current state
         if(context->selectedMethod == context->reqMethod)
         {
            //Switch to the METHOD state
            eapPeerChangeState(context, EAP_PEER_STATE_METHOD);
         }
         else
         {
            //Switch to the SEND_RESPONSE state
            eapPeerChangeState(context, EAP_PEER_STATE_SEND_RESPONSE);
         }

         break;

      //IDENTITY state?
      case EAP_PEER_STATE_IDENTITY:
         //Unconditional transition (UCT) to SEND_RESPONSE state
         eapPeerChangeState(context, EAP_PEER_STATE_SEND_RESPONSE);
         break;

      //NOTIFICATION state?
      case EAP_PEER_STATE_NOTIFICATION:
         //Unconditional transition (UCT) to SEND_RESPONSE state
         eapPeerChangeState(context, EAP_PEER_STATE_SEND_RESPONSE);
         break;

      //RETRANSMIT state?
      case EAP_PEER_STATE_RETRANSMIT:
         //Unconditional transition (UCT) to SEND_RESPONSE state
         eapPeerChangeState(context, EAP_PEER_STATE_SEND_RESPONSE);
         break;

      //DISCARD state?
      case EAP_PEER_STATE_DISCARD:
         //Unconditional transition (UCT) to IDLE state
         eapPeerChangeState(context, EAP_PEER_STATE_IDLE);
         break;

      //SEND_RESPONSE state?
      case EAP_PEER_STATE_SEND_RESPONSE:
         //Unconditional transition (UCT) to IDLE state
         eapPeerChangeState(context, EAP_PEER_STATE_IDLE);
         break;

      //SUCCESS state?
      case EAP_PEER_STATE_SUCCESS:
         //Final state indicating success
         break;

      //FAILURE state?
      case EAP_PEER_STATE_FAILURE:
         //Final state indicating failure
         break;

      //Invalid state?
      default:
         //Just for sanity
         supplicantFsmError(context);
         break;
      }
   }
}


/**
 * @brief Update EAP peer state
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] newState New state to switch to
 **/

void eapPeerChangeState(SupplicantContext *context,
   EapPeerState newState)
{
   EapPeerState oldState;

   //Retrieve current state
   oldState = context->eapPeerState;

   //Any state change?
   if(newState != oldState)
   {
      //Dump the state transition
      TRACE_DEBUG("EAP peer state machine %s -> %s\r\n",
         eapGetParamName(oldState, eapPeerStates, arraysize(eapPeerStates)),
         eapGetParamName(newState, eapPeerStates, arraysize(eapPeerStates)));
   }

   //Switch to the new state
   context->eapPeerState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to RFC 4137, section 3.1)
   switch(newState)
   {
   //DISABLED state?
   case EAP_PEER_STATE_DISABLED:
      //This state is reached whenever service from the lower layer is
      //interrupted or unavailable
      break;

   //INITIALIZE state?
   case EAP_PEER_STATE_INITIALIZE:
      //Initialize variables when the state machine is activated
      context->selectedMethod = EAP_METHOD_TYPE_NONE;
      context->methodState = EAP_METHOD_STATE_NONE;
      context->allowNotifications = TRUE;
      context->decision = EAP_DECISION_FAIL;
      context->idleWhile = context->clientTimeout;
      context->lastId = EAP_LAST_ID_NONE;
      context->eapSuccess = FALSE;
      context->eapFail = FALSE;
      context->eapKeyData = NULL;
      context->eapKeyAvailable = FALSE;
      context->eapRestart = FALSE;
      break;

   //IDLE state?
   case EAP_PEER_STATE_IDLE:
      //The state machine spends most of its time here, waiting for something
      //to happen
      break;

   //RECEIVED state?
   case EAP_PEER_STATE_RECEIVED:
      //This state is entered when an EAP packet is received
      eapParseReq(context);
      break;

   //METHOD state?
   case EAP_PEER_STATE_METHOD:
      //The method must decide whether to process the packet or to discard it
      //silently (refer to RFC 4137, section 4.2)
      context->ignore = eapCheckReq(context);

      //Check whether the packet should be processed or discarded
      if(!context->ignore)
      {
         //The request from the authenticator is processed, and an appropriate
         //response packet is built
         eapProcessReq(context);
         eapBuildResp(context);

         //Check whether EAP key is available
         if(eapIsKeyAvailable(context))
         {
            context->eapKeyData = eapPeerGetKey(context);
         }
      }

      break;

   //GET_METHOD state?
   case EAP_PEER_STATE_GET_METHOD:
      //This state is entered when a request for a new type comes in. Either
      //the correct method is started, or a Nak response is built
      if(eapAllowMethod(context, context->reqMethod))
      {
         context->selectedMethod = context->reqMethod;
         context->methodState = EAP_METHOD_STATE_INIT;
      }
      else
      {
         eapBuildNak(context);
      }

      break;

   //IDENTITY state?
   case EAP_PEER_STATE_IDENTITY:
      //Handle request for Identity method and build a response
      eapProcessIdentity(context);
      eapBuildIdentity(context);
      break;

   //NOTIFICATION state?
   case EAP_PEER_STATE_NOTIFICATION:
      //Handle request for Notification method and build a response
      eapProcessNotify(context);
      eapBuildNotify(context);
      break;

   //RETRANSMIT state?
   case EAP_PEER_STATE_RETRANSMIT:
      //Retransmit the previous response packet
      context->eapRespData = context->lastRespData;
      context->eapRespDataLen = context->lastRespDataLen;
      break;

   //DISCARD state?
   case EAP_PEER_STATE_DISCARD:
      //The request was discarded and no response packet will be sent
      context->eapReq = FALSE;
      context->eapNoResp = TRUE;
      break;

   //SEND_RESPONSE state?
   case EAP_PEER_STATE_SEND_RESPONSE:
      //A response packet is ready to be sent
      context->lastId = context->reqId;
      context->lastRespData = context->eapRespData;
      context->lastRespDataLen = context->eapRespDataLen;
      context->eapReq = FALSE;
      context->eapResp = TRUE;
      context->idleWhile = context->clientTimeout;
      break;

   //SUCCESS state?
   case EAP_PEER_STATE_SUCCESS:
      //Valid EAP key?
      if(context->eapKeyData != NULL)
      {
         context->eapKeyAvailable = TRUE;
      }

      //Final state indicating success
      context->eapSuccess = TRUE;
      break;

   //FAILURE state?
   case EAP_PEER_STATE_FAILURE:
      //Final state indicating failure
      context->eapFail = TRUE;
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
      if(context->eapPeerStateChangeCallback != NULL)
      {
         //Invoke user callback function
         context->eapPeerStateChangeCallback(context, newState);
      }
   }

   //Check whether the port is enabled
   if(context->portEnabled)
   {
      //The EAP peer state machine is busy
      context->busy = TRUE;
   }
}

#endif
