/**
 * @file supplicant_backend_fsm.c
 * @brief Supplicant backend state machine
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
#include "supplicant/supplicant_backend_fsm.h"
#include "supplicant/supplicant_procedures.h"
#include "supplicant/supplicant_misc.h"
#include "eap/eap_debug.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (SUPPLICANT_SUPPORT == ENABLED)

//Supplicant backend states
const EapParamName supplicantBackendStates[] =
{
   {SUPPLICANT_BACKEND_STATE_INITIALIZE, "INITIALIZE"},
   {SUPPLICANT_BACKEND_STATE_IDLE,       "IDLE"},
   {SUPPLICANT_BACKEND_STATE_REQUEST,    "REQUEST"},
   {SUPPLICANT_BACKEND_STATE_RESPONSE,   "RESPONSE"},
   {SUPPLICANT_BACKEND_STATE_RECEIVE,    "RECEIVE"},
   {SUPPLICANT_BACKEND_STATE_FAIL,       "FAIL"},
   {SUPPLICANT_BACKEND_STATE_TIMEOUT,    "TIMEOUT"},
   {SUPPLICANT_BACKEND_STATE_SUCCESS,    "SUCCESS"}
};


/**
 * @brief Supplicant backend state machine initialization
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void supplicantBackendInitFsm(SupplicantContext *context)
{
   //Enter initial state
   supplicantBackendChangeState(context, SUPPLICANT_BACKEND_STATE_INITIALIZE);
}


/**
 * @brief Supplicant backend state machine implementation
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void supplicantBackendFsm(SupplicantContext *context)
{
   //A global transition can occur from any of the possible states
   if(context->initialize || context->suppAbort)
   {
      //When the condition associated with a global transition is met, it
      //supersedes all other exit conditions
      supplicantBackendChangeState(context, SUPPLICANT_BACKEND_STATE_INITIALIZE);
   }
   else
   {
      //All exit conditions for the state are evaluated continuously until one
      //of the conditions is met (refer to IEEE Std 802.1X-2004, section 8.2.1)
      switch(context->suppBackendState)
      {
      //INITIALIZE state?
      case SUPPLICANT_BACKEND_STATE_INITIALIZE:
         //Unconditional transition (UCT) to IDLE state
         supplicantBackendChangeState(context, SUPPLICANT_BACKEND_STATE_IDLE);
         break;

      //IDLE state?
      case SUPPLICANT_BACKEND_STATE_IDLE:
         //Evaluate conditions for the current state
         if(context->eapFail && context->suppStart)
         {
            //Switch to the FAIL state
            supplicantBackendChangeState(context, SUPPLICANT_BACKEND_STATE_FAIL);
         }
         else if(context->eapolEap && context->suppStart)
         {
            //Switch to the REQUEST state
            supplicantBackendChangeState(context, SUPPLICANT_BACKEND_STATE_REQUEST);
         }
         else if(context->eapSuccess && context->suppStart)
         {
            //Switch to the SUCCESS state
            supplicantBackendChangeState(context, SUPPLICANT_BACKEND_STATE_SUCCESS);
         }
         else
         {
            //Just for sanity
         }

         break;

      //REQUEST state?
      case SUPPLICANT_BACKEND_STATE_REQUEST:
         //Evaluate conditions for the current state
         if(context->eapFail)
         {
            //Switch to the FAIL state
            supplicantBackendChangeState(context, SUPPLICANT_BACKEND_STATE_FAIL);
         }
         else if(context->eapNoResp)
         {
            //Switch to the RECEIVE state
            supplicantBackendChangeState(context, SUPPLICANT_BACKEND_STATE_RECEIVE);
         }
         else if(context->eapResp)
         {
            //Switch to the RESPONSE state
            supplicantBackendChangeState(context, SUPPLICANT_BACKEND_STATE_RESPONSE);
         }
         else if(context->eapSuccess)
         {
            //Switch to the SUCCESS state
            supplicantBackendChangeState(context, SUPPLICANT_BACKEND_STATE_SUCCESS);
         }
         else
         {
            //Just for sanity
         }

         break;

      //RESPONSE state?
      case SUPPLICANT_BACKEND_STATE_RESPONSE:
         //Unconditional transition (UCT) to RECEIVE state
         supplicantBackendChangeState(context, SUPPLICANT_BACKEND_STATE_RECEIVE);
         break;

      //RECEIVE state?
      case SUPPLICANT_BACKEND_STATE_RECEIVE:
         //Evaluate conditions for the current state
         if(context->eapolEap)
         {
            //Switch to the REQUEST state
            supplicantBackendChangeState(context, SUPPLICANT_BACKEND_STATE_REQUEST);
         }
         else if(context->eapFail)
         {
            //Switch to the FAIL state
            supplicantBackendChangeState(context, SUPPLICANT_BACKEND_STATE_FAIL);
         }
         else if(context->authWhile == 0)
         {
            //Switch to the TIMEOUT state
            supplicantBackendChangeState(context, SUPPLICANT_BACKEND_STATE_TIMEOUT);
         }
         else if(context->eapSuccess)
         {
            //Switch to the SUCCESS state
            supplicantBackendChangeState(context, SUPPLICANT_BACKEND_STATE_SUCCESS);
         }
         else
         {
            //Just for sanity
         }

         break;

      //FAIL state?
      case SUPPLICANT_BACKEND_STATE_FAIL:
         //Unconditional transition (UCT) to IDLE state
         supplicantBackendChangeState(context, SUPPLICANT_BACKEND_STATE_IDLE);
         break;

      //TIMEOUT state?
      case SUPPLICANT_BACKEND_STATE_TIMEOUT:
         //Unconditional transition (UCT) to IDLE state
         supplicantBackendChangeState(context, SUPPLICANT_BACKEND_STATE_IDLE);
         break;

      //SUCCESS state?
      case SUPPLICANT_BACKEND_STATE_SUCCESS:
         //Unconditional transition (UCT) to IDLE state
         supplicantBackendChangeState(context, SUPPLICANT_BACKEND_STATE_IDLE);
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
 * @brief Update supplicant backend state
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] newState New state to switch to
 **/

void supplicantBackendChangeState(SupplicantContext *context,
   SupplicantBackendState newState)
{
   SupplicantBackendState oldState;

   //Retrieve current state
   oldState = context->suppBackendState;

   //Any state change?
   if(newState != oldState)
   {
      //Dump the state transition
      TRACE_DEBUG("Supplicant Backend state machine %s -> %s\r\n",
         eapGetParamName(oldState, supplicantBackendStates,
         arraysize(supplicantBackendStates)),
         eapGetParamName(newState, supplicantBackendStates,
         arraysize(supplicantBackendStates)));
   }

   //Switch to the new state
   context->suppBackendState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to IEEE Std 802.1X-2004, section 8.2.1)
   switch(newState)
   {
   //INITIALIZE state?
   case SUPPLICANT_BACKEND_STATE_INITIALIZE:
      //System initialization
      supplicantAbortSupp(context);
      context->suppAbort = FALSE;
      //Errata
      context->eapReq = FALSE;
      break;

   //IDLE state?
   case SUPPLICANT_BACKEND_STATE_IDLE:
      //The state machine is waiting for the supplicant state machine to signal
      //the start of a new authentication session
      context->suppStart = FALSE;
      break;

   //REQUEST state?
   case SUPPLICANT_BACKEND_STATE_REQUEST:
      //The state machine has received an EAP request from the authenticator,
      //and invokes EAP to perform whatever processing is needed in order to
      //acquire the information that will form the response
      context->authWhile = 0;
      context->eapReq = TRUE;
      supplicantGetSuppRsp(context);
      break;

   //RESPONSE state?
   case SUPPLICANT_BACKEND_STATE_RESPONSE:
      //The appropriate EAP response constructed by EAP is transmitted to the
      //authenticator
      supplicantTxSuppRsp(context);
      context->eapResp = FALSE;
      break;

   //RECEIVE state?
   case SUPPLICANT_BACKEND_STATE_RECEIVE:
      //The supplicant is waiting for the next EAP request from the
      //authenticator
      context->authWhile = context->authPeriod;
      context->eapolEap = FALSE;
      context->eapNoResp = FALSE;
      break;

   //FAIL state?
   case SUPPLICANT_BACKEND_STATE_FAIL:
      //The authentication session has terminated unsuccessfully
      context->suppFail = TRUE;
      //Errata
      context->eapolEap = FALSE;
      break;

   //TIMEOUT state?
   case SUPPLICANT_BACKEND_STATE_TIMEOUT:
      //The authentication session has terminated due to a timeout
      context->suppTimeout = TRUE;
      break;

   //SUCCESS state?
   case SUPPLICANT_BACKEND_STATE_SUCCESS:
      //The authentication session has terminated successfully
      context->keyRun = TRUE;
      context->suppSuccess = TRUE;
      //Errata
      context->eapolEap = FALSE;
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
      if(context->backendStateChangeCallback != NULL)
      {
         //Invoke user callback function
         context->backendStateChangeCallback(context, newState);
      }
   }

   //Check whether the port is enabled
   if(!context->initialize && context->portEnabled)
   {
      //The supplicant backend state machine is busy
      context->busy = TRUE;
   }
}

#endif
