/**
 * @file authenticator_backend_fsm.c
 * @brief Backend authentication state machine
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
#include "authenticator/authenticator_backend_fsm.h"
#include "authenticator/authenticator_procedures.h"
#include "authenticator/authenticator_misc.h"
#include "eap/eap_debug.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (AUTHENTICATOR_SUPPORT == ENABLED)

//Backend authentication states
const EapParamName authenticatorBackendStates[] =
{
   {AUTHENTICATOR_BACKEND_STATE_INITIALIZE, "INITIALIZE"},
   {AUTHENTICATOR_BACKEND_STATE_IDLE,       "IDLE"},
   {AUTHENTICATOR_BACKEND_STATE_REQUEST,    "REQUEST"},
   {AUTHENTICATOR_BACKEND_STATE_RESPONSE,   "RESPONSE"},
   {AUTHENTICATOR_BACKEND_STATE_IGNORE,     "IGNORE"},
   {AUTHENTICATOR_BACKEND_STATE_FAIL,       "FAIL"},
   {AUTHENTICATOR_BACKEND_STATE_TIMEOUT,    "TIMEOUT"},
   {AUTHENTICATOR_BACKEND_STATE_SUCCESS,    "SUCCESS"}
};


/**
 * @brief Backend authentication state machine initialization
 * @param[in] port Pointer to the port context
 **/

void authenticatorBackendInitFsm(AuthenticatorPort *port)
{
   //Enter initial state
   authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_INITIALIZE);
}


/**
 * @brief Backend authentication state machine implementation
 * @param[in] port Pointer to the port context
 **/

void authenticatorBackendFsm(AuthenticatorPort *port)
{
   //A global transition can occur from any of the possible states. When the
   //condition associated with a global transition is met, it supersedes all
   //other exit conditions
   if(port->portControl != AUTHENTICATOR_PORT_MODE_AUTO ||
      port->initialize || port->authAbort)
   {
      //Switch to the INITIALIZE state
      authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_INITIALIZE);
   }
   else
   {
      //All exit conditions for the state are evaluated continuously until one
      //of the conditions is met (refer to IEEE Std 802.1X-2004, section 8.2.1)
      switch(port->authBackendState)
      {
      //INITIALIZE state?
      case AUTHENTICATOR_BACKEND_STATE_INITIALIZE:
         //Unconditional transition (UCT) to IDLE state
         authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_IDLE);
         break;

      //IDLE state?
      case AUTHENTICATOR_BACKEND_STATE_IDLE:
         //Evaluate conditions for the current state
         if(port->eapFail && port->authStart)
         {
            //Switch to the FAIL state
            authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_FAIL);
         }
         else if(port->eapReq && port->authStart)
         {
            //Switch to the REQUEST state
            authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_REQUEST);
         }
         else if(port->eapSuccess && port->authStart)
         {
            //Switch to the SUCCESS state
            authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_SUCCESS);
         }
         else
         {
            //Just for sanity
         }

         break;

      //REQUEST state?
      case AUTHENTICATOR_BACKEND_STATE_REQUEST:
         //Evaluate conditions for the current state
         if(port->eapTimeout)
         {
            //Switch to the TIMEOUT state
            authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_TIMEOUT);
         }
         else if(port->eapolEap)
         {
            //Switch to the RESPONSE state
            authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_RESPONSE);
         }
         else if(port->eapReq)
         {
            //Switch to the REQUEST state
            authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_REQUEST);
         }
         else
         {
            //Just for sanity
         }

         break;

      //RESPONSE state?
      case AUTHENTICATOR_BACKEND_STATE_RESPONSE:
         //Evaluate conditions for the current state
         if(port->eapNoReq)
         {
            //Switch to the IGNORE state
            authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_IGNORE);
         }
         else if(port->aWhile == 0)
         {
            //Switch to the TIMEOUT state
            authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_TIMEOUT);
         }
         else if(port->eapFail)
         {
            //Switch to the FAIL state
            authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_FAIL);
         }
         else if(port->eapSuccess)
         {
            //Switch to the SUCCESS state
            authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_SUCCESS);
         }
         else if(port->eapReq)
         {
            //Switch to the REQUEST state
            authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_REQUEST);
         }
         else
         {
            //Just for sanity
         }

         break;

      //IGNORE state?
      case AUTHENTICATOR_BACKEND_STATE_IGNORE:
         //Evaluate conditions for the current state
         if(port->eapolEap)
         {
            //Switch to the RESPONSE state
            authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_RESPONSE);
         }
         else if(port->eapReq)
         {
            //Switch to the REQUEST state
            authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_REQUEST);
         }
         else if(port->eapTimeout)
         {
            //Switch to the TIMEOUT state
            authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_TIMEOUT);
         }
         else
         {
            //Just for sanity
         }

         break;

      //FAIL state?
      case AUTHENTICATOR_BACKEND_STATE_FAIL:
         //Unconditional transition (UCT) to IDLE state
         authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_IDLE);
         break;

      //TIMEOUT state?
      case AUTHENTICATOR_BACKEND_STATE_TIMEOUT:
         //Unconditional transition (UCT) to IDLE state
         authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_IDLE);
         break;

      //SUCCESS state?
      case AUTHENTICATOR_BACKEND_STATE_SUCCESS:
         //Unconditional transition (UCT) to IDLE state
         authenticatorBackendChangeState(port, AUTHENTICATOR_BACKEND_STATE_IDLE);
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
 * @brief Update backend authentication state
 * @param[in] port Pointer to the port context
 * @param[in] newState New state to switch to
 **/

void authenticatorBackendChangeState(AuthenticatorPort *port,
   AuthenticatorBackendState newState)
{
   AuthenticatorBackendState oldState;

   //Retrieve current state
   oldState = port->authBackendState;

   //Any state change?
   if(newState != oldState)
   {
      //Dump the state transition
      TRACE_DEBUG("Port %" PRIu8 ": Backend authentication state machine %s -> %s\r\n",
         port->portIndex,
         eapGetParamName(oldState, authenticatorBackendStates,
         arraysize(authenticatorBackendStates)),
         eapGetParamName(newState, authenticatorBackendStates,
         arraysize(authenticatorBackendStates)));
   }

   //Switch to the new state
   port->authBackendState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to IEEE Std 802.1X-2004, section 8.2.1)
   switch(newState)
   {
   //INITIALIZE state?
   case AUTHENTICATOR_BACKEND_STATE_INITIALIZE:
      //The abortAuth procedure is used to release any system resources that
      //may have been occupied by the session
      authenticatorAbortAuth(port);
      port->eapNoReq = FALSE;
      port->authAbort = FALSE;
      break;

   //IDLE state?
   case AUTHENTICATOR_BACKEND_STATE_IDLE:
      //In this state, the state machine is waiting for the authenticator state
      //machine to signal the start of a new authentication session
      port->authStart = FALSE;
      break;

   //REQUEST state?
   case AUTHENTICATOR_BACKEND_STATE_REQUEST:
      //In this state, the state machine has received an EAP request packet
      //from the higher layer and is relaying that packet to the supplicant as
      //an EAPOL-encapsulated frame
      authenticatorTxReq(port);
      port->eapReq = FALSE;
      break;

   //RESPONSE state?
   case AUTHENTICATOR_BACKEND_STATE_RESPONSE:
      //In this state, the state machine has received an EAPOL-encapsulated
      //EAP response packet from the supplicant, and is relaying the EAP packet
      //to the higher layer to be relayed on to the Authentication Server, and
      //is awaiting instruction from the higher layer as to what to do next
      port->authTimeout = FALSE;
      port->eapolEap = FALSE;
      port->eapNoReq = FALSE;
      port->aWhile = port->serverTimeout;
      port->eapResp = TRUE;
      authenticatorSendRespToServer(port);
      break;

   //IGNORE state?
   case AUTHENTICATOR_BACKEND_STATE_IGNORE:
      //This state is entered when the higher layer has decided to ignore the
      //previous EAP response message received from the supplicant
      port->eapNoReq = FALSE;
      break;

   //FAIL state?
   case AUTHENTICATOR_BACKEND_STATE_FAIL:
      //The state machine sets the global variable authFail TRUE in order to
      //signal to the Authenticator state machine that the authentication
      //session has terminated with an authentication failure, and it transmits
      //the final EAP message from the AAA client that was encapsulated in the
      //Reject message from the authentication server
      authenticatorTxReq(port);
      port->authFail = TRUE;
      break;

   //TIMEOUT state?
   case AUTHENTICATOR_BACKEND_STATE_TIMEOUT:
      //The state machine sets the global variable authTimeout TRUE in order
      //to signal to the Authenticator state machine that the authentication
      //session has terminated with a timeout
      port->authTimeout = TRUE;
      break;

   //SUCCESS state?
   case AUTHENTICATOR_BACKEND_STATE_SUCCESS:
      //The state machine sets the global variable authSuccess TRUE in order
      //to signal to the authenticator state machine that the authentication
      //session has terminated successfully, and it transmits the final EAP
      //message from the AAA client that was encapsulated in the Accept message
      //from the authentication server
      authenticatorTxReq(port);
      port->authSuccess = TRUE;
      port->keyRun = TRUE;
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
      if(port->context->backendStateChangeCallback != NULL)
      {
         //Invoke user callback function
         port->context->backendStateChangeCallback(port, newState);
      }
   }

   //Check whether the port is enabled
   if(port->portControl == AUTHENTICATOR_PORT_MODE_AUTO &&
      !port->initialize && !port->authAbort)
   {
      //The backend authentication state machine is busy
      port->context->busy = TRUE;
   }
}

#endif
