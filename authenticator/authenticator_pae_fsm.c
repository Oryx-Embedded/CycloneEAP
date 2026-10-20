/**
 * @file authenticator_pae_fsm.c
 * @brief Authenticator PAE state machine
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
#include "authenticator/authenticator_pae_fsm.h"
#include "authenticator/authenticator_procedures.h"
#include "authenticator/authenticator_misc.h"
#include "eap/eap_debug.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (AUTHENTICATOR_SUPPORT == ENABLED)

//Authenticator PAE states
const EapParamName authenticatorPaeStates[] =
{
   {AUTHENTICATOR_PAE_STATE_INITIALIZE,     "INITIALIZE"},
   {AUTHENTICATOR_PAE_STATE_DISCONNECTED,   "DISCONNECTED"},
   {AUTHENTICATOR_PAE_STATE_RESTART,        "RESTART"},
   {AUTHENTICATOR_PAE_STATE_CONNECTING,     "CONNECTING"},
   {AUTHENTICATOR_PAE_STATE_AUTHENTICATING, "AUTHENTICATING"},
   {AUTHENTICATOR_PAE_STATE_AUTHENTICATED,  "AUTHENTICATED"},
   {AUTHENTICATOR_PAE_STATE_ABORTING,       "ABORTING"},
   {AUTHENTICATOR_PAE_STATE_HELD,           "HELD"},
   {AUTHENTICATOR_PAE_STATE_FORCE_AUTH,     "FORCE_AUTH"},
   {AUTHENTICATOR_PAE_STATE_FORCE_UNAUTH,   "FORCE_UNAUTH"}
};


/**
 * @brief Authenticator PAE state machine initialization
 * @param[in] port Pointer to the port context
 **/

void authenticatorPaeInitFsm(AuthenticatorPort *port)
{
   //Enter initial state
   authenticatorPaeChangeState(port, AUTHENTICATOR_PAE_STATE_INITIALIZE);
}


/**
 * @brief Authenticator PAE state machine implementation
 * @param[in] port Pointer to the port context
 **/

void authenticatorPaeFsm(AuthenticatorPort *port)
{
   //A global transition can occur from any of the possible states. When the
   //condition associated with a global transition is met, it supersedes all
   //other exit conditions
   if((port->portControl == AUTHENTICATOR_PORT_MODE_AUTO &&
      port->portMode != port->portControl) ||
      port->initialize || !port->portEnabled)
   {
      //Switch to the INITIALIZE state
      authenticatorPaeChangeState(port, AUTHENTICATOR_PAE_STATE_INITIALIZE);
   }
   else if(port->portControl == AUTHENTICATOR_PORT_MODE_FORCE_AUTH &&
      port->portMode != port->portControl &&
      !(port->initialize || !port->portEnabled))
   {
      //Switch to the FORCE_AUTH state
      authenticatorPaeChangeState(port, AUTHENTICATOR_PAE_STATE_FORCE_AUTH);
   }
   else if(port->portControl == AUTHENTICATOR_PORT_MODE_FORCE_UNAUTH &&
      port->portMode != port->portControl &&
      !(port->initialize || !port->portEnabled))
   {
      //Switch to the FORCE_UNAUTH state
      authenticatorPaeChangeState(port, AUTHENTICATOR_PAE_STATE_FORCE_UNAUTH);
   }
   else
   {
      //All exit conditions for the state are evaluated continuously until one
      //of the conditions is met (refer to IEEE Std 802.1X-2004, section 8.2.1)
      switch(port->authPaeState)
      {
      //INITIALIZE state?
      case AUTHENTICATOR_PAE_STATE_INITIALIZE:
         //Unconditional transition (UCT) to DISCONNECTED state
         authenticatorPaeChangeState(port, AUTHENTICATOR_PAE_STATE_DISCONNECTED);
         break;

      //DISCONNECTED state?
      case AUTHENTICATOR_PAE_STATE_DISCONNECTED:
         //Unconditional transition (UCT) to RESTART state
         authenticatorPaeChangeState(port, AUTHENTICATOR_PAE_STATE_RESTART);
         break;

      //RESTART state?
      case AUTHENTICATOR_PAE_STATE_RESTART:
         //This state will exit to CONNECTING when EAP has acknowledged the
         //restart by resetting eapRestart to FALSE
         if(!port->eapRestart)
         {
            //Switch to the CONNECTING state
            authenticatorPaeChangeState(port, AUTHENTICATOR_PAE_STATE_CONNECTING);
         }

         break;

      //CONNECTING state?
      case AUTHENTICATOR_PAE_STATE_CONNECTING:
         //Evaluate conditions for the current state
         if(port->eapolLogoff || port->reAuthCount > port->reAuthMax)
         {
            //Switch to the DISCONNECTED state
            authenticatorPaeChangeState(port, AUTHENTICATOR_PAE_STATE_DISCONNECTED);
         }
         else if((port->eapReq && port->reAuthCount <= port->reAuthMax) ||
            port->eapSuccess || port->eapFail)
         {
            //Switch to the AUTHENTICATING state
            authenticatorPaeChangeState(port, AUTHENTICATOR_PAE_STATE_AUTHENTICATING);
         }
         else
         {
            //Just for sanity
         }

         break;

      //AUTHENTICATING state?
      case AUTHENTICATOR_PAE_STATE_AUTHENTICATING:
         //Evaluate conditions for the current state
         if(port->authSuccess && port->portValid)
         {
            //Switch to the AUTHENTICATED state
            authenticatorPaeChangeState(port, AUTHENTICATOR_PAE_STATE_AUTHENTICATED);
         }
         else if(port->eapolStart || port->eapolLogoff || port->authTimeout)
         {
            //Switch to the ABORTING state
            authenticatorPaeChangeState(port, AUTHENTICATOR_PAE_STATE_ABORTING);
         }
         else if(port->authFail || (port->keyDone && !port->portValid))
         {
            //Switch to the HELD state
            authenticatorPaeChangeState(port, AUTHENTICATOR_PAE_STATE_HELD);
         }
         else
         {
            //Just for sanity
         }

         break;

      //AUTHENTICATED state?
      case AUTHENTICATOR_PAE_STATE_AUTHENTICATED:
         //Evaluate conditions for the current state
         if(port->eapolStart || port->reAuthenticate)
         {
            //Switch to the RESTART state
            authenticatorPaeChangeState(port, AUTHENTICATOR_PAE_STATE_RESTART);
         }
         else if(port->eapolLogoff || !port->portValid)
         {
            //Switch to the DISCONNECTED state
            authenticatorPaeChangeState(port, AUTHENTICATOR_PAE_STATE_DISCONNECTED);
         }
         else
         {
            //Just for sanity
         }

         break;

      //ABORTING state?
      case AUTHENTICATOR_PAE_STATE_ABORTING:
         //Evaluate conditions for the current state
         if(port->eapolLogoff && !port->authAbort)
         {
            //Switch to the DISCONNECTED state
            authenticatorPaeChangeState(port, AUTHENTICATOR_PAE_STATE_DISCONNECTED);
         }
         else if(!port->eapolLogoff && !port->authAbort)
         {
            //Switch to the RESTART state
            authenticatorPaeChangeState(port, AUTHENTICATOR_PAE_STATE_RESTART);
         }
         else
         {
            //Just for sanity
         }

         break;

      //HELD state?
      case AUTHENTICATOR_PAE_STATE_HELD:
         //At the expiration of the quietWhile timer, the state machine
         //transitions to the RESTART state
         if(port->quietWhile == 0)
         {
            //Switch to the RESTART state
            authenticatorPaeChangeState(port, AUTHENTICATOR_PAE_STATE_RESTART);
         }

         break;

      //FORCE_AUTH state?
      case AUTHENTICATOR_PAE_STATE_FORCE_AUTH:
         //If an EAPOL-Start message is received from the supplicant, the state
         //is re-entered and a further EAP success message is sent
         if(port->eapolStart)
         {
            //Switch to the FORCE_AUTH state
            authenticatorPaeChangeState(port, AUTHENTICATOR_PAE_STATE_FORCE_AUTH);
         }

         break;

      //FORCE_UNAUTH state?
      case AUTHENTICATOR_PAE_STATE_FORCE_UNAUTH:
         //If an EAPOL-Start message is received from the supplicant, the state
         //is re-entered and a further EAP failure message is sent
         if(port->eapolStart)
         {
            //Switch to the FORCE_UNAUTH state
            authenticatorPaeChangeState(port, AUTHENTICATOR_PAE_STATE_FORCE_UNAUTH);
         }

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
 * @brief Update authenticator PAE state
 * @param[in] port Pointer to the port context
 * @param[in] newState New state to switch to
 **/

void authenticatorPaeChangeState(AuthenticatorPort *port,
   AuthenticatorPaeState newState)
{
   AuthenticatorPaeState oldState;

   //Retrieve current state
   oldState = port->authPaeState;

   //Any state change?
   if(newState != oldState)
   {
      //Dump the state transition
      TRACE_DEBUG("Port %" PRIu8 ": Authenticator PAE state machine %s -> %s\r\n",
         port->portIndex,
         eapGetParamName(oldState, authenticatorPaeStates,
         arraysize(authenticatorPaeStates)),
         eapGetParamName(newState, authenticatorPaeStates,
         arraysize(authenticatorPaeStates)));
   }

   //Switch to the new state
   port->authPaeState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to IEEE Std 802.1X-2004, section 8.2.1)
   switch(newState)
   {
   //INITIALIZE state?
   case AUTHENTICATOR_PAE_STATE_INITIALIZE:
      //The value of the portMode variable is set to Auto
      port->portMode = AUTHENTICATOR_PORT_MODE_AUTO;

      //Errata
      if(port->authPortStatus != AUTHENTICATOR_PORT_STATUS_UNAUTH)
      {
         authenticatorSetAuthPortStatus(port, AUTHENTICATOR_PORT_STATUS_UNAUTH);
      }

      break;

   //DISCONNECTED state?
   case AUTHENTICATOR_PAE_STATE_DISCONNECTED:
      //Errata
      if(port->eapolStart)
      {
         port->sessionStats.sessionTerminateCause =
            AUTHENTICATOR_TERMINATE_CAUSE_SUPPLICANT_RESTART;
      }
      else if(port->eapolLogoff)
      {
         port->sessionStats.sessionTerminateCause =
            AUTHENTICATOR_TERMINATE_CAUSE_SUPPLICANT_LOGOFF;
      }
      else if(port->reAuthCount > port->reAuthMax)
      {
         port->sessionStats.sessionTerminateCause =
            AUTHENTICATOR_TERMINATE_CAUSE_REAUTH_FAILED;
      }
      else
      {
      }

      //The authPortStatus variable is set to Unauthorized in this state,
      //thereby setting the value of AuthControlledPortStatus to Unauthorized,
      //the eapolLogoff variable is cleared and the reAuthCount is reset
      authenticatorSetAuthPortStatus(port, AUTHENTICATOR_PORT_STATUS_UNAUTH);
      port->reAuthCount = 0;
      port->eapolLogoff = FALSE;
      break;

   //RESTART state?
   case AUTHENTICATOR_PAE_STATE_RESTART:
      //The RESTART state is entered when the authenticator PAE needs to
      //inform the higher layer that it has restarted
      port->eapRestart = TRUE;
      break;

   //CONNECTING state?
   case AUTHENTICATOR_PAE_STATE_CONNECTING:
      //In this state, the port is operable, the higher layer is in sync and
      //ready to attempt to establish communication with a supplicant
      port->reAuthenticate = FALSE;
      port->reAuthCount++;
      break;

   //AUTHENTICATING state?
   case AUTHENTICATOR_PAE_STATE_AUTHENTICATING:
      //In this state, a supplicant is being authenticated
      port->eapolStart = FALSE;
      port->authSuccess = FALSE;
      port->authFail = FALSE;
      port->authTimeout = FALSE;
      port->authStart = TRUE;
      port->keyRun = FALSE;
      port->keyDone = FALSE;
      break;

   //AUTHENTICATED state?
   case AUTHENTICATOR_PAE_STATE_AUTHENTICATED:
      //In this state, the Authenticator has successfully authenticated the
      //supplicant and the portValid variable has become TRUE
      authenticatorSetAuthPortStatus(port, AUTHENTICATOR_PORT_STATUS_AUTH);
      port->reAuthCount = 0;

      //Errata
      port->sessionStats.sessionTerminateCause =
         AUTHENTICATOR_TERMINATE_CAUSE_NOT_TERMINATED_YET;

      break;

   //ABORTING state?
   case AUTHENTICATOR_PAE_STATE_ABORTING:
      //In this state, the authentication procedure is being prematurely
      //aborted due to receipt of an EAPOL-Start frame, an EAPOL-Logoff
      //frame, or an authTimeout
      port->authAbort = TRUE;
      port->keyRun = FALSE;
      port->keyDone = FALSE;
      break;

   //HELD state?
   case AUTHENTICATOR_PAE_STATE_HELD:
      //In this state, the state machine ignores and discards all EAPOL
      //packets, so as to discourage brute force attacks
      authenticatorSetAuthPortStatus(port, AUTHENTICATOR_PORT_STATUS_UNAUTH);
      port->quietWhile = port->quietPeriod;
      port->eapolLogoff = FALSE;
      break;

   //FORCE_AUTH state?
   case AUTHENTICATOR_PAE_STATE_FORCE_AUTH:
      //The authPortStatus is set to Authorized, and a canned EAP success
      //packet is sent to the supplicant
      authenticatorSetAuthPortStatus(port, AUTHENTICATOR_PORT_STATUS_AUTH);
      port->portMode = AUTHENTICATOR_PORT_MODE_FORCE_AUTH;
      port->eapolStart = FALSE;
      authenticatorTxCannedSuccess(port);

      //Errata
      port->sessionStats.sessionTerminateCause =
         AUTHENTICATOR_TERMINATE_CAUSE_NOT_TERMINATED_YET;

      break;

   //FORCE_UNAUTH state?
   case AUTHENTICATOR_PAE_STATE_FORCE_UNAUTH:
      //The authPortStatus is set to Unauthorized, and a canned EAP failure
      //packet is sent to the supplicant
      authenticatorSetAuthPortStatus(port, AUTHENTICATOR_PORT_STATUS_UNAUTH);
      port->portMode = AUTHENTICATOR_PORT_MODE_FORCE_UNAUTH;
      port->eapolStart = FALSE;
      authenticatorTxCannedFail(port);

      //Errata
      port->sessionStats.sessionTerminateCause =
         AUTHENTICATOR_TERMINATE_CAUSE_AUTH_CONTROL_FORCE_UNAUTH;

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
      if(port->context->paeStateChangeCallback != NULL)
      {
         //Invoke user callback function
         port->context->paeStateChangeCallback(port, newState);
      }
   }

   //Check whether the port is enabled
   if(!port->initialize && port->portEnabled)
   {
      //The authenticator PAE state machine is busy
      port->context->busy = TRUE;
   }
}

#endif
