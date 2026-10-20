/**
 * @file supplicant_pae_fsm.c
 * @brief Supplicant PAE state machine
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
#include "supplicant/supplicant_pae_fsm.h"
#include "supplicant/supplicant_procedures.h"
#include "supplicant/supplicant_misc.h"
#include "eap/eap_debug.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (SUPPLICANT_SUPPORT == ENABLED)

//Supplicant PAE states
const EapParamName supplicantPaeStates[] =
{
   {SUPPLICANT_PAE_STATE_LOGOFF,         "LOGOFF"},
   {SUPPLICANT_PAE_STATE_DISCONNECTED,   "DISCONNECTED"},
   {SUPPLICANT_PAE_STATE_CONNECTING,     "CONNECTING"},
   {SUPPLICANT_PAE_STATE_AUTHENTICATING, "AUTHENTICATING"},
   {SUPPLICANT_PAE_STATE_AUTHENTICATED,  "AUTHENTICATED"},
   {SUPPLICANT_PAE_STATE_HELD,           "HELD"},
   {SUPPLICANT_PAE_STATE_RESTART,        "RESTART"},
   {SUPPLICANT_PAE_STATE_S_FORCE_AUTH,   "S_FORCE_AUTH"},
   {SUPPLICANT_PAE_STATE_S_FORCE_UNAUTH, "S_FORCE_UNAUTH"}
};


/**
 * @brief Supplicant PAE state machine initialization
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void supplicantPaeInitFsm(SupplicantContext *context)
{
   //Enter initial state
   supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_DISCONNECTED);
}


/**
 * @brief Supplicant PAE state machine implementation
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void supplicantPaeFsm(SupplicantContext *context)
{
   //A global transition can occur from any of the possible states. When the
   //condition associated with a global transition is met, it supersedes all
   //other exit conditions
   if(context->userLogoff && !context->logoffSent &&
      !(context->initialize || !context->portEnabled))
   {
      //Switch to the LOGOFF state
      supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_LOGOFF);
   }
   else if((context->portControl == SUPPLICANT_PORT_MODE_AUTO &&
      context->sPortMode != context->portControl) ||
      context->initialize || !context->portEnabled)
   {
      //Switch to the DISCONNECTED state
      supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_DISCONNECTED);
   }
   else if(context->portControl == SUPPLICANT_PORT_MODE_FORCE_AUTH &&
      context->sPortMode != context->portControl &&
      !(context->initialize || !context->portEnabled))
   {
      //Switch to the S_FORCE_AUTH state
      supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_S_FORCE_AUTH);
   }
   else if(context->portControl == SUPPLICANT_PORT_MODE_FORCE_UNAUTH &&
      context->sPortMode != context->portControl &&
      !(context->initialize || !context->portEnabled))
   {
      //Switch to the S_FORCE_UNAUTH state
      supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_S_FORCE_UNAUTH);
   }
   else
   {
      //All exit conditions for the state are evaluated continuously until one
      //of the conditions is met (refer to IEEE Std 802.1X-2004, section 8.2.1)
      switch(context->suppPaeState)
      {
      //LOGOFF state?
      case SUPPLICANT_PAE_STATE_LOGOFF:
         //Evaluate conditions for the current state
         if(!context->userLogoff)
         {
            //Switch to the DISCONNECTED state
            supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_DISCONNECTED);
         }

         break;

      //DISCONNECTED state?
      case SUPPLICANT_PAE_STATE_DISCONNECTED:
         //Unconditional transition (UCT) to CONNECTING state
         supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_CONNECTING);
         break;

      //CONNECTING state?
      case SUPPLICANT_PAE_STATE_CONNECTING:
         //Evaluate conditions for the current state
         if(context->startWhen == 0)
         {
            //If the startWhen timer expires, the transmission is repeated up
            //to a maximum of maxStart transmissions
            if(context->startCount < context->maxStart)
            {
               //An EAPOL-Start packet is transmitted by the supplicant, and
               //the startWhen timer is started, to cause retransmission if no
               //response is received from the authenticator
               supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_CONNECTING);
            }
            else
            {
               //If no response is received after maxStart transmissions, the state
               //machine assumes that it is attached to a system that is not EAPOL
               //aware, and transitions to AUTHENTICATED state if portValid is TRUE
               if(context->portValid)
               {
                  //Switch to the AUTHENTICATED state
                  supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_AUTHENTICATED);
               }
               else
               {
                  //Switch to the HELD state
                  supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_HELD);
               }
            }
         }
         else if(context->eapolEap)
         {
            //If an EAP-Request frame is received, the supplicant transitions
            //to the RESTART state
            supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_RESTART);
         }
         else if(context->eapSuccess || context->eapFail)
         {
//Errata
#if 0
            //If the higher layer has decided it is satisfied with an
            //eapSuccess or eapFail, the supplicant transitions directly to
            //the AUTHENTICATING state
            supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_AUTHENTICATING);
#endif
         }
         else
         {
            //Just for sanity
         }

         break;

      //AUTHENTICATING state?
      case SUPPLICANT_PAE_STATE_AUTHENTICATING:
         //Evaluate conditions for the current state
         if(context->suppSuccess && context->portValid)
         {
            //Switch to the AUTHENTICATED state
            supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_AUTHENTICATED);
         }
         else if(context->suppFail || (context->keyDone && !context->portValid))
         {
            //Switch to the HELD state
            supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_HELD);
         }
         else if(context->suppTimeout)
         {
            //Switch to the CONNECTING state
            supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_CONNECTING);
         }
         else
         {
            //Just for sanity
         }

         break;

      //AUTHENTICATED state?
      case SUPPLICANT_PAE_STATE_AUTHENTICATED:
         //Evaluate conditions for the current state
         if(context->eapolEap && context->portValid)
         {
            //Switch to the RESTART state
            supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_RESTART);
         }
         else if(!context->portValid)
         {
            //Switch to the DISCONNECTED state
            supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_DISCONNECTED);
         }
         else
         {
            //Just for sanity
         }

         break;

      //HELD state?
      case SUPPLICANT_PAE_STATE_HELD:
         //Evaluate conditions for the current state
         if(context->heldWhile == 0)
         {
            //Switch to the CONNECTING state
            supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_CONNECTING);
         }
         else if(context->eapolEap)
         {
            //Switch to the RESTART state
            supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_RESTART);
         }
         else
         {
            //Just for sanity
         }

         break;

      //RESTART state?
      case SUPPLICANT_PAE_STATE_RESTART:
         //Evaluate conditions for the current state
         if(!context->eapRestart)
         {
            //Switch to the AUTHENTICATING state
            supplicantPaeChangeState(context, SUPPLICANT_PAE_STATE_AUTHENTICATING);
         }

         break;

      //S_FORCE_AUTH state?
      case SUPPLICANT_PAE_STATE_S_FORCE_AUTH:
         //Force the port state to Authorized
         break;

      //S_FORCE_UNAUTH state?
      case SUPPLICANT_PAE_STATE_S_FORCE_UNAUTH:
         //Force the port state to Unauthorized
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
 * @brief Update supplicant PAE state
 * @param[in] context Pointer to the 802.1X supplicant context
 * @param[in] newState New state to switch to
 **/

void supplicantPaeChangeState(SupplicantContext *context,
   SupplicantPaeState newState)
{
   SupplicantPaeState oldState;

   //Retrieve current state
   oldState = context->suppPaeState;

   //Any state change?
   if(newState != oldState)
   {
      //Dump the state transition
      TRACE_DEBUG("Supplicant PAE state machine %s -> %s\r\n",
         eapGetParamName(oldState, supplicantPaeStates,
         arraysize(supplicantPaeStates)),
         eapGetParamName(newState, supplicantPaeStates,
         arraysize(supplicantPaeStates)));
   }

   //Switch to the new state
   context->suppPaeState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to IEEE Std 802.1X-2004, section 8.2.1)
   switch(newState)
   {
   //LOGOFF state?
   case SUPPLICANT_PAE_STATE_LOGOFF:
      //The user of the system requests an explicit logoff
      supplicantTxLogoff(context);
      context->logoffSent = TRUE;
      context->suppPortStatus = SUPPLICANT_PORT_STATUS_UNAUTH;
      break;

   //DISCONNECTED state?
   case SUPPLICANT_PAE_STATE_DISCONNECTED:
      //This state is entered from any other state when the MAC service
      //associated with the port is inoperable, or when the system is
      //initialized or reinitialized
      context->sPortMode = SUPPLICANT_PORT_MODE_AUTO;
      context->startCount = 0;
      context->logoffSent = FALSE;
      context->suppPortStatus = SUPPLICANT_PORT_STATUS_UNAUTH;
      context->suppAbort = TRUE;
      break;

   //CONNECTING state?
   case SUPPLICANT_PAE_STATE_CONNECTING:
      //In this state, the port has become operable and the supplicant is
      //attempting to acquire an authenticator
      context->startWhen = context->startPeriod;
      context->startCount++;
      context->eapolEap = FALSE;
      supplicantTxStart(context);
      break;

   //AUTHENTICATING state?
   case SUPPLICANT_PAE_STATE_AUTHENTICATING:
      //An EAP Request packet has been received from the authenticator
      context->startCount = 0;
      context->suppSuccess = FALSE;
      context->suppFail = FALSE;
      context->suppTimeout = FALSE;
      context->keyRun = FALSE;
      context->keyDone = FALSE;
      context->suppStart = TRUE;
      break;

   //AUTHENTICATED state?
   case SUPPLICANT_PAE_STATE_AUTHENTICATED:
      //The supplicant has been successfully authenticated by the authenticator,
      //or it has assumed that the authenticator is not EAPOL aware
      context->suppPortStatus = SUPPLICANT_PORT_STATUS_AUTH;
      break;

   //HELD state?
   case SUPPLICANT_PAE_STATE_HELD:
      //The state provides a delay period before the supplicant will attempt to
      //acquire an authenticator
      context->heldWhile = context->heldPeriod;
      context->suppPortStatus = SUPPLICANT_PORT_STATUS_UNAUTH;
      break;

   //RESTART state?
   case SUPPLICANT_PAE_STATE_RESTART:
      //The RESTART state is entered when the supplicant PAE needs to inform the
      //higher layer that it has restarted
      context->eapRestart = TRUE;
      break;

   //S_FORCE_AUTH state?
   case SUPPLICANT_PAE_STATE_S_FORCE_AUTH:
      //The effect of these actions is to force the port state to Authorized
      context->suppPortStatus = SUPPLICANT_PORT_STATUS_AUTH;
      context->sPortMode = SUPPLICANT_PORT_MODE_FORCE_AUTH;
      break;

   //S_FORCE_UNAUTH state?
   case SUPPLICANT_PAE_STATE_S_FORCE_UNAUTH:
      //The effect of this set of actions is to force the port state to
      //Unauthorized, and to reflect this state back to the authenticator by
      //issuing a logoff request
      context->suppPortStatus = SUPPLICANT_PORT_STATUS_UNAUTH;
      context->sPortMode = SUPPLICANT_PORT_MODE_FORCE_UNAUTH;
      supplicantTxLogoff(context);
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
      if(context->paeStateChangeCallback != NULL)
      {
         //Invoke user callback function
         context->paeStateChangeCallback(context, newState);
      }
   }

   //Check whether the port is enabled
   if(!context->initialize && context->portEnabled)
   {
      //The supplicant PAE state machine is busy
      context->busy = TRUE;
   }
}

#endif
