/**
 * @file authenticator_reauth_timer_fsm.c
 * @brief Reauthentication timer state machine
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
#include "authenticator/authenticator_reauth_timer_fsm.h"
#include "authenticator/authenticator_procedures.h"
#include "authenticator/authenticator_misc.h"
#include "eap/eap_debug.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (AUTHENTICATOR_SUPPORT == ENABLED)

//Authenticator PAE states
const EapParamName authenticatorReauthTimerStates[] =
{
   {AUTHENTICATOR_REAUTH_TIMER_STATE_INITIALIZE,     "INITIALIZE"},
   {AUTHENTICATOR_REAUTH_TIMER_STATE_REAUTHENTICATE, "REAUTHENTICATE"}
};


/**
 * @brief Authenticator PAE state machine initialization
 * @param[in] port Pointer to the port context
 **/

void authenticatorReauthTimerInitFsm(AuthenticatorPort *port)
{
   //Enter initial state
   authenticatorReauthTimerChangeState(port, AUTHENTICATOR_REAUTH_TIMER_STATE_INITIALIZE);
}


/**
 * @brief Authenticator PAE state machine implementation
 * @param[in] port Pointer to the port context
 **/

void authenticatorReauthTimerFsm(AuthenticatorPort *port)
{
   //A global transition can occur from any of the possible states. When the
   //condition associated with a global transition is met, it supersedes all
   //other exit conditions
   if(port->portControl != AUTHENTICATOR_PORT_MODE_AUTO || port->initialize ||
      port->authPortStatus == AUTHENTICATOR_PORT_STATUS_UNAUTH ||
      !port->reAuthEnabled)
   {
      //Switch to the INITIALIZE state
      authenticatorReauthTimerChangeState(port,
         AUTHENTICATOR_REAUTH_TIMER_STATE_INITIALIZE);
   }
   else
   {
      //All exit conditions for the state are evaluated continuously until one
      //of the conditions is met (refer to IEEE Std 802.1X-2004, section 8.2.1)
      switch(port->reauthTimerState)
      {
      //INITIALIZE state?
      case AUTHENTICATOR_REAUTH_TIMER_STATE_INITIALIZE:
         //When the reAuthWhen timer expires, the state machine will then
         //transition to the REAUTHENTICATE state
         if(port->reAuthWhen == 0)
         {
            //Switch to the REAUTHENTICATE state
            authenticatorReauthTimerChangeState(port,
               AUTHENTICATOR_REAUTH_TIMER_STATE_REAUTHENTICATE);
         }

         break;

      //REAUTHENTICATE state?
      case AUTHENTICATOR_REAUTH_TIMER_STATE_REAUTHENTICATE:
         //Unconditional transition (UCT) to INITIALIZE state
         authenticatorReauthTimerChangeState(port,
            AUTHENTICATOR_REAUTH_TIMER_STATE_INITIALIZE);

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

void authenticatorReauthTimerChangeState(AuthenticatorPort *port,
   AuthenticatorReauthTimerState newState)
{
   AuthenticatorReauthTimerState oldState;

   //Retrieve current state
   oldState = port->reauthTimerState;

   //Any state change?
   if(newState != oldState)
   {
      //Dump the state transition
      TRACE_DEBUG("Port %" PRIu8 ": Reauthentication timer state machine %s -> %s\r\n",
         port->portIndex,
         eapGetParamName(oldState, authenticatorReauthTimerStates,
         arraysize(authenticatorReauthTimerStates)),
         eapGetParamName(newState, authenticatorReauthTimerStates,
         arraysize(authenticatorReauthTimerStates)));
   }

   //Switch to the new state
   port->reauthTimerState = newState;

   //On entry to a state, the procedures defined for the state are executed
   //exactly once (refer to IEEE Std 802.1X-2004, section 8.2.1)
   switch(newState)
   {
   //INITIALIZE state?
   case AUTHENTICATOR_REAUTH_TIMER_STATE_INITIALIZE:
      //The reAuthWhen timer is set to its initial value
      port->reAuthWhen = port->reAuthPeriod;
      break;

   //REAUTHENTICATE state?
   case AUTHENTICATOR_REAUTH_TIMER_STATE_REAUTHENTICATE:
      //The reAuthenticate variable is set TRUE by the reauthentication timer
      //state machine on expiry of the reAuthWhen timer
      port->reAuthenticate = TRUE;
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
      if(port->context->reauthTimerStateChangeCallback != NULL)
      {
         //Invoke user callback function
         port->context->reauthTimerStateChangeCallback(port, newState);
      }
   }

   //Check whether the port is enabled
   if(port->portControl == AUTHENTICATOR_PORT_MODE_AUTO &&
      port->authPortStatus != AUTHENTICATOR_PORT_STATUS_UNAUTH &&
      !port->initialize && port->reAuthEnabled)
   {
      //The authenticator PAE state machine is busy
      port->context->busy = TRUE;
   }
}

#endif
