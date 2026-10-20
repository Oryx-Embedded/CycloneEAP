/**
 * @file authenticator_fsm.c
 * @brief Authenticator state machine
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
#include "authenticator/authenticator_backend_fsm.h"
#include "authenticator/authenticator_reauth_timer_fsm.h"
#include "authenticator/authenticator_misc.h"
#include "eap/eap_full_auth_fsm.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (AUTHENTICATOR_SUPPORT == ENABLED)


/**
 * @brief Authenticator state machine initialization
 * @param[in] context Pointer to the 802.1X authenticator context
 **/

void authenticatorInitFsm(AuthenticatorContext *context)
{
   uint_t i;

   //The state machines are defined on a per-port basis (refer to IEEE Std
   //802.1X-2004, section 8.2)
   for(i = 0; i < context->numPorts; i++)
   {
      //Initialize current port
      authenticatorInitPortFsm(&context->ports[i]);
   }

   //Update authenticator state machines
   authenticatorFsm(context);

   //The PACP state machines are held in their initial state until initialize
   //is deasserted (refer to IEEE Std 802.1X-2004, section 8.2.2.2)
   for(i = 0; i < context->numPorts; i++)
   {
      context->ports[i].initialize = FALSE;
   }
}


/**
 * @brief Initialize authenticator state machine for a given port
 * @param[in] port Pointer to the port context
 **/

void authenticatorInitPortFsm(AuthenticatorPort *port)
{
   AuthenticatorContext *context;

   //Point to the 802.1X authenticator context
   context = port->context;

   //Initialize variables
   port->aWhile = 0;
   port->quietWhile = 0;
   port->reAuthWhen = 0;

   port->authAbort = FALSE;
   port->authFail = FALSE;
   port->authPortStatus = AUTHENTICATOR_PORT_STATUS_UNKNOWN;
   port->authStart = FALSE;
   port->authTimeout = FALSE;
   port->authSuccess = FALSE;
   port->eapFail = FALSE;
   port->eapolEap = FALSE;
   port->eapSuccess = FALSE;
   port->eapTimeout = FALSE;

   port->initialize = TRUE;
   port->keyDone = FALSE;
   port->keyRun = FALSE;
   port->portValid = TRUE;
   port->reAuthenticate = FALSE;

   port->eapolLogoff = FALSE;
   port->eapolStart = FALSE;
   port->eapRestart = FALSE;
   port->portMode = AUTHENTICATOR_PORT_MODE_FORCE_UNAUTH;
   port->reAuthCount = 0;

   port->eapNoReq = FALSE;
   port->eapReq = FALSE;
   port->eapResp = FALSE;

   port->eapRespData = context->rxBuffer + sizeof(EapolPdu);
   port->eapRespDataLen = 0;
   port->retransWhile = 0;

   port->eapReqData = port->eapTxBuffer + sizeof(EapolPdu);
   port->eapReqDataLen = 0;
   port->eapKeyData = NULL;
   port->eapKeyAvailable = 0;

   port->currentMethod = EAP_METHOD_TYPE_NONE;
   port->currentId = EAP_CURRENT_ID_NONE;
   port->methodState = EAP_METHOD_STATE_NONE;
   port->retransCount = 0;
   port->methodTimeout = 0;

   port->rxResp = FALSE;
   port->respId = EAP_CURRENT_ID_NONE;
   port->respMethod = EAP_METHOD_TYPE_NONE;
   port->ignore = FALSE;
   port->decision = EAP_DECISION_FAILURE;

   port->aaaEapReq = FALSE;
   port->aaaEapNoReq = FALSE;
   port->aaaSuccess = FALSE;
   port->aaaFail = FALSE;
   port->aaaEapReqData = port->eapTxBuffer + sizeof(EapolPdu);
   port->aaaEapReqDataLen = 0;
   port->aaaEapKeyData = NULL;
   port->aaaEapKeyAvailable = FALSE;
   port->aaaMethodTimeout = AUTHENTICATOR_DEFAULT_METHOD_TIMEOUT;

   port->aaaEapResp = FALSE;
   port->aaaEapRespData = NULL;
   port->aaaEapRespDataLen = 0;
   port->aaaIdentity[0] = '\0';
   port->aaaTimeout = FALSE;

   port->aaaReqId = 0;
   port->aaaReqData = port->aaaTxBuffer;
   port->aaaReqDataLen = 0;
   port->aaaRetransTimer = 0;
   port->aaaRetransCount = 0;

   //Initialize authenticator PAE state machine
   authenticatorPaeInitFsm(port);
   //Initialize backend authentication state machine
   authenticatorBackendInitFsm(port);
   //Initialize reauthentication timer state machine
   authenticatorReauthTimerInitFsm(port);
   //Initialize EAP full authenticator state machine
   eapFullAuthInitFsm(port);
}


/**
 * @brief Authenticator state machine implementation
 * @param[in] context Pointer to the 802.1X authenticator context
 **/

void authenticatorFsm(AuthenticatorContext *context)
{
   error_t error;
   uint_t i;
   AuthenticatorPort *port;

   //The behavior of the 802.1X authenticator is specified by a number of
   //cooperating state machines
   do
   {
      //Clear the busy flag
      context->busy = FALSE;

      //The state machines are defined on a per-port basis (refer to IEEE Std
      //802.1X-2004, section 8.2)
      for(i = 0; i < context->numPorts; i++)
      {
         //Point to the current port
         port = &context->ports[i];

         //Update the authenticator PAE state machine
         authenticatorPaeFsm(port);
         //Update the backend authentication state machine
         authenticatorBackendFsm(port);
         //Update the reauthentication timer state machine
         authenticatorReauthTimerFsm(port);
         //Update the EAP full authenticator state machine
         eapFullAuthFsm(port);

         //Check the state of the EAP full authenticator state machine
         if(port->eapFullAuthState == EAP_FULL_AUTH_STATE_AAA_IDLE)
         {
            //Any EAP response available for processing by the AAA server?
            if(port->aaaEapResp)
            {
               //Encapsulate the EAP response in a RADIUS Access-Request packet
               error = authenticatorBuildRadiusRequest(port);

               //Check status code
               if(!error)
               {
                  //Send the RADIUS Access-Request packet
                  authenticatorSendRadiusRequest(port);
                  //A response from the AAA server is now awaited
                  port->aaaTimeout = FALSE;
               }
               else
               {
                  //The AAA layer is unable to process the EAP response
                  port->aaaTimeout = TRUE;
                  context->busy = TRUE;
               }

               //The EAP response has been processed by the AAA layer
               port->aaaEapResp = FALSE;
            }
            else if(port->aaaRetransTimer == 0)
            {
               //Check retransmission counter
               if(port->aaaRetransCount < AUTHENTICATOR_MAX_RADIUS_RETRANS)
               {
                  //Retransmit RADIUS Access-Request packet
                  authenticatorSendRadiusRequest(port);
               }
               else
               {
                  //Set the aaaTimeout flag if, after a configurable amount of
                  //time, there is no response from the AAA layer
                  port->aaaTimeout = TRUE;
                  context->busy = TRUE;
               }
            }
            else
            {
               //Just for sanity
            }
         }
      }

      //Transition conditions are evaluated continuously as long as the
      //authenticator state machine is busy
   } while(context->busy);
}


/**
 * @brief Authenticator state machine error handler
 * @param[in] context Pointer to the 802.1X authenticator context
 **/

void authenticatorFsmError(AuthenticatorContext *context)
{
   //Debug message
   TRACE_ERROR("Authenticator state machine error!\r\n");
}

#endif
