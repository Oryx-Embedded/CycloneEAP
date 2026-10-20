/**
 * @file supplicant_fsm.c
 * @brief Supplicant state machine
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
#include "supplicant/supplicant_backend_fsm.h"
#include "eap/eap_peer_fsm.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (SUPPLICANT_SUPPORT == ENABLED)


/**
 * @brief Supplicant state machine initialization
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void supplicantInitFsm(SupplicantContext *context)
{
   //Initialize variables
   context->authWhile = 0;
   context->heldWhile = 0;
   context->startWhen = 0;

   context->eapFail = FALSE;
   context->eapolEap = FALSE;
   context->eapSuccess = FALSE;
   context->initialize = FALSE;
   context->keyDone = FALSE;
   context->keyRun = FALSE;
   context->portEnabled = FALSE;
   context->portValid = TRUE;
   context->suppAbort = FALSE;
   context->suppFail = FALSE;
   context->suppPortStatus = SUPPLICANT_PORT_STATUS_UNAUTH;
   context->suppStart = FALSE;
   context->suppSuccess = FALSE;
   context->suppTimeout = FALSE;

   context->eapRestart = FALSE;
   context->logoffSent = FALSE;
   context->sPortMode = SUPPLICANT_PORT_MODE_FORCE_UNAUTH;
   context->startCount = 0;

   context->eapNoResp = FALSE;
   context->eapReq = FALSE;
   context->eapResp = FALSE;

   context->allowNotifications = TRUE;
   context->eapReqData = context->rxBuffer + sizeof(EapolPdu);
   context->eapReqDataLen = 0;
   context->idleWhile = 0;
   context->altAccept = FALSE;
   context->altReject = FALSE;
   context->eapRespData = context->txBuffer + sizeof(EapolPdu);
   context->eapRespDataLen = 0;
   context->eapKeyData = NULL;
   context->eapKeyAvailable = FALSE;

   context->selectedMethod = EAP_METHOD_TYPE_NONE;
   context->methodState = EAP_METHOD_STATE_NONE;
   context->lastId = 0;
   context->lastRespData = context->txBuffer + sizeof(EapolPdu);
   context->lastRespDataLen = 0;
   context->decision = EAP_DECISION_FAIL;

   context->rxReq = FALSE;
   context->rxSuccess = FALSE;
   context->rxFailure = FALSE;
   context->reqId = 0;
   context->reqMethod = EAP_METHOD_TYPE_NONE;
   context->ignore = FALSE;

   context->allowCanned = TRUE;

   //Initialize supplicant PAE state machine
   supplicantPaeInitFsm(context);
   //Initialize supplicant backend state machine
   supplicantBackendInitFsm(context);
   //Initialize EAP peer state machine
   eapPeerInitFsm(context);

   //Update supplicant state machines
   supplicantFsm(context);
}


/**
 * @brief Supplicant state machine implementation
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void supplicantFsm(SupplicantContext *context)
{
   //The operation of the supplicant can be represented with three simple
   //state machines
   do
   {
      //Clear the busy flag
      context->busy = FALSE;

      //Update the supplicant PAE state machine
      supplicantPaeFsm(context);
      //Update the supplicant backend state machine
      supplicantBackendFsm(context);
      //Update the EAP peer state machine
      eapPeerFsm(context);

      //Transition conditions are evaluated continuously as long as the
      //supplicant state machine is busy
   } while(context->busy);
}


/**
 * @brief Supplicant state machine error handler
 * @param[in] context Pointer to the 802.1X supplicant context
 **/

void supplicantFsmError(SupplicantContext *context)
{
   //Debug message
   TRACE_ERROR("Supplicant state machine error!\r\n");
}

#endif
