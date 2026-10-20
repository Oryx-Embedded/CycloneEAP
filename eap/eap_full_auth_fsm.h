/**
 * @file eap_full_auth_fsm.h
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

#ifndef _EAP_FULL_AUTH_FSM_H
#define _EAP_FULL_AUTH_FSM_H

//Dependencies
#include <limits.h>
#include "authenticator/authenticator.h"

//Invalid identifier
#define EAP_CURRENT_ID_NONE UINT_MAX

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief EAP full authenticator states
 **/

typedef enum
{
   EAP_FULL_AUTH_STATE_DISABLED               = 0,
   EAP_FULL_AUTH_STATE_INITIALIZE             = 1,
   EAP_FULL_AUTH_STATE_IDLE                   = 2,
   EAP_FULL_AUTH_STATE_RETRANSMIT             = 3,
   EAP_FULL_AUTH_STATE_RECEIVED               = 4,
   EAP_FULL_AUTH_STATE_NAK                    = 5,
   EAP_FULL_AUTH_STATE_SELECT_ACTION          = 6,
   EAP_FULL_AUTH_STATE_INTEGRITY_CHECK        = 7,
   EAP_FULL_AUTH_STATE_METHOD_RESPONSE        = 8,
   EAP_FULL_AUTH_STATE_PROPOSE_METHOD         = 9,
   EAP_FULL_AUTH_STATE_METHOD_REQUEST         = 10,
   EAP_FULL_AUTH_STATE_DISCARD                = 11,
   EAP_FULL_AUTH_STATE_SEND_REQUEST           = 12,
   EAP_FULL_AUTH_STATE_TIMEOUT_FAILURE        = 13,
   EAP_FULL_AUTH_STATE_FAILURE                = 14,
   EAP_FULL_AUTH_STATE_SUCCESS                = 15,
   EAP_FULL_AUTH_STATE_INITIALIZE_PASSTHROUGH = 16,
   EAP_FULL_AUTH_STATE_IDLE2                  = 17,
   EAP_FULL_AUTH_STATE_RETRANSMIT2            = 18,
   EAP_FULL_AUTH_STATE_RECEIVED2              = 19,
   EAP_FULL_AUTH_STATE_AAA_REQUEST            = 20,
   EAP_FULL_AUTH_STATE_AAA_IDLE               = 21,
   EAP_FULL_AUTH_STATE_AAA_RESPONSE           = 22,
   EAP_FULL_AUTH_STATE_DISCARD2               = 23,
   EAP_FULL_AUTH_STATE_SEND_REQUEST2          = 24,
   EAP_FULL_AUTH_STATE_TIMEOUT_FAILURE2       = 25,
   EAP_FULL_AUTH_STATE_FAILURE2               = 26,
   EAP_FULL_AUTH_STATE_SUCCESS2               = 27
} EapFullAuthState;


/**
 * @brief EAP method states
 **/

typedef enum
{
   EAP_METHOD_STATE_NONE     = 0,
   EAP_METHOD_STATE_CONTINUE = 1,
   EAP_METHOD_STATE_PROPOSED = 2,
   EAP_METHOD_STATE_END      = 3
} EapMethodState;


/**
 * @brief Decisions
 **/

typedef enum
{
   EAP_DECISION_FAILURE     = 0,
   EAP_DECISION_SUCCESS     = 1,
   EAP_DECISION_CONTINUE    = 2,
   EAP_DECISION_PASSTHROUGH = 3
} EapDecision;


//Authenticator related functions
void eapFullAuthInitFsm(AuthenticatorPort *port);
void eapFullAuthFsm(AuthenticatorPort *port);

void eapFullAuthChangeState(AuthenticatorPort *port,
   EapFullAuthState newState);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
