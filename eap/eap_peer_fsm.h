/**
 * @file eap_peer_fsm.h
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

#ifndef _EAP_PEER_FSM_H
#define _EAP_PEER_FSM_H

//Dependencies
#include <limits.h>
#include "eap/eap.h"
#include "supplicant/supplicant.h"

//Invalid identifier
#define EAP_LAST_ID_NONE UINT_MAX

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief EAP peer states
 **/

typedef enum
{
   EAP_PEER_STATE_DISABLED      = 0,
   EAP_PEER_STATE_INITIALIZE    = 1,
   EAP_PEER_STATE_IDLE          = 2,
   EAP_PEER_STATE_RECEIVED      = 3,
   EAP_PEER_STATE_METHOD        = 4,
   EAP_PEER_STATE_GET_METHOD    = 5,
   EAP_PEER_STATE_IDENTITY      = 6,
   EAP_PEER_STATE_NOTIFICATION  = 7,
   EAP_PEER_STATE_RETRANSMIT    = 8,
   EAP_PEER_STATE_DISCARD       = 9,
   EAP_PEER_STATE_SEND_RESPONSE = 10,
   EAP_PEER_STATE_SUCCESS       = 11,
   EAP_PEER_STATE_FAILURE       = 12
} EapPeerState;


/**
 * @brief EAP method states
 **/

typedef enum
{
   EAP_METHOD_STATE_NONE     = 0,
   EAP_METHOD_STATE_INIT     = 1,
   EAP_METHOD_STATE_CONT     = 2,
   EAP_METHOD_STATE_MAY_CONT = 3,
   EAP_METHOD_STATE_DONE     = 4
} EapMethodState;


/**
 * @brief Decisions
 **/

typedef enum
{
   EAP_DECISION_FAIL        = 1,
   EAP_DECISION_COND_SUCC   = 2,
   EAP_DECISION_UNCOND_SUCC = 3
} EapDecision;


//Supplicant related functions
void eapPeerInitFsm(SupplicantContext *context);
void eapPeerFsm(SupplicantContext *context);

void eapPeerChangeState(SupplicantContext *context,
   EapPeerState newState);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
