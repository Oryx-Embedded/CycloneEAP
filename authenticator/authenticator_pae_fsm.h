/**
 * @file authenticator_pae_fsm.h
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

#ifndef _AUTHENTICATOR_PAE_FSM_H
#define _AUTHENTICATOR_PAE_FSM_H

//Dependencies
#include "authenticator/authenticator.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Authenticator PAE states
 **/

typedef enum
{
   AUTHENTICATOR_PAE_STATE_INITIALIZE     = 0,
   AUTHENTICATOR_PAE_STATE_DISCONNECTED   = 1,
   AUTHENTICATOR_PAE_STATE_RESTART        = 2,
   AUTHENTICATOR_PAE_STATE_CONNECTING     = 3,
   AUTHENTICATOR_PAE_STATE_AUTHENTICATING = 4,
   AUTHENTICATOR_PAE_STATE_AUTHENTICATED  = 5,
   AUTHENTICATOR_PAE_STATE_ABORTING       = 6,
   AUTHENTICATOR_PAE_STATE_HELD           = 7,
   AUTHENTICATOR_PAE_STATE_FORCE_AUTH     = 8,
   AUTHENTICATOR_PAE_STATE_FORCE_UNAUTH   = 9
} AuthenticatorPaeState;


/**
 * @brief Port status
 **/

typedef enum
{
   AUTHENTICATOR_PORT_STATUS_UNKNOWN = 0,
   AUTHENTICATOR_PORT_STATUS_UNAUTH  = 1,
   AUTHENTICATOR_PORT_STATUS_AUTH    = 2
} AuthenticatorPortStatus;


/**
 * @brief Port modes
 **/

typedef enum
{
   AUTHENTICATOR_PORT_MODE_FORCE_UNAUTH = 0,
   AUTHENTICATOR_PORT_MODE_FORCE_AUTH   = 1,
   AUTHENTICATOR_PORT_MODE_AUTO         = 2
} AuthenticatorPortMode;


//Authenticator related functions
void authenticatorPaeInitFsm(AuthenticatorPort *port);
void authenticatorPaeFsm(AuthenticatorPort *port);

void authenticatorPaeChangeState(AuthenticatorPort *port,
   AuthenticatorPaeState newState);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
